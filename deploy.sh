#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AgentOS v6.12 — All-in-one deployment script
# ─────────────────────────────────────────────────────────────────────────────
#
# This single script does everything needed to ship v6.12:
#   1. Pre-flight checks (Azure subscription, CLI versions, repo existence)
#   2. Push v6.12 marketplace to your existing Container App
#   3. Verify the marketplace is healthy
#   4. Create the org-level .github repo if it doesn't exist
#   5. Push the canonical reusable security workflow there
#   6. Add the security wrapper to each agent repo (idempotent)
#   7. Trigger the first security scan in each repo
#   8. Trigger the runtime image scan once
#   9. Print a summary of what was done and what humans still need to do
#
# DESIGN: Every step is idempotent — re-running the script after a partial
# failure picks up where it left off. Every external call is checked. When
# the script can't proceed automatically (e.g. for branch protection UI),
# it prints exact instructions and exits cleanly so you can resume after.
#
# USAGE:
#   chmod +x deploy.sh
#   ./deploy.sh                    # interactive, asks for confirmation
#   ./deploy.sh --yes              # non-interactive, accept all defaults
#   ./deploy.sh --skip-marketplace # skip Phase 1 (e.g. already deployed)
#   ./deploy.sh --skip-agents      # skip wrapping the agent repos
#   ./deploy.sh --dry-run          # print what would happen without doing it
#
# REQUIRES:
#   - bash 4+
#   - az CLI (logged in via `az login`)
#   - gh CLI (logged in via `gh auth login` with repo + workflow scopes)
#   - jq, openssl, unzip
#   - The agentos-v6.12.zip in the same directory as this script
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────
GITHUB_ORG="${GITHUB_ORG:-Arun-Cloudsec}"
MARKETPLACE_REPO="${MARKETPLACE_REPO:-agent-deploy-platform}"
AZURE_RG="${AZURE_RG:-ai-platform-rg}"
AZURE_CONTAINER_APP="${AZURE_CONTAINER_APP:-agent-deploy-platform}"
AZURE_ACR="${AZURE_ACR:-aiplatformacrkrz6di3sepgjo}"
ZIP_FILE="${ZIP_FILE:-agentos-v6.12.zip}"
WORK_DIR="${WORK_DIR:-$HOME/agentos-deploy-work}"

# Agent repos that get the security wrapper. Add more as you onboard agents.
# Format: repo_name:language  (language ∈ javascript, python, go)
AGENT_REPOS=(
  "agent-deploy-platform:javascript"     # the marketplace itself
  # Add more as you onboard them:
  # "rfp-agent:javascript"
  # "threat-model:python"
  # "sbom-radar:go"
)

# Flags
SKIP_MARKETPLACE=false
SKIP_ORG_REPO=false
SKIP_AGENTS=false
SKIP_RUNTIME_SCAN=false
DRY_RUN=false
ASSUME_YES=false

# ─── Output helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${BLUE}▸${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }
fatal(){ err "$*"; exit 1; }
section() { echo -e "\n${BOLD}═══ $* ═══${NC}\n"; }

# Echo + run unless dry-run. Uses arrays so quoting is safe.
runcmd() {
  if $DRY_RUN; then
    printf '  [dry-run] '; printf '%q ' "$@"; echo
  else
    "$@"
  fi
}

confirm() {
  local prompt="${1:-Continue?}"
  if $ASSUME_YES; then return 0; fi
  read -r -p "$(echo -e "${YELLOW}?${NC} $prompt [y/N] ")" reply
  [[ "$reply" =~ ^[Yy] ]]
}

# ─── Argument parsing ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)              ASSUME_YES=true ;;
    --skip-marketplace)    SKIP_MARKETPLACE=true ;;
    --skip-org-repo)       SKIP_ORG_REPO=true ;;
    --skip-agents)         SKIP_AGENTS=true ;;
    --skip-runtime-scan)   SKIP_RUNTIME_SCAN=true ;;
    --dry-run)             DRY_RUN=true ;;
    --help|-h)
      sed -n '/^# USAGE:/,/^# ─/p' "$0" | sed 's/^# //; s/^#$//'
      exit 0 ;;
    *) fatal "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

# ─── Phase 0 — Pre-flight ────────────────────────────────────────────────────
section "Phase 0 — Pre-flight checks"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fatal "Required command '$1' not found. Please install it."
}

require_cmd az
require_cmd gh
require_cmd jq
require_cmd openssl
require_cmd unzip
ok "Required CLIs present (az, gh, jq, openssl, unzip)"

# Azure auth
if ! az account show >/dev/null 2>&1; then
  fatal "Not logged in to Azure. Run: az login"
fi
SUB_NAME=$(az account show --query name -o tsv)
SUB_ID=$(az account show --query id -o tsv)
ok "Azure subscription: $SUB_NAME ($SUB_ID)"

# GitHub auth — need repo + workflow scopes
if ! gh auth status >/dev/null 2>&1; then
  fatal "Not logged in to GitHub. Run: gh auth login --scopes 'repo,workflow,admin:org'"
fi
GH_USER=$(gh api user --jq .login)
ok "GitHub: authenticated as $GH_USER"

# Verify gh has the right scopes (best-effort — `gh auth status` doesn't always print them)
if ! gh auth status 2>&1 | grep -qE 'repo|workflow'; then
  warn "Couldn't confirm gh has 'repo' + 'workflow' scopes. If push fails later, run:"
  warn "  gh auth refresh --scopes 'repo,workflow,admin:org'"
fi

# Marketplace zip present?
if [ ! -f "$ZIP_FILE" ]; then
  fatal "Cannot find $ZIP_FILE in current directory ($PWD).
  Upload it to Cloud Shell first, or set ZIP_FILE=/path/to/agentos-v6.12.zip"
fi
ok "Marketplace zip found: $ZIP_FILE ($(du -h "$ZIP_FILE" | cut -f1))"

# Container App exists?
if ! az containerapp show -n "$AZURE_CONTAINER_APP" -g "$AZURE_RG" >/dev/null 2>&1; then
  fatal "Container App '$AZURE_CONTAINER_APP' not found in '$AZURE_RG'.
  Either you're in the wrong subscription, or the marketplace was never deployed.
  Switch subs: az account set --subscription <id>"
fi
ok "Container App '$AZURE_CONTAINER_APP' exists in '$AZURE_RG'"

# Marketplace repo exists?
if ! gh repo view "$GITHUB_ORG/$MARKETPLACE_REPO" >/dev/null 2>&1; then
  fatal "GitHub repo '$GITHUB_ORG/$MARKETPLACE_REPO' not accessible.
  Either it doesn't exist, or your gh token doesn't have access."
fi
ok "GitHub repo '$GITHUB_ORG/$MARKETPLACE_REPO' accessible"

mkdir -p "$WORK_DIR"
ok "Working directory: $WORK_DIR"

# Git identity — required for any commit/push the script does later. Cloud
# Shell sandboxes don't ship with a persistent identity, and `git commit`
# fails with "unable to auto-detect email address" if neither user.email
# nor user.name is set. We use the GitHub account if no identity is
# configured already, scoped --global so subsequent runs reuse it.
GIT_EMAIL=$(git config --global user.email 2>/dev/null || echo "")
GIT_NAME=$(git config --global user.name 2>/dev/null || echo "")
if [ -z "$GIT_EMAIL" ] || [ -z "$GIT_NAME" ]; then
  log "git user.email/user.name not set globally — configuring from GitHub identity..."
  # Try to get a usable email from GitHub. Public profile email may be
  # null if the user hasn't exposed it; fall back to the noreply address
  # GitHub provides for every account, which works for commits.
  GH_EMAIL=$(gh api user --jq '.email // empty' 2>/dev/null || echo "")
  GH_NAME=$(gh api user --jq '.name // .login' 2>/dev/null || echo "$GH_USER")
  GH_ID=$(gh api user --jq '.id' 2>/dev/null || echo "0")
  if [ -z "$GH_EMAIL" ]; then
    # GitHub's noreply email format: <id>+<login>@users.noreply.github.com
    GH_EMAIL="${GH_ID}+${GH_USER}@users.noreply.github.com"
  fi
  runcmd git config --global user.email "$GH_EMAIL"
  runcmd git config --global user.name  "$GH_NAME"
  ok "git identity set: $GH_NAME <$GH_EMAIL>"
else
  ok "git identity already configured: $GIT_NAME <$GIT_EMAIL>"
fi

# ─── Phase 1 — Push v6.12 marketplace ────────────────────────────────────────
if $SKIP_MARKETPLACE; then
  warn "Skipping Phase 1 (marketplace deploy) — flag --skip-marketplace set"
else
  section "Phase 1 — Deploy v6.12 marketplace"

  # 1.1 — SESSION_SECRET (only set if missing)
  log "Ensuring SESSION_SECRET secret exists on Container App..."
  EXISTING_SECRETS=$(az containerapp secret list -n "$AZURE_CONTAINER_APP" -g "$AZURE_RG" --query "[].name" -o tsv 2>/dev/null || echo "")
  if echo "$EXISTING_SECRETS" | grep -qx "session-secret"; then
    ok "session-secret already configured (preserving existing value)"
  else
    log "Generating SESSION_SECRET and storing in Container App secrets..."
    SESSION_SECRET=$(openssl rand -hex 32)
    runcmd az containerapp secret set \
      --name "$AZURE_CONTAINER_APP" --resource-group "$AZURE_RG" \
      --secrets session-secret="$SESSION_SECRET"
    runcmd az containerapp update \
      --name "$AZURE_CONTAINER_APP" --resource-group "$AZURE_RG" \
      --set-env-vars NODE_ENV=production SESSION_SECRET=secretref:session-secret
    ok "SESSION_SECRET configured"
  fi

  # 1.2 — Unzip
  log "Unpacking $ZIP_FILE..."
  rm -rf "$WORK_DIR/agentos-v6.12"
  runcmd unzip -q "$ZIP_FILE" -d "$WORK_DIR/agentos-v6.12"
  ok "Unpacked to $WORK_DIR/agentos-v6.12"

  # 1.3 — Build image
  log "Building image in ACR (this takes ~2 min)..."
  if $DRY_RUN; then
    echo "  [dry-run] az acr build --registry $AZURE_ACR --image agent-marketplace:v6 ..."
  else
    pushd "$WORK_DIR/agentos-v6.12" >/dev/null
    az acr build \
      --registry "$AZURE_ACR" \
      --image agent-marketplace:v6 \
      --image agent-marketplace:latest \
      --no-logs . > /dev/null
    popd >/dev/null
    ok "Image built"
  fi

  # 1.4 — Roll out
  REVISION_SUFFIX="v612-$(date +%s)"
  log "Rolling out new revision (suffix: $REVISION_SUFFIX)..."
  runcmd az containerapp update \
    --name "$AZURE_CONTAINER_APP" --resource-group "$AZURE_RG" \
    --image "$AZURE_ACR.azurecr.io/agent-marketplace:v6" \
    --revision-suffix "$REVISION_SUFFIX" > /dev/null
  ok "Revision rollout initiated"

  # 1.5 — Wait for healthy
  log "Waiting for new revision to become healthy (up to 3 min)..."
  if ! $DRY_RUN; then
    for i in $(seq 1 30); do
      HEALTH=$(az containerapp revision list -n "$AZURE_CONTAINER_APP" -g "$AZURE_RG" \
        --query '[?properties.active].properties.healthState | [0]' -o tsv 2>/dev/null || echo "")
      if [ "$HEALTH" = "Healthy" ]; then
        ok "Active revision is Healthy"
        break
      fi
      if [ "$i" -eq 30 ]; then
        err "Active revision did not become Healthy within 3 minutes."
        err "Check logs: az containerapp logs show -n $AZURE_CONTAINER_APP -g $AZURE_RG --tail 50 --follow false"
        exit 1
      fi
      sleep 6
    done
  fi

  # 1.6 — Get URL
  MARKETPLACE_URL=$(az containerapp show -n "$AZURE_CONTAINER_APP" -g "$AZURE_RG" \
    --query 'properties.configuration.ingress.fqdn' -o tsv)
  ok "Marketplace live at: https://$MARKETPLACE_URL"
  echo "$MARKETPLACE_URL" > "$WORK_DIR/marketplace-url.txt"

  # 1.7 — Verify security headers shipped
  if ! $DRY_RUN; then
    if curl -sI "https://$MARKETPLACE_URL/" | grep -qi 'content-security-policy'; then
      ok "Security headers (CSP) confirmed shipped"
    else
      warn "CSP header not detected — old image may still be cached. Hard-refresh in browser."
    fi
  fi
fi

# ─── Phase 2 — Org-level .github repo ────────────────────────────────────────
if $SKIP_ORG_REPO; then
  warn "Skipping Phase 2 (org .github repo) — flag --skip-org-repo set"
else
  section "Phase 2 — Org-level .github repo (canonical reusable workflow)"

  ORG_REPO_DIR="$WORK_DIR/dot-github"
  REUSABLE_SRC="$WORK_DIR/agentos-v6.12/_org-github-repo"

  if [ ! -d "$REUSABLE_SRC" ]; then
    fatal "Source for reusable workflow not found at $REUSABLE_SRC.
    Did Phase 1 unzip correctly? Re-run without --skip-marketplace."
  fi

  # 2.1 — Does the org .github repo exist?
  if gh repo view "$GITHUB_ORG/.github" >/dev/null 2>&1; then
    ok "Repo $GITHUB_ORG/.github exists"
    EXISTS=true
  else
    EXISTS=false
    log "Repo $GITHUB_ORG/.github does NOT exist. Need to create it."
    if confirm "Create $GITHUB_ORG/.github as a private repo?"; then
      runcmd gh repo create "$GITHUB_ORG/.github" \
        --private \
        --description "Org-wide GitHub defaults: shared workflows, templates, and policies." \
        --add-readme
      ok "Created $GITHUB_ORG/.github"
    else
      err "Cannot proceed without the .github repo. Re-run when ready."
      exit 1
    fi
  fi

  # 2.2 — Clone, copy files, push
  log "Cloning $GITHUB_ORG/.github to $ORG_REPO_DIR..."
  rm -rf "$ORG_REPO_DIR"
  runcmd gh repo clone "$GITHUB_ORG/.github" "$ORG_REPO_DIR" -- --quiet

  if ! $DRY_RUN; then
    mkdir -p "$ORG_REPO_DIR/.github/workflows"
    cp "$REUSABLE_SRC/.github/workflows/reusable-security.yml" \
       "$ORG_REPO_DIR/.github/workflows/reusable-security.yml"
    # Only overwrite README if we just created the repo (don't clobber existing)
    if ! $EXISTS || [ ! -s "$ORG_REPO_DIR/README.md" ]; then
      cp "$REUSABLE_SRC/README.md" "$ORG_REPO_DIR/README.md"
    fi

    pushd "$ORG_REPO_DIR" >/dev/null
    if [ -n "$(git status --porcelain)" ]; then
      git add .github/workflows/reusable-security.yml README.md 2>/dev/null || git add .
      git commit -m "Add/update canonical security workflow (v6.12)" >/dev/null
      git push origin HEAD >/dev/null
      ok "Pushed canonical reusable-security.yml to $GITHUB_ORG/.github"
    else
      ok "Reusable workflow already up to date in $GITHUB_ORG/.github"
    fi
    popd >/dev/null
  fi
fi

# ─── Phase 3 — Wrap each agent repo ──────────────────────────────────────────
if $SKIP_AGENTS; then
  warn "Skipping Phase 3 (agent wrappers) — flag --skip-agents set"
else
  section "Phase 3 — Add security wrapper to each agent repo"

  WRAPPER_SRC="$WORK_DIR/agentos-v6.12/_agent-wrapper-templates"
  if [ ! -d "$WRAPPER_SRC" ]; then
    fatal "Wrapper templates not found at $WRAPPER_SRC. Re-run without --skip-marketplace."
  fi

  for entry in "${AGENT_REPOS[@]}"; do
    REPO_NAME="${entry%:*}"
    LANG="${entry#*:}"
    log "Wrapping $GITHUB_ORG/$REPO_NAME (language: $LANG)..."

    # Verify repo accessible
    if ! gh repo view "$GITHUB_ORG/$REPO_NAME" >/dev/null 2>&1; then
      warn "Cannot access $GITHUB_ORG/$REPO_NAME — skipping (check gh auth scope)"
      continue
    fi

    # Check if wrapper already exists
    if gh api "repos/$GITHUB_ORG/$REPO_NAME/contents/.github/workflows/security.yml" >/dev/null 2>&1; then
      ok "  Wrapper already exists in $REPO_NAME — skipping"
      continue
    fi

    # Pick the right template
    case "$LANG" in
      javascript) TEMPLATE="$WRAPPER_SRC/security-javascript.yml" ;;
      python)     TEMPLATE="$WRAPPER_SRC/security-python.yml" ;;
      go)         TEMPLATE="$WRAPPER_SRC/security-go.yml" ;;
      *)          warn "  Unknown language '$LANG' for $REPO_NAME — skipping"; continue ;;
    esac

    if ! [ -f "$TEMPLATE" ]; then
      warn "  Template $TEMPLATE missing — skipping"
      continue
    fi

    # Clone, add wrapper on a branch, open PR
    REPO_DIR="$WORK_DIR/agent-$REPO_NAME"
    rm -rf "$REPO_DIR"
    runcmd gh repo clone "$GITHUB_ORG/$REPO_NAME" "$REPO_DIR" -- --quiet

    if ! $DRY_RUN; then
      pushd "$REPO_DIR" >/dev/null
      DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo main)
      BRANCH="add-security-ci-$(date +%s)"
      git checkout -b "$BRANCH" >/dev/null

      mkdir -p .github/workflows
      cp "$TEMPLATE" .github/workflows/security.yml
      git add .github/workflows/security.yml
      git commit -m "Add reusable security CI wrapper" >/dev/null
      git push -u origin "$BRANCH" >/dev/null

      gh pr create \
        --repo "$GITHUB_ORG/$REPO_NAME" \
        --base "$DEFAULT_BRANCH" \
        --head "$BRANCH" \
        --title "Add reusable security CI" \
        --body "Adds the standard org security pipeline.

Wraps the canonical pipeline in \`$GITHUB_ORG/.github/.github/workflows/reusable-security.yml@main\`.

**Expected on first run:** the security pipeline will likely report findings against existing dependencies and base images. Triage them in a follow-up PR — see \`SECURITY-CI.md\` in the marketplace repo for guidance.

Auto-generated by \`deploy.sh\` on $(date -u +%Y-%m-%dT%H:%M:%SZ)." > /dev/null
      ok "  Opened PR on $REPO_NAME ($BRANCH)"
      popd >/dev/null
    fi
  done
fi

# ─── Phase 4 — Trigger initial scans ─────────────────────────────────────────
section "Phase 4 — Trigger first runs"

# 4.1 — Marketplace security workflow
log "Triggering marketplace security workflow..."
if ! $DRY_RUN; then
  if gh workflow run security.yml -R "$GITHUB_ORG/$MARKETPLACE_REPO" >/dev/null 2>&1; then
    ok "Triggered: $GITHUB_ORG/$MARKETPLACE_REPO::security.yml"
  else
    warn "Couldn't trigger security.yml — check the workflow is on the default branch."
  fi
fi

# 4.2 — Runtime image scan
if $SKIP_RUNTIME_SCAN; then
  warn "Skipping runtime image scan trigger — flag set"
else
  log "Triggering runtime image scan..."
  if ! $DRY_RUN; then
    if gh workflow run runtime-image-scan.yml -R "$GITHUB_ORG/$MARKETPLACE_REPO" >/dev/null 2>&1; then
      ok "Triggered: $GITHUB_ORG/$MARKETPLACE_REPO::runtime-image-scan.yml"
    else
      warn "Couldn't trigger runtime-image-scan.yml — likely needs to be on main first."
      warn "After v6.12 merges, run: gh workflow run runtime-image-scan.yml -R $GITHUB_ORG/$MARKETPLACE_REPO"
    fi
  fi
fi

# ─── Phase 5 — Summary ───────────────────────────────────────────────────────
section "Phase 5 — Summary"

if [ -f "$WORK_DIR/marketplace-url.txt" ]; then
  MARKETPLACE_URL=$(cat "$WORK_DIR/marketplace-url.txt")
  echo "Marketplace URL:    https://$MARKETPLACE_URL"
fi
echo "Org repo:           https://github.com/$GITHUB_ORG/.github"
echo "Marketplace repo:   https://github.com/$GITHUB_ORG/$MARKETPLACE_REPO"
echo "Workflow runs:      https://github.com/$GITHUB_ORG/$MARKETPLACE_REPO/actions"
echo "Security findings:  https://github.com/$GITHUB_ORG/$MARKETPLACE_REPO/security/code-scanning"

cat <<'TAIL'

────────────────────────────────────────────────────────────────────────────
What humans still need to do:
────────────────────────────────────────────────────────────────────────────

1. Hard-refresh the marketplace URL in your browser (Ctrl+Shift+R).
   Confirm the v6.12 indicators are visible:
     - Subtitle mentions UAE Central + Bahrain
     - 🔊 sound toggle in topbar
     - 🎧 voice tour strip on marketplace page

2. Review the PRs created in agent repos and merge them.
   Each PR will run its security pipeline against the agent's code.
   Expect findings on first run — triage them in follow-up PRs.

3. Configure branch protection in each agent repo:
     Settings → Branches → Add rule for 'main'
     → Require status check: 'security / Security gate'

4. Watch the runtime image scan run:
     https://github.com/<org>/<marketplace-repo>/actions/workflows/runtime-image-scan.yml
   First run may file Issues for vulnerable production images.
   Triage them per the steps in SECURITY-CI.md.

5. Add more agent repos by editing the AGENT_REPOS array in this script
   and re-running with --skip-marketplace --skip-org-repo. The script will
   skip already-wrapped repos and only act on new ones.

────────────────────────────────────────────────────────────────────────────
TAIL

ok "Done."
