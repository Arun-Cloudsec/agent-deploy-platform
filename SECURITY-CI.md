# Security CI — operator guide

This doc explains the AgentOS security pipeline: what it scans, how to read
results, what to do when it fails, and how to keep it useful over time.

## Three layers of coverage

There are three security workflows working together:

| Layer | Workflow | Scans | Triggers |
|---|---|---|---|
| **Marketplace source** | `.github/workflows/security.yml` (this repo) | The marketplace's own code, IaC, and workflows | Per-PR, nightly |
| **Agent source** (each agent repo) | `.github/workflows/security.yml` (wrapper, calls reusable) | Each agent's own code, deps, Dockerfile, workflows | Per-PR, nightly |
| **Runtime images** (this repo) | `.github/workflows/runtime-image-scan.yml` | Images currently running in production (Azure + AWS) | Weekly, manual |

The marketplace and runtime scans live in this repo. Each agent repo gets a
short wrapper that delegates to the canonical reusable pipeline in
`Arun-Cloudsec/.github`.

## Layer 1 — Marketplace source scanning

| Job | Tool | What it catches | Fail condition |
|---|---|---|---|
| `secrets-scan` | Gitleaks | Committed API keys, AWS access keys, JWTs, private keys | Any secret found |
| `dependency-audit` | npm audit + Trivy fs | Known-vulnerable npm packages (direct + transitive) | High or Critical CVE |
| `container-scan` | Trivy image | Vulnerable base-image packages, copied-in CVEs | High or Critical CVE |
| `code-analysis` | CodeQL (JS + Actions) | Code-level vulns: taint flow, prototype pollution, regex DoS | Any High alert |
| `iac-scan` | Checkov | CloudFormation misconfigurations: public RDS, weak IAM, etc. | Any High finding |
| `actions-audit` | zizmor | GitHub Actions script injection, mutable action refs | Any finding |
| `sbom` | Syft | Software Bill of Materials (SPDX + CycloneDX) | Never fails (output only) |

All seven run in parallel on every PR and on a nightly cron at 02:00 UTC.

## Triggers

```yaml
on:
  pull_request: { branches: [main] }   # blocks merge if security-gate fails
  push:         { branches: [main] }   # post-merge sanity check
  schedule:     [{ cron: '0 2 * * *' }] # catches new CVEs in old code
  workflow_dispatch:                   # ad-hoc runs
```

The nightly run is the unsung hero. A vuln disclosed today on a package you
merged six months ago wouldn't show up on a PR scan; the scheduled run
catches it the next morning.

## How to read the results

**Inside a PR:** scroll to the "Security gate" check. It rolls up all seven
scans into one status. If it's red, click "Details" → which underlying job
failed → SARIF results appear in the run log.

**Repo-wide view:** `https://github.com/<org>/<repo>/security/code-scanning`.
Every SARIF upload populates this; you can filter by tool, severity, branch,
or commit. This is the auditor view — clean dashboard, exportable.

**SBOM artifacts:** every successful run uploads `agentos-sbom.spdx.json`
and `agentos-sbom.cdx.json`. Download from the workflow run page → Artifacts.
These are increasingly contractual deliverables in enterprise procurement.

## What to do when something fails

### Gitleaks finding

**Stop and rotate.** A real secret in git history isn't fixed by deletion —
it's compromised. Steps:

1. Rotate the credential at the source (regenerate the API key, etc.)
2. Update the production env var to the new credential
3. Use `git filter-repo` or BFG to scrub history if it's a long-lived secret
4. Add the file pattern to `.gitleaks.toml` if it's a false positive

### npm audit / Trivy fs CVE

1. Read the advisory — does it affect a code path you actually use?
2. If yes: `npm audit fix` for direct deps, or `npm update <pkg>` for
   transitive ones. Re-run the scan locally with `npm audit --audit-level=high`.
3. If no, or no fix is available: add to `.trivyignore` with a brief reason
   and an expiry date. Don't ignore indefinitely.

### Trivy image CVE

Usually a base-image issue. Three fixes in order of preference:

1. Bump the base image: `FROM node:20-alpine3.20` → `FROM node:20-alpine3.21`
2. Pin to the patched version: check the CVE for "Fixed in" version
3. If it's an OS package without a fix: add to `.trivyignore`

### CodeQL alert

Read the dataflow path the alert shows — it tells you exactly which input
flows to which sink. Most JS findings are real. Common ones for this codebase:

- **Reflected XSS:** add `escapeHtml()` at the sink
- **Prototype pollution:** validate object keys before assignment
- **Regex DoS:** rewrite the regex to avoid catastrophic backtracking
- **Hardcoded credentials:** move to env var

### Checkov finding

Read the check ID (e.g. `CKV_AWS_108`) and look it up at
[checkov.io](https://www.checkov.io/5.Policy%20Index/cloudformation.html).
Most are legitimate; some don't apply to your model. Add to the workflow's
`skip_check` list with a comment if it's not relevant.

### zizmor finding

Almost always a real issue. Common ones:

- **`pull-request-target` with checkout** — refactor to use `pull_request`
- **`${{ inputs.* }}` in shell** — refactor to use env vars
- **Mutable action ref** — pin to a SHA (look up at the action's repo)

## Branch protection

The pipeline is only useful if PRs can't merge without it passing. In the
GitHub repo settings:

1. Settings → Branches → Add branch protection rule for `main`
2. Require status checks to pass: **`Security gate`** (and your other CI)
3. Require branches to be up to date before merging
4. Require pull request reviews before merging (at least 1 approval)
5. Restrict who can push to main (admins only, ideally)
6. Optionally: enable "Require signed commits" for non-repudiation

## Action pinning policy

Every third-party action in `.github/workflows/*.yml` is pinned to a commit
SHA, not a tag. This is non-negotiable.

**Why:** tags are mutable. An attacker who compromises a popular action's
maintainer account can push a malicious commit, retag a release, and any
workflow using `@v4` picks it up immediately. The 2024 `tj-actions/changed-files`
incident exfiltrated secrets from thousands of repos this way.

**How to upgrade:**
1. Find the new release at `https://github.com/<owner>/<action>/releases`
2. Click the release tag → "Browse files" → copy the commit SHA from the URL
3. Replace `@<sha> # <old-version>` with `@<new-sha> # <new-version>`
4. Test the workflow locally with `act` or in a feature branch first

A spreadsheet of pinned actions and their last-checked dates is overkill
for now; revisit quarterly.

## Required GitHub secrets / variables

The security workflow itself uses:

- `GITHUB_TOKEN` — auto-provided
- `GITLEAKS_LICENSE` — optional. Required only for Gitleaks Action on
  private repos with org-paid plans. For Anthropic-API-style usage on a
  small team, leave it unset; Gitleaks falls back to the OSS path.

No AWS / Azure / Anthropic credentials needed for security scanning — those
live in `deploy-agent.yml` only.

## Suppressing false positives

Each tool has its own ignore mechanism:

- **Gitleaks:** `.gitleaks.toml` with `[[allowlist]]` blocks
- **Trivy:** `.trivyignore` (one CVE ID per line) or `.trivyignore.yaml`
- **Checkov:** `skip_check:` in the workflow, or `.checkov.yaml` for repo-wide
- **CodeQL:** dismiss the alert with a comment in the Security tab
- **zizmor:** `# zizmor: ignore[<rule-id>]` comment on the offending line

**Always include a reason and a date.** A nine-month-old `# false positive`
with no context is the same thing as broken security.

## Cost

GitHub Actions free tier covers 2,000 minutes/month for private repos.
Estimated monthly burn for this pipeline:

- 7 jobs × ~3 min average × ~30 PRs/month = ~630 min
- Plus 30 nightly runs × ~3 min × 7 jobs = ~630 min

So **~1,260 minutes/month**, comfortably inside the free tier. If you 10x
PR velocity, consider:

1. Skip secrets-scan on push-to-main (it ran on the PR already)
2. Make container-scan conditional on `Dockerfile` or `package.json` changes
3. Use a paths filter to skip irrelevant files (`paths-ignore: ['**.md']`)

## Maintenance cadence

| Frequency | Task |
|---|---|
| Per PR | Review red checks, fix or justify ignores |
| Weekly | Skim `Security` tab; close stale dismissed alerts |
| Monthly | Review the `.trivyignore` / `.gitleaks.toml` for stale entries |
| Quarterly | Bump pinned action SHAs; review skip lists |
| Annually | Review tool selection — newer tools may replace existing ones |

---

## Layer 2 — Agent repo source scanning

Every agent repo gets a wrapper workflow that delegates to the canonical
pipeline in `Arun-Cloudsec/.github`. **This is mandatory** — without it,
nothing scans the agent code that customers actually run.

### One-time setup per agent repo

1. Pick the right wrapper template from `Arun-Cloudsec/.github` README:
   - JavaScript: 8 lines
   - Python: 8 lines
   - Go: 8 lines
   - IaC-only: 11 lines

2. Drop it into the agent repo at `.github/workflows/security.yml`

3. Open a PR in the agent repo — the workflow runs, you triage the initial
   findings (just like first-run on the marketplace repo)

4. Once green, configure branch protection in the agent repo:
   `Settings → Branches → Add rule → require "security / Security gate"`

The wrapper is intentionally trivial. **Do not customize the wrapper** —
all customization (which scanners, which severity, which ignores) lives in
the canonical reusable workflow. To change behavior, edit
`Arun-Cloudsec/.github/.github/workflows/reusable-security.yml` once.

### Why a wrapper instead of duplicating the workflow

- Single source of truth: 25 agent repos, 1 file to maintain
- Consistent enforcement: everyone gets the same severity threshold
- Faster scanner upgrades: new SHA in one place, all agents inherit
- Audit-friendly: "show me what scans every agent" → one file

### What the reusable pipeline supports

| Input | Type | Default | Notes |
|---|---|---|---|
| `language` | string | `javascript` | `javascript`, `python`, `go`, or `none` |
| `scan-container` | bool | `true` | Set false if no Dockerfile |
| `scan-iac` | bool | `false` | Enable for repos with CFN/Bicep |
| `iac-files` | string | `` | Comma-separated paths |
| `severity-threshold` | string | `HIGH` | `CRITICAL`, `HIGH`, `MEDIUM` |

---

## Layer 3 — Runtime image scanning

`.github/workflows/runtime-image-scan.yml` runs **weekly** (Mondays 06:00 UTC)
and scans every image actually deployed in production.

### Why this is separate from layer 1 + 2

A CVE disclosed today against a package merged six months ago:
- **Layer 1/2 PR scan** — never re-runs on old PRs, doesn't see the new vuln
- **Layer 1/2 nightly cron** — sees the vuln in `main`, but doesn't know
  what's actually deployed
- **Layer 3 runtime scan** — pulls live images from ACR/ECR, scans them
  as-is, files an issue for human acknowledgement

The first two tell you "your codebase is vulnerable." The third tells you
"your customers are running vulnerable software right now."

### What it does

1. **Discover** — lists every running Container App in
   `ai-platform-rg` and `ai-platform-rg-uksouth` (Azure), and every
   `agentos-*` App Runner service in `me-central-1` and `me-south-1` (AWS)
2. **Scan** — for each discovered image, pulls from its registry
   (ACR or ECR) and runs Trivy with HIGH/CRITICAL severity threshold
3. **Report** — uploads SARIF to the Security tab (categorized per service)
   AND files a GitHub issue per finding with the affected service, image
   tag, run link, and remediation steps
4. **Dedupe** — issues are deduped by title; running again won't pile them up

### Reading runtime findings

Findings appear in three places:

- **Security tab → Code scanning** — filter by `category:runtime-*` to see
  only runtime findings
- **Issues tab → label:runtime-scan** — actionable list of services that
  need rebuilding
- **Workflow run summary** — quick overview: "X images scanned, Y had findings"

### Remediation flow when an issue is filed

```
1. Identify the source repo for the affected service
   (rfp-agent → Arun-Cloudsec/agent-deploy-platform, etc.)
2. In that repo:
     - Bump the vulnerable dependency, or
     - Bump the Dockerfile base image, or
     - Add the CVE to .trivyignore with a justification
3. Re-run the source-repo Security CI to confirm clean
4. Click Deploy in the marketplace to roll out the new image
5. Close the runtime-scan issue (it'll re-file next Monday if the
   vuln is still present, so don't worry about being tidy)
```

### Required secrets/vars

Inherits from this repo:
- `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` (secrets) —
  for Container Apps discovery + ACR pull
- `AWS_DEPLOYER_ROLE_ARN` (variable) — for App Runner discovery + ECR pull.
  Optional; AWS scanning is skipped if not set.

### Cadence and cost

Weekly is the right default. Considered alternatives:
- **Daily** — alert fatigue. CVE databases update constantly; you don't
  need to file the same issue 7x in 7 days.
- **Quarterly** — too slow. CVEs disclosed mid-quarter would have weeks
  of exposure.

Estimated cost: ~25 services × ~30s scan each + ~1 min discovery = ~14 min
per run × 4 runs/month = **~56 minutes/month**. Negligible.

### Manual trigger

```bash
gh workflow run runtime-image-scan.yml \
  -f severity-threshold=CRITICAL    # only block on critical, useful for ad-hoc
```

---

## Putting all three layers together

| Question | Layer that answers it |
|---|---|
| Did the marketplace code pass review? | 1 — marketplace source scan |
| Did the RFP Agent code pass review? | 2 — agent source scan |
| Is the running RFP Agent in UAE vulnerable to CVE-2026-XXXXX disclosed yesterday? | 3 — runtime scan |
| Did anyone commit an API key into the marketplace repo? | 1 (Gitleaks) |
| Did anyone commit an API key into an agent repo? | 2 (Gitleaks via reusable) |

If a scan layer is missing, the corresponding question goes unanswered.
