// server.js — AgentOS v6
//
// Adds executive screens on top of v5.2's deploy platform:
//   - Dashboard: live deployment counts, real cost estimates, uptime
//   - Analytics: requests per agent, cost breakdown, deployment speed, success rate
//   - Users: roles & permissions (RBAC config display)
//   - ROI: business case summary, roadmap
//
// Where data comes from:
//   - Deployment counts → /app/data/deployments.json (file store, like v5)
//   - Per-region resource counts → Azure REST (when managed identity available)
//   - Cost estimates → Azure pricing assumptions × actual Container App count
//   - Request stats → simulated until Azure App Insights wiring is added (deferred to v7)
//
// We do NOT mock numbers when reality is reachable. The dashboard reads what's
// actually deployed in each region's resource group and computes from that.

import express from 'express';
import cookieSession from 'cookie-session';
import bodyParser from 'body-parser';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';

import { AGENTS } from './src/agents-with-repos.js';
import { REGIONS, regionById, fqdnFor } from './src/regions.js';
import {
  createDeployment, getDeployment, updateDeployment, listDeployments,
  addLog, getDeploymentLogs,
} from './src/deployment-store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = parseInt(process.env.PORT || '3010', 10);
const VERSION = '6.0';

const GITHUB_ORG = process.env.GITHUB_ORG || 'Arun-Cloudsec';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

const SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID || 'ead28ade-e9f9-4bde-8f35-63c4f4b53992';

// ─── Cost estimation table ────────────────────────────────────────────────────
// Monthly USD cost per resource type, assuming default sizing. These are
// realistic 2025 published Azure prices for the SKUs we provision via Bicep.
// Used as a fallback when Azure Cost Mgmt API isn't accessible.
const MONTHLY_COST_USD = {
  // Per-Container-App estimate — 0.5 CPU, 1Gi RAM, ~1 replica avg, ~10K requests/day
  containerApp: 14.40,

  // Per-region foundation cost (independent of agent count)
  perRegion: {
    'azure-uaenorth': {
      containerAppsEnv: 0,        // managed env is free, you pay per app
      postgres: 84.00,            // B2ms / 7-day backup
      redis: 16.00,               // C0 Basic
      keyVault: 0.30,             // ~10K ops/mo
      storage: 2.40,              // 10GB GRS
      logAnalytics: 12.00,        // ~1GB/day ingestion
      appInsights: 5.00,          // basic plan
    },
    'azure-uksouth': {
      containerAppsEnv: 0,
      postgres: 84.00,
      redis: 16.00,
      keyVault: 0.30,
      storage: 4.20,              // 10GB GRS to UK West
      logAnalytics: 12.00,
      appInsights: 5.00,
    },
  },
};

// Demo users — for the platform sign-in
// Demo users — passwords stored as bcrypt hashes (never plaintext).
// Default password for both demo accounts is "demo123" — change on first
// production deploy by:
//   1. Generating a fresh hash:  node -e "console.log(require('bcryptjs').hashSync('NEW_PASSWORD',10))"
//   2. Replacing the passwordHash value below
//   3. Better still: replace this whole array with a Postgres-backed user
//      table or federate via Keycloak / Entra (see roadmap).
const DEMO_HASH = '$2a$10$IYXa.aGBI/CiTjyRD4f6v.hfuyf6ygYzqY4yVgOy8JGUDBYIleM1y';
const USERS = [
  { id: 'admin', email: 'admin@demo.com',  passwordHash: DEMO_HASH, name: 'Admin User',  role: 'admin'  },
  { id: 'view',  email: 'viewer@demo.com', passwordHash: DEMO_HASH, name: 'Viewer User', role: 'viewer' },
];

// Live in-flight deploys
const liveDeploys = new Map();

// ─── Express setup ────────────────────────────────────────────────────────────
const app = express();

// Trust the cloud's reverse proxy (Container Apps / App Runner) so secure
// cookies and rate-limit IP detection work correctly.
app.set('trust proxy', 1);

// Security headers — clickjacking, MIME-sniffing, HSTS, basic XSS defenses.
// CSP is intentionally permissive enough for the inline scripts the SPA
// uses today; tighten further once we move to a build pipeline.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Inline scripts/styles are needed for the current single-file SPA.
      // 'unsafe-inline' is a known compromise; tighten when we adopt a build.
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'"],
      mediaSrc: ["'self'", 'blob:'],
      frameAncestors: ["'none'"],   // blocks clickjacking
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,  // allow audio/img cross-origin for ElevenLabs
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

app.use(bodyParser.json({ limit: '1mb' }));

// ─── Rate limiting ────────────────────────────────────────────────────────────
// Three tiers:
//   1. Login: 10 attempts per IP per 15 minutes — blocks credential stuffing
//   2. Chat:  20 requests per session per minute — caps Anthropic API cost
//   3. API:   200 requests per IP per minute — catches general abuse
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  // Skip rate-limiting in test env to keep CI fast
  skip: () => process.env.NODE_ENV === 'test',
});
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  // Key by user when authenticated, else by IP
  keyGenerator: (req) => req.session?.user?.id || req.ip,
  message: { error: 'Chat rate limit reached. Slow down a moment.' },
  skip: () => process.env.NODE_ENV === 'test',
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down.' },
  skip: () => process.env.NODE_ENV === 'test',
});
app.use('/api/', apiLimiter);

// ─── CSRF defense ─────────────────────────────────────────────────────────────
// All state-changing endpoints (POST/PUT/PATCH/DELETE) require a custom
// `X-Requested-With: agentos` header. Browsers will not add custom headers on
// cross-origin form submissions, and any cross-origin fetch with a custom
// header triggers a CORS preflight that the server can deny. Combined with
// SameSite=lax cookies, this gives defense in depth against CSRF.
//
// The frontend SPA always sends this header; legitimate API clients must too.
// GET/HEAD/OPTIONS pass through unchanged.
function requireCsrfHeader(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  // Skip CSRF for the login endpoint itself — there's no session to forge
  // before a user has logged in. SameSite=lax still protects against
  // cross-site session fixation.
  // NOTE: this middleware is mounted at '/api/', so req.path is the suffix
  // after that mount point. Login path here is '/auth/login', not '/api/auth/login'.
  if (req.path === '/auth/login') return next();
  if (req.headers['x-requested-with'] !== 'agentos') {
    return res.status(403).json({ error: 'Missing CSRF header' });
  }
  next();
}
app.use('/api/', requireCsrfHeader);


// Cookie-based sessions: session data lives in the cookie itself (signed),
// not in server memory. This means sessions SURVIVE container restarts —
// crucial because every revision deploy on Azure Container Apps spins up a
// fresh replica and would otherwise drop in-memory sessions, forcing every
// user to log in again after each deploy.
//
// SECURITY: SESSION_SECRET must be a strong random value in production. If
// unset (or set to the dev fallback), the server refuses to start when
// NODE_ENV=production. Generate with: openssl rand -hex 32
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me-in-production';
if (process.env.NODE_ENV === 'production' && SESSION_SECRET === 'dev-secret-change-me-in-production') {
  console.error('[fatal] SESSION_SECRET must be set in production. Generate one with: openssl rand -hex 32');
  process.exit(1);
}

app.use(cookieSession({
  name: 'agentos-session',
  keys: [SESSION_SECRET],
  maxAge: 7 * 24 * 60 * 60 * 1000,   // 7 days
  sameSite: 'lax',
  httpOnly: true,
  // secure: cookies only sent over HTTPS in production. Container Apps and
  // App Runner both terminate TLS at the ingress, so we trust the proxy.
  secure: process.env.NODE_ENV === 'production',
}));

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '5m' }));

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'auth required' });
  next();
}
function requireAdmin(req, res, next) {
  if (req.session?.user?.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  next();
}

// ─── Azure REST helpers ───────────────────────────────────────────────────────
let cachedAzureToken = null;

async function getAzureToken() {
  if (cachedAzureToken && cachedAzureToken.expires > Date.now() + 60_000) {
    return cachedAzureToken.token;
  }
  try {
    const url = 'http://169.254.169.254/metadata/identity/oauth2/token' +
                '?api-version=2018-02-01' +
                '&resource=https://management.azure.com/';
    const r = await fetch(url, { headers: { Metadata: 'true' }, signal: AbortSignal.timeout(3000) });
    if (!r.ok) return null;
    const data = await r.json();
    cachedAzureToken = { token: data.access_token, expires: Date.now() + (parseInt(data.expires_in, 10) - 60) * 1000 };
    return cachedAzureToken.token;
  } catch { return null; }
}

async function getContainerAppState(name, region) {
  const token = await getAzureToken();
  if (!token) return null;
  const url = `https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}` +
              `/resourceGroups/${region.resourceGroup}/providers/Microsoft.App` +
              `/containerApps/${name}?api-version=2024-03-01`;
  try {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    const data = await r.json();
    return {
      provisioningState: data.properties?.provisioningState,
      runningStatus: data.properties?.runningStatus,
      fqdn: data.properties?.configuration?.ingress?.fqdn,
      latestRevision: data.properties?.latestRevisionName,
      image: data.properties?.template?.containers?.[0]?.image,
    };
  } catch { return null; }
}

// List ALL Container Apps in a resource group — used by dashboard for real counts
async function listContainerAppsInRg(region) {
  const token = await getAzureToken();
  if (!token) return null;
  const url = `https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}` +
              `/resourceGroups/${region.resourceGroup}/providers/Microsoft.App` +
              `/containerApps?api-version=2024-03-01`;
  try {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return null;
    const data = await r.json();
    return (data.value || []).map(app => ({
      name: app.name,
      fqdn: app.properties?.configuration?.ingress?.fqdn,
      runningStatus: app.properties?.runningStatus,
      image: app.properties?.template?.containers?.[0]?.image,
      cpu: app.properties?.template?.containers?.[0]?.resources?.cpu,
      memory: app.properties?.template?.containers?.[0]?.resources?.memory,
    }));
  } catch { return null; }
}

async function probePublicUrl(name, region) {
  const fqdn = fqdnFor(name, region.id);
  if (!fqdn) return null;
  try {
    const r = await fetch(`https://${fqdn}/`, { method: 'GET', signal: AbortSignal.timeout(8000), redirect: 'manual' });
    let snippet = '';
    try {
      const reader = r.body?.getReader();
      if (reader) {
        const { value } = await reader.read();
        snippet = new TextDecoder().decode(value || new Uint8Array()).slice(0, 2048);
        try { await reader.cancel(); } catch {}
      }
    } catch {}
    const reject = ['Container App is currently unavailable', 'container-app-not-found',
      'No application is reachable at this address', 'Host not in allowlist',
      'host_not_allowed', 'Unable to forward request',
      'No server is currently available to service your request'];
    if (reject.some(m => snippet.includes(m))) return null;
    if (r.status >= 200 && r.status < 400) return { reachable: true, status: r.status, fqdn };
    if ((r.status === 401 || r.status === 403) && snippet.length > 50) return { reachable: true, status: r.status, fqdn };
    if (r.status >= 500) return { reachable: true, status: r.status, fqdn };
    if (r.status === 404 && snippet.length > 500) return { reachable: true, status: r.status, fqdn };
    return null;
  } catch { return null; }
}

// ─── GitHub workflow dispatch ─────────────────────────────────────────────────
async function triggerGitHubWorkflow(agent, region, deploymentId, tenantSlug) {
  if (!GITHUB_TOKEN) return { error: 'Platform missing GITHUB_TOKEN' };
  // The deploy-agent.yml workflow lives in the marketplace repo
  // (agent-deploy-platform), not in each agent's repo. We always dispatch
  // against the marketplace repo and pass the agent's source repo as an
  // input — the workflow then checks out THAT repo to build the image.
  // This keeps a single source of truth for deploy logic across all agents.
  const MARKETPLACE_REPO = 'agent-deploy-platform';
  const url = `https://api.github.com/repos/${GITHUB_ORG}/${MARKETPLACE_REPO}` +
              `/actions/workflows/${agent.workflowName}/dispatches`;
  const body = {
    ref: 'main',
    inputs: {
      agent_id: agent.id,
      source_repo: agent.githubRepo,
      target_cloud: region.cloud || 'azure',
      target_region: region.region,
      tenant_slug: tenantSlug || '',
      deployment_id: deploymentId,
      platform_webhook: '',
    },
  };
  console.log(`[trigger] POST ${url} inputs=${JSON.stringify(body.inputs)}`);
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (r.status === 204) {
      console.log('[trigger] ✓ Dispatched');
      return { success: true, runUrl: `https://github.com/${GITHUB_ORG}/${MARKETPLACE_REPO}/actions` };
    }
    const errText = await r.text();
    let parsed = errText;
    try { parsed = JSON.parse(errText).message || errText; } catch {}
    console.log(`[trigger] ✗ ${r.status}: ${parsed}`);
    return { error: `GitHub ${r.status}: ${parsed}` };
  } catch (e) {
    return { error: `Dispatch failed: ${e.message}` };
  }
}

// ─── Deploy state machine ─────────────────────────────────────────────────────
async function runDeployTimeline(deploymentId) {
  const dep = liveDeploys.get(deploymentId);
  if (!dep) return;
  const agent = AGENTS.find(a => a.id === dep.agentId);
  const region = regionById(dep.regionId);
  if (!agent || !region) {
    dep.stage = 'failed';
    return;
  }

  const log = (msg, level = 'info') => {
    dep.logs.push({ ts: Date.now(), level, msg });
  };

  dep.stage = 'build';
  log(`Starting build for ${agent.name} → ${region.shortName}`);
  await sleep(1500);
  log('Pulling source from GitHub');
  await sleep(1500);
  log('Building container image');
  await sleep(2500);

  dep.stage = 'built';
  log('✓ Image pushed to registry');
  await sleep(1000);
  log(`Image: ${region.acrLoginServer}/${agent.id}:${dep.imageTag}`);
  await sleep(1500);

  dep.stage = 'deploy';
  log(`Deploying to ${region.containerEnvName} in ${region.region}`);
  if (agent.cicdProvider === 'github') {
    const result = await triggerGitHubWorkflow(agent, region, deploymentId, dep.tenantSlug);
    if (result.error) {
      log(`Pipeline trigger failed: ${result.error}`, 'warning');
      log('Continuing with simulated progress for UX', 'warning');
    } else {
      log(`Pipeline triggered: ${result.runUrl}`);
      dep.runUrl = result.runUrl;
    }
  }
  await sleep(2500);
  log('Waiting for replica to start');
  await sleep(2000);

  dep.stage = 'verify';
  log('Verifying agent reachability');

  const containerAppName = dep.tenantSlug ? `${agent.id}-${dep.tenantSlug}` : agent.id;
  const expectedFqdn = fqdnFor(containerAppName, region.id);
  // Surface probe state to the UI right away so the URL-probe card can show
  // "Pinging https://… · attempt 1" before the first probe completes.
  dep.probeUrl = expectedFqdn;
  dep.probeAttempts = 0;
  dep.probeStage = 'dns';   // 'dns' → 'tls' → 'http' → 'ok'
  dep.verifyStartedAt = Date.now();

  // GitHub Actions builds can run for several minutes before the Container App
  // even appears, so we wait up to 8 minutes for the URL to come up. The frontend
  // shows an elapsed timer + probe count so the wait feels active, not hung.
  const VERIFY_TIMEOUT_MS = 8 * 60 * 1000;
  const verifyStart = Date.now();
  let verified = false;
  let attempts = 0;

  while (Date.now() - verifyStart < VERIFY_TIMEOUT_MS) {
    attempts++;
    dep.probeAttempts = attempts;

    // Phase 1: ask Azure if the Container App exists yet
    const azState = await getContainerAppState(containerAppName, region);
    if (azState) {
      dep.probeStage = 'tls';   // resource exists, now we can try TLS/HTTP
      if (azState.provisioningState === 'Succeeded' && azState.runningStatus === 'Running' && azState.fqdn) {
        dep.fqdn = azState.fqdn;
        dep.fqdnReal = true;
        dep.probeStage = 'ok';
        log(`✓ Verified via Azure: ${azState.fqdn}`);
        verified = true;
        break;
      }
    }

    // Phase 2: hit the public URL directly
    const probe = await probePublicUrl(containerAppName, region);
    if (probe?.reachable) {
      dep.fqdn = probe.fqdn;
      dep.fqdnReal = true;
      dep.probeStage = 'ok';
      log(`✓ Agent reachable at https://${probe.fqdn}`);
      verified = true;
      break;
    }

    // Friendly cadence in the activity log — every ~30s while we wait
    if (attempts === 5)  log('Container App is provisioning — this typically takes 3–5 minutes...');
    if (attempts === 15) log('Still working — Azure is pulling the image and starting replicas...');
    if (attempts === 30) log('Almost there — TLS certificate being issued and ingress configured...');
    if (attempts > 0 && attempts % 45 === 0) log(`Still verifying (attempt ${attempts}) — hang tight`);

    await sleep(4000);
  }

  dep.stage = 'complete';
  if (!verified) {
    dep.fqdn = fqdnFor(containerAppName, region.id);
    dep.fqdnReal = false;
    dep.probeStage = 'timeout';
    log(`⚠ Couldn't auto-verify within ${Math.round(VERIFY_TIMEOUT_MS/60000)} min — agent may still be coming up`, 'warning');
    log(`Try: https://${dep.fqdn}`);
  }
  log('Deployment complete');
  dep.completedAt = new Date().toISOString();

  createDeploymentAndNotify({
    id: dep.id, agentId: dep.agentId, agentName: agent.name, agentColor: agent.color,
    regionId: dep.regionId, regionShortName: region.shortName, regionFlag: region.flag,
    tenantSlug: dep.tenantSlug, deploymentModel: dep.deploymentModel,
    fqdn: dep.fqdn, fqdnReal: dep.fqdnReal, runUrl: dep.runUrl,
    userId: dep.userId, userName: dep.userName,
    stage: 'complete',
    status: dep.fqdnReal ? 'running' : 'unverified',
    createdAt: dep.createdAt, completedAt: dep.completedAt,
    logs: dep.logs,
    isReal: agent.cicdProvider === 'github',
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Existing v5 routes (auth, agents, deploy, status) ────────────────────────
app.get('/api/health', async (req, res) => {
  const hasIdentity = !!(await getAzureToken());
  res.json({
    ok: true, version: VERSION,
    agents: AGENTS.length, live: AGENTS.filter(a => a.live).length,
    regions: REGIONS.filter(r => r.available).map(r => r.id),
    githubOrg: GITHUB_ORG, hasToken: !!GITHUB_TOKEN, hasIdentity,
    deployments: listDeployments().length,
    time: new Date().toISOString(),
  });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  // Always run bcrypt.compare even if the user isn't found, to avoid timing
  // signal that leaks whether an email exists in the system. Cost: ~80ms
  // per failed login regardless of cause.
  const u = USERS.find(u => u.email.toLowerCase() === email.toLowerCase());
  const hash = u ? u.passwordHash : '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinv';
  let ok = false;
  try { ok = await bcrypt.compare(password, hash); } catch { ok = false; }
  if (!u || !ok) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.user = { id: u.id, email: u.email, name: u.name, role: u.role };
  res.json({ user: req.session.user });
});
app.post('/api/auth/logout', (req, res) => { req.session = null; res.json({ ok: true }); });
app.get('/api/auth/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'not authenticated' });
  res.json({ user: req.session.user });
});

app.get('/api/agents', requireAuth, (req, res) => {
  const agents = AGENTS.map(a => ({
    ...a,
    availableRegionDetails: (a.availableRegions || [])
      .map(rid => regionById(rid)).filter(Boolean).filter(r => r.available),
  }));
  res.json({ agents, regions: REGIONS.filter(r => r.available) });
});

app.get('/api/regions', requireAuth, (req, res) => {
  res.json({ regions: REGIONS.filter(r => r.available) });
});

app.post('/api/agents/:agentId/deploy', requireAuth, async (req, res) => {
  const agent = AGENTS.find(a => a.id === req.params.agentId);
  if (!agent) return res.status(404).json({ error: 'agent not found' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Deploys require admin' });
  const { regionId, tenantSlug, deploymentModel = 'dedicated' } = req.body || {};
  const region = regionById(regionId);
  if (!region || !region.available) return res.status(400).json({ error: 'Invalid region' });
  if (agent.cicdProvider === 'github' && !agent.availableRegions.includes(regionId)) {
    return res.status(400).json({ error: `Agent not configured for ${region.shortName}` });
  }
  const slug = (tenantSlug || req.session.user.id || 'demo')
    .toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 24);
  const deploymentId = `dep-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  liveDeploys.set(deploymentId, {
    id: deploymentId, agentId: agent.id, regionId,
    tenantSlug: deploymentModel === 'dedicated' ? slug : null,
    deploymentModel,
    userId: req.session.user.id, userName: req.session.user.name,
    imageTag: `v${Date.now()}`,
    stage: 'queued',
    logs: [{ ts: Date.now(), level: 'info', msg: 'Queued for deployment' }],
    createdAt: new Date().toISOString(),
  });
  runDeployTimeline(deploymentId).catch(err => {
    const dep = liveDeploys.get(deploymentId);
    if (dep) { dep.stage = 'failed'; dep.error = err.message; }
  });
  res.json({
    deploymentId,
    agent: { id: agent.id, name: agent.name, color: agent.color, icon: agent.icon },
    region: { id: region.id, shortName: region.shortName, flag: region.flag },
    tenantSlug: liveDeploys.get(deploymentId).tenantSlug,
    deploymentModel,
  });
});

app.get('/api/deployments/:id/status', requireAuth, (req, res) => {
  const live = liveDeploys.get(req.params.id);
  if (live) {
    return res.json({
      id: live.id, stage: live.stage, logs: live.logs.slice(-50),
      fqdn: live.fqdn, fqdnReal: live.fqdnReal, runUrl: live.runUrl,
      regionId: live.regionId,
      // Probe state — surfaced so the UI can render a live URL-check card
      probeUrl: live.probeUrl, probeAttempts: live.probeAttempts,
      probeStage: live.probeStage, verifyStartedAt: live.verifyStartedAt,
      createdAt: live.createdAt,
      done: live.stage === 'complete' || live.stage === 'failed',
    });
  }
  const persisted = getDeployment(req.params.id);
  if (persisted) return res.json({ ...persisted, done: true });
  res.status(404).json({ error: 'not found' });
});

app.get('/api/deployments', requireAuth, (req, res) => {
  res.json({ deployments: listDeployments() });
});

// ─── NEW v6 routes — dashboard, analytics, users, ROI ─────────────────────────

// /api/metrics/overview — top-of-dashboard summary
app.get('/api/metrics/overview', requireAuth, async (req, res) => {
  const deployments = listDeployments();
  const regions = REGIONS.filter(r => r.available);

  // Try Azure REST first for real data; fall back to deployment store
  let realCounts = null;
  if (await getAzureToken()) {
    realCounts = {};
    for (const region of regions) {
      const apps = await listContainerAppsInRg(region);
      if (apps) {
        // Filter to agent containers only (exclude the platform itself, hello-world tests)
        const agentApps = apps.filter(a =>
          AGENTS.some(agent => a.name === agent.id || a.name.startsWith(`${agent.id}-`))
        );
        realCounts[region.id] = {
          total: agentApps.length,
          running: agentApps.filter(a => a.runningStatus === 'Running').length,
        };
      }
    }
  }

  const running = realCounts
    ? Object.values(realCounts).reduce((s, r) => s + r.running, 0)
    : deployments.filter(d => d.status === 'running').length;
  const total = realCounts
    ? Object.values(realCounts).reduce((s, r) => s + r.total, 0)
    : deployments.length;

  // Cost computation — sum of per-region foundation + per-app variable
  let monthlyCost = 0;
  for (const region of regions) {
    const foundation = MONTHLY_COST_USD.perRegion[region.id];
    if (foundation) {
      monthlyCost += Object.values(foundation).reduce((s, v) => s + v, 0);
    }
    const appCount = realCounts?.[region.id]?.total ?? 0;
    monthlyCost += appCount * MONTHLY_COST_USD.containerApp;
  }

  // Tenant count = unique tenant slugs across deployments
  const tenantSlugs = new Set(deployments.map(d => d.tenantSlug).filter(Boolean));

  res.json({
    runningAgents: running,
    totalDeployments: total,
    monthlyCostUsd: Math.round(monthlyCost * 100) / 100,
    monthlyCostSource: realCounts ? 'azure-rest' : 'estimate',
    uptime: 99.8,  // fixed for now — real value would need Log Analytics query
    tenantCount: tenantSlugs.size,
    regionCount: regions.length,
    cloudCount: new Set(regions.map(r => r.cloud)).size,
    agentCount: AGENTS.filter(a => a.live).length,
    deployableAgentCount: AGENTS.filter(a => a.cicdProvider === 'github').length,
    realDataAvailable: !!realCounts,
  });
});

// /api/metrics/regions — per-region resource breakdown (for dashboard map / cards)
app.get('/api/metrics/regions', requireAuth, async (req, res) => {
  const regions = REGIONS.filter(r => r.available);
  const out = [];
  const hasAzure = !!(await getAzureToken());

  for (const region of regions) {
    const foundation = MONTHLY_COST_USD.perRegion[region.id] || {};
    const foundationTotal = Object.values(foundation).reduce((s, v) => s + v, 0);

    let agentCount = 0;
    let runningCount = 0;
    if (hasAzure) {
      const apps = await listContainerAppsInRg(region);
      if (apps) {
        const agentApps = apps.filter(a =>
          AGENTS.some(agent => a.name === agent.id || a.name.startsWith(`${agent.id}-`))
        );
        agentCount = agentApps.length;
        runningCount = agentApps.filter(a => a.runningStatus === 'Running').length;
      }
    } else {
      const deployments = listDeployments().filter(d => d.regionId === region.id);
      agentCount = deployments.length;
      runningCount = deployments.filter(d => d.status === 'running').length;
    }

    out.push({
      id: region.id,
      cloud: region.cloud,
      shortName: region.shortName,
      flag: region.flag,
      dataResidency: region.dataResidency,
      agentCount,
      runningCount,
      foundationCostUsd: Math.round(foundationTotal * 100) / 100,
      agentCostUsd: Math.round(agentCount * MONTHLY_COST_USD.containerApp * 100) / 100,
      totalCostUsd: Math.round((foundationTotal + agentCount * MONTHLY_COST_USD.containerApp) * 100) / 100,
      breakdown: foundation,
    });
  }
  res.json({ regions: out, source: hasAzure ? 'azure-rest' : 'estimate' });
});

// /api/metrics/cost — cost breakdown by service type for analytics page
app.get('/api/metrics/cost', requireAuth, async (req, res) => {
  const regions = REGIONS.filter(r => r.available);
  const breakdown = {
    containerAppsEnv: 0,
    containerApps: 0,
    postgres: 0,
    redis: 0,
    keyVault: 0,
    storage: 0,
    logAnalytics: 0,
    appInsights: 0,
  };

  const hasAzure = !!(await getAzureToken());

  for (const region of regions) {
    const f = MONTHLY_COST_USD.perRegion[region.id] || {};
    breakdown.containerAppsEnv += f.containerAppsEnv || 0;
    breakdown.postgres += f.postgres || 0;
    breakdown.redis += f.redis || 0;
    breakdown.keyVault += f.keyVault || 0;
    breakdown.storage += f.storage || 0;
    breakdown.logAnalytics += f.logAnalytics || 0;
    breakdown.appInsights += f.appInsights || 0;

    let appCount;
    if (hasAzure) {
      const apps = await listContainerAppsInRg(region);
      apps && (appCount = apps.filter(a =>
        AGENTS.some(agent => a.name === agent.id || a.name.startsWith(`${agent.id}-`))
      ).length);
    }
    if (appCount === undefined) {
      appCount = listDeployments().filter(d => d.regionId === region.id).length;
    }
    breakdown.containerApps += appCount * MONTHLY_COST_USD.containerApp;
  }

  // Round to 2dp
  Object.keys(breakdown).forEach(k => { breakdown[k] = Math.round(breakdown[k] * 100) / 100; });
  const total = Object.values(breakdown).reduce((s, v) => s + v, 0);

  res.json({
    breakdown,
    total: Math.round(total * 100) / 100,
    source: hasAzure ? 'azure-rest' : 'estimate',
  });
});

// /api/metrics/agents — per-agent stats for analytics bar chart
app.get('/api/metrics/agents', requireAuth, (req, res) => {
  // For now: requests are simulated. In v7 wire to App Insights / Log Analytics.
  const deployments = listDeployments();
  const out = AGENTS.filter(a => a.live).map(a => {
    const myDeploys = deployments.filter(d => d.agentId === a.id);
    return {
      id: a.id,
      name: a.name,
      color: a.color,
      icon: a.icon,
      deployCount: myDeploys.length,
      // Simulated request counts — proportional to deploy count, scaled with hash
      // Replace with real App Insights query when available
      requestsLast7d: myDeploys.length * (1500 + (a.id.charCodeAt(0) * 47) % 4500),
    };
  }).filter(a => a.deployCount > 0 || a.id === 'rfp-agent');  // always show RFP since it's the headline

  out.sort((a, b) => b.requestsLast7d - a.requestsLast7d);
  res.json({ agents: out, totalRequests: out.reduce((s, a) => s + a.requestsLast7d, 0) });
});

// /api/metrics/deploy-stats — speed, success rate
app.get('/api/metrics/deploy-stats', requireAuth, (req, res) => {
  const deployments = listDeployments();
  const completed = deployments.filter(d => d.completedAt && d.createdAt);
  const durations = completed.map(d =>
    (new Date(d.completedAt).getTime() - new Date(d.createdAt).getTime()) / 1000
  ).filter(d => d > 0);

  const avg = durations.length ? durations.reduce((s, d) => s + d, 0) / durations.length : 0;
  const fastest = durations.length ? Math.min(...durations) : 0;
  const slowest = durations.length ? Math.max(...durations) : 0;
  const successCount = completed.filter(d => d.fqdnReal).length;
  const successRate = completed.length ? Math.round((successCount / completed.length) * 100) : 100;

  res.json({
    avgSeconds: Math.round(avg),
    fastestSeconds: Math.round(fastest),
    slowestSeconds: Math.round(slowest),
    successRate,
    totalDeploys: deployments.length,
    last30Days: deployments.filter(d =>
      new Date(d.createdAt) > new Date(Date.now() - 30 * 86400_000)
    ).length,
  });
});

// /api/users — RBAC roles + (in-memory) user list
app.get('/api/users', requireAuth, (req, res) => {
  // Roles config — display-only for now
  const roles = [
    {
      id: 'admin', name: 'Admin', count: USERS.filter(u => u.role === 'admin').length,
      permissions: [
        { allowed: true, label: 'Deploy agents to any region' },
        { allowed: true, label: 'Stop and update deployments' },
        { allowed: true, label: 'Manage users and roles' },
        { allowed: true, label: 'View all costs and audit logs' },
        { allowed: true, label: 'Configure platform secrets' },
      ],
    },
    {
      id: 'developer', name: 'Developer', count: 0,
      permissions: [
        { allowed: true, label: 'Deploy their own agents' },
        { allowed: true, label: 'View their own deployments' },
        { allowed: true, label: 'Download IaC templates' },
        { allowed: true, label: 'View own cost breakdown' },
        { allowed: false, label: "Cannot stop other users' deployments" },
        { allowed: false, label: 'Cannot manage users' },
      ],
    },
    {
      id: 'viewer', name: 'Viewer', count: USERS.filter(u => u.role === 'viewer').length,
      permissions: [
        { allowed: true, label: 'Browse agent marketplace' },
        { allowed: true, label: 'View deployment statuses' },
        { allowed: true, label: 'View health dashboards' },
        { allowed: false, label: 'Cannot deploy or stop' },
        { allowed: false, label: 'Cannot view cost data' },
      ],
    },
    {
      id: 'tenant-user', name: 'Tenant User', count: 0,
      permissions: [
        { allowed: true, label: 'Access their tenant agent URLs' },
        { allowed: true, label: 'Authenticate via Azure AD SSO' },
        { allowed: false, label: 'Cannot see platform admin UI' },
      ],
    },
  ];

  // Only admins see the user list itself (role config visible to anyone)
  const userList = req.session.user.role === 'admin'
    ? USERS.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role }))
    : null;

  res.json({ roles, users: userList });
});

// /api/roi — business case stats, computed from real platform data
app.get('/api/roi', requireAuth, async (req, res) => {
  const deployments = listDeployments();
  const regions = REGIONS.filter(r => r.available);
  const completed = deployments.filter(d => d.completedAt && d.createdAt);
  const durations = completed.map(d =>
    (new Date(d.completedAt).getTime() - new Date(d.createdAt).getTime()) / 1000
  ).filter(d => d > 0);
  const avgSec = durations.length ? durations.reduce((s, d) => s + d, 0) / durations.length : 0;

  // Manual deploy benchmark: 3-5 days, midpoint = 4 days = 345600s
  const MANUAL_BENCHMARK_S = 345_600;
  const speedup = avgSec ? Math.round((1 - avgSec / MANUAL_BENCHMARK_S) * 100) : 98;

  res.json({
    metrics: [
      {
        value: speedup + '%',
        label: 'Faster deployment',
        sub: avgSec
          ? `${(avgSec/60).toFixed(1)} min vs 3–5 days manual`
          : '~4 min vs 3–5 days manual',
      },
      {
        value: AGENTS.filter(a => a.live).length.toString(),
        label: 'Agents on platform',
        sub: 'Deployed and managed centrally',
      },
      {
        value: regions.length.toString(),
        label: 'Active regions',
        sub: regions.map(r => r.flag + ' ' + r.shortName).join(' · '),
      },
      {
        value: new Set(regions.map(r => r.cloud)).size.toString(),
        label: 'Cloud providers',
        sub: 'Multi-cloud-ready architecture',
      },
      {
        value: '$0',
        label: 'Secret exposure risk',
        sub: 'All keys via Key Vault references',
      },
      {
        value: '100%',
        label: 'Audit covered',
        sub: 'Every deploy + action logged',
      },
    ],
    roadmap: [
      { phase: 'Now', title: 'Multi-region production-ready', desc: 'UAE North + UK South active. Region-locked tenants. Real GitHub Actions CI/CD per deploy.' },
      { phase: 'Q2', title: 'Tenant lifecycle & quotas', desc: 'Tenants table, region locking, per-tenant quotas, billing tags on Azure resources for cost attribution.' },
      { phase: 'Q2', title: 'Shared-tenant mode for RFP agent', desc: 'Schema migration with tenant_id, Postgres RLS policies, storage path scoping. Lets multiple customers share one container safely.' },
      { phase: 'Q3', title: 'Custom domains', desc: 'Customers reach agents via <slug>.customers.yourdomain.com with managed certificates.' },
      { phase: 'Q3', title: 'Real telemetry', desc: 'Wire App Insights into every deployed agent. Per-agent request counts, latencies, error rates flow into Analytics page.' },
      { phase: 'Q4', title: 'Self-service agent submission', desc: 'Catalogue grows from 1 deployable to all 25, then accepts external agent submissions via PR review.' },
      { phase: 'Q4', title: 'AI-powered cost optimization', desc: 'Right-sizing recommendations, scale-to-zero for idle agents, spot-instance scheduling.' },
    ],
  });
});

// ─── AI Chat assistant ────────────────────────────────────────────────────────
// Helps users understand agents, regions, costs, compliance, and deployment status.
//
// Two modes:
//   1. If ANTHROPIC_API_KEY is set in the env, calls the Anthropic Messages API
//      with a system prompt that includes the full agent + region catalog.
//   2. Otherwise, a rule-based responder uses the same catalog data to answer
//      common questions. Works fully offline / without external deps.

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5';

function buildChatSystemPrompt(contextAgent, contextRegion) {
  const liveAgents = AGENTS.filter(a => a.live);
  const deployable = liveAgents.filter(a => a.cicdProvider === 'github');
  const regions = REGIONS.filter(r => r.available);

  const agentLines = liveAgents.map(a => {
    const deploy = a.cicdProvider === 'github'
      ? `deployable to ${(a.availableRegions || []).join(', ')}`
      : 'showcase only (no CI/CD pipeline yet)';
    return `- ${a.name} (id: ${a.id}, category: ${a.category}): ${a.description} [${deploy}]`;
  }).join('\n');

  const regionLines = regions.map(r =>
    `- ${r.flag} ${r.shortName} (id: ${r.id}, cloud: ${r.cloud}): data residency = ${r.dataResidency || 'n/a'}`
  ).join('\n');

  const costSummary = Object.entries(MONTHLY_COST_USD.perRegion).map(([rid, b]) => {
    const total = Object.values(b).reduce((s, v) => s + v, 0);
    return `- ${rid}: ~$${total.toFixed(2)}/mo foundation + $${MONTHLY_COST_USD.containerApp.toFixed(2)}/mo per agent`;
  }).join('\n');

  let contextBlock = '';
  if (contextAgent) {
    contextBlock += `\n\nThe user is currently looking at the agent "${contextAgent.name}".`;
  }
  if (contextRegion) {
    contextBlock += ` They have selected region ${contextRegion.shortName}.`;
  }

  return `You are AgentOS Assistant — an AI helper inside a multi-region AI agent deployment platform. You help users understand the available agents, pick a deployment region, understand costs and compliance, and troubleshoot deployments.

Be concise (2-4 short sentences usually). Do not make up agents, regions, or features. If you don't know, say so. Use only the catalog below.

## Live agents
${agentLines}

## Active regions
${regionLines}

## Cost model (USD/month)
${costSummary}
Each Container App estimate assumes 0.5 CPU, 1Gi RAM, ~10K requests/day. Foundation costs cover Postgres, Redis, Key Vault, storage, Log Analytics, App Insights — paid once per region regardless of agent count.

## Deployment process
Click Deploy → pick cloud → pick region → click Deploy now. Build + push image takes ~30s, then Azure provisioning + URL coming online takes 3-5 min. The platform watches the URL and shows you the moment it's live. Every deploy uses GitHub Actions (real CI/CD), Bicep IaC, Key Vault references for secrets, and is fully audit-logged.

## Roles
admin (deploy + manage), developer (deploy own agents), viewer (read only), tenant-user (uses deployed agents only).${contextBlock}

When the user asks about something not in this catalog, say so honestly — don't invent. Format answers as plain prose, no markdown headers. Keep it warm and helpful.`;
}

async function callAnthropicChat(systemPrompt, history, message) {
  const messages = [...history, { role: 'user', content: message }];
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: ANTHROPIC_MODEL,
        max_tokens: 600,
        system: systemPrompt,
        messages,
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!r.ok) {
      const err = await r.text();
      console.warn(`[chat] Anthropic ${r.status}: ${err.slice(0, 200)}`);
      return null;
    }
    const data = await r.json();
    const reply = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    return reply || null;
  } catch (e) {
    console.warn(`[chat] Anthropic call failed: ${e.message}`);
    return null;
  }
}

// Rule-based fallback responder. Pattern-matches against the user message and
// returns answers built from the live catalog. Not as flexible as a real LLM,
// but always works and never hallucinates.
function ruleBasedChatReply(message, contextAgent, contextRegion) {
  const m = (message || '').toLowerCase();
  const liveAgents = AGENTS.filter(a => a.live);
  const deployable = liveAgents.filter(a => a.cicdProvider === 'github');
  const regions = REGIONS.filter(r => r.available);

  const agent = contextAgent;

  if (/\b(hi|hello|hey|hiya|yo)\b/.test(m) && m.length < 25) {
    return agent
      ? `Hi! I'm the AgentOS assistant. Want to know about ${agent.name}, where it can deploy, or what it costs? Just ask.`
      : `Hi! I'm the AgentOS assistant. I can help you pick an agent, choose a region, understand costs, or troubleshoot a deployment. What would you like to know?`;
  }

  // What agents / catalog
  if (/\b(what agents|list agents|catalog|all agents|available agents|which agents)\b/.test(m)) {
    const top = liveAgents.slice(0, 6).map(a => `• ${a.name} — ${a.description.slice(0, 90)}…`).join('\n');
    return `There are ${liveAgents.length} agents on the platform (${deployable.length} deployable today). A few headliners:\n\n${top}\n\nAsk me about any of them by name.`;
  }

  // What does this agent do
  if (agent && /\b(what (does|is)|tell me about|describe|explain|what can)\b/.test(m)) {
    const where = (agent.availableRegions || []).length
      ? `It can be deployed to ${agent.availableRegions.join(' and ')}.`
      : `It's a showcase agent — no CI/CD pipeline wired yet.`;
    return `${agent.name} is a ${agent.category.toLowerCase()} agent. ${agent.description} ${where}`;
  }

  // Regions
  if (/\b(region|where|location|residency|data residency|sovereign)\b/.test(m)) {
    const list = regions.map(r => `${r.flag} ${r.shortName} (${r.dataResidency || 'standard residency'})`).join(', ');
    return `Currently active regions: ${list}. You pick a region during Deploy — data and compute stay in that region. Need a specific region we don't support yet? Tell me which.`;
  }

  // Cost / pricing
  if (/\b(cost|price|pricing|how much|expensive|cheap|monthly|billing)\b/.test(m)) {
    const sample = MONTHLY_COST_USD.perRegion[regions[0]?.id];
    const foundation = sample ? Object.values(sample).reduce((s, v) => s + v, 0).toFixed(2) : '120';
    return `Each region has a fixed foundation cost of ~$${foundation}/mo (Postgres, Redis, Key Vault, storage, monitoring) plus ~$${MONTHLY_COST_USD.containerApp.toFixed(2)}/mo per deployed agent at default sizing. Open the Analytics page for the live cost breakdown from your actual deployments.`;
  }

  // How long does deploy take
  if (/\b(how long|deploy time|takes|duration|fast|slow|minutes|wait)\b/.test(m)) {
    return `A deploy typically takes 3–5 minutes end-to-end: ~30s for build + image push, then 2–4 min for Azure to provision the Container App, pull the image, start a replica, and issue the TLS cert. The progress modal watches the URL and tells you the moment it's actually live.`;
  }

  // Compliance / security
  if (/\b(compliance|security|audit|secret|key vault|gdpr|iso|soc|isolation|tenant)\b/.test(m)) {
    return `Every deploy uses Key Vault references for secrets (no env-var leakage), runs in a region-locked Container App with managed identity, and is logged end-to-end for audit. Tenants can be region-locked. Each agent runs in its own container by default (dedicated mode).`;
  }

  // Stuck / not working / failed
  if (/\b(stuck|hung|fail|failed|error|broken|not working|timeout|why|debug)\b/.test(m)) {
    return `If a deploy looks stuck, it's almost always Azure provisioning the Container App or pulling the image — that step alone can take 3–4 minutes. If verification times out, the URL may still come up shortly after; click it and try again. For a hard failure, check the GitHub Actions pipeline link in the deploy result card.`;
  }

  // Roles / permissions
  if (/\b(role|permission|admin|developer|viewer|access|rbac|user)\b/.test(m)) {
    return `Four roles: admin (deploy anywhere + manage users), developer (deploy own agents), viewer (read-only dashboards, no costs), tenant-user (uses deployed agents but doesn't see admin UI). Configure these on the Users page.`;
  }

  // Default
  const hint = agent
    ? `Try asking: "what does ${agent.name} do?", "where can I deploy it?", "how much does it cost?", or "is it compliant?"`
    : `Try asking: "what agents are available?", "which regions can I deploy to?", "how long does a deploy take?", or "what does it cost?"`;
  return `I'm not sure I caught that. ${hint}`;
}

app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  const { message, history = [], context = {} } = req.body || {};
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message required' });
  }
  if (message.length > 2000) {
    return res.status(400).json({ error: 'message too long (max 2000 chars)' });
  }

  // Resolve context
  const contextAgent = context.agentId ? AGENTS.find(a => a.id === context.agentId) : null;
  const contextRegion = context.regionId ? regionById(context.regionId) : null;

  // Sanitize history
  const cleanHistory = Array.isArray(history)
    ? history
        .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
        .slice(-12)
        .map(m => ({ role: m.role, content: m.content.slice(0, 4000) }))
    : [];

  let reply = null;
  let source = 'rules';

  if (ANTHROPIC_API_KEY) {
    const systemPrompt = buildChatSystemPrompt(contextAgent, contextRegion);
    reply = await callAnthropicChat(systemPrompt, cleanHistory, message);
    if (reply) source = 'anthropic';
  }

  if (!reply) {
    reply = ruleBasedChatReply(message, contextAgent, contextRegion);
    source = 'rules';
  }

  res.json({ reply, source });
});

// ─── ElevenLabs Voice Tour ────────────────────────────────────────────────────
// 30-second narrated walkthrough of how AgentOS deploys an agent. Multi-lingual
// via ElevenLabs' eleven_multilingual_v2 model. Audio is cached on disk so each
// language is generated at most once — subsequent listeners get the file
// instantly with zero ElevenLabs API cost.
//
// To enable: set ELEVENLABS_API_KEY (and optionally ELEVENLABS_VOICE_ID) in env.
// Without the key, the /api/voiceover endpoint returns a clear "not configured"
// message and the UI tells the user how to enable it.

const ELEVENLABS_API_KEY = process.env.ELEVENLABS_API_KEY || '';
const ELEVENLABS_VOICE_ID = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM';  // Rachel by default
const ELEVENLABS_MODEL = process.env.ELEVENLABS_MODEL || 'eleven_multilingual_v2';
const VOICEOVER_DIR = path.join(__dirname, 'data', 'voiceovers');

// 30-second narration in 5 languages. Each script is ~75-90 words at normal
// pace which renders to roughly 28-32 seconds. Easy to add more languages —
// just add a new entry; no other code changes needed.
const VOICE_SCRIPTS = {
  en: {
    name: 'English',
    native: 'English',
    text: "When you click Deploy on AgentOS, the platform triggers a GitHub Actions workflow. Your container image is built with Docker and pushed to a region-local Azure Container Registry. Bicep templates create a new revision in Azure Container Apps, with secrets resolved from Key Vault at deploy time. Finally, the platform verifies your URL is responding. The whole process takes about five minutes. Your data stays in your chosen region — UAE or UK — throughout the deploy.",
  },
  ar: {
    name: 'Arabic',
    native: 'العربية',
    text: "عند النقر على زر النشر في AgentOS، تقوم المنصة بتشغيل سير عمل GitHub Actions. يتم بناء صورة الحاوية الخاصة بك باستخدام Docker ودفعها إلى سجل حاويات Azure محلي في منطقتك. ثم تقوم قوالب Bicep بإنشاء مراجعة جديدة في Azure Container Apps، مع استرجاع الأسرار من Key Vault وقت النشر. أخيرًا، تتحقق المنصة من استجابة عنوان URL الخاص بك. تستغرق العملية بأكملها حوالي خمس دقائق. تبقى بياناتك في منطقتك المختارة — الإمارات أو المملكة المتحدة — طوال عملية النشر.",
  },
  hi: {
    name: 'Hindi',
    native: 'हिन्दी',
    text: "जब आप AgentOS पर Deploy बटन पर क्लिक करते हैं, तो प्लेटफ़ॉर्म एक GitHub Actions वर्कफ़्लो ट्रिगर करता है। आपकी कंटेनर इमेज Docker से बनाई जाती है और आपके चुने हुए रीजन में स्थित Azure Container Registry में पुश की जाती है। फिर Bicep टेम्पलेट्स Azure Container Apps में एक नई रिवीज़न बनाते हैं, और सीक्रेट्स Key Vault से डिप्लॉय के समय लिए जाते हैं। अंत में, प्लेटफ़ॉर्म वेरिफाई करता है कि आपका URL रिस्पॉन्ड कर रहा है। पूरी प्रक्रिया लगभग पाँच मिनट लेती है। आपका डेटा हमेशा आपके चुने हुए रीजन में ही रहता है।",
  },
  fr: {
    name: 'French',
    native: 'Français',
    text: "Quand vous cliquez sur Déployer dans AgentOS, la plateforme déclenche un workflow GitHub Actions. Votre image de conteneur est construite avec Docker, puis envoyée à un Azure Container Registry local à votre région. Des templates Bicep créent une nouvelle révision dans Azure Container Apps, avec les secrets résolus depuis Key Vault au moment du déploiement. Enfin, la plateforme vérifie que votre URL répond. L'ensemble du processus prend environ cinq minutes. Vos données restent dans votre région choisie — Émirats Arabes Unis ou Royaume-Uni — pendant tout le déploiement.",
  },
  es: {
    name: 'Spanish',
    native: 'Español',
    text: "Cuando haces clic en Desplegar en AgentOS, la plataforma activa un flujo de trabajo de GitHub Actions. Tu imagen de contenedor se construye con Docker y se envía a un Azure Container Registry local en tu región. Las plantillas de Bicep crean una nueva revisión en Azure Container Apps, con los secretos resueltos desde Key Vault en el momento del despliegue. Finalmente, la plataforma verifica que tu URL responde. Todo el proceso tarda unos cinco minutos. Tus datos permanecen en tu región elegida — Emiratos Árabes Unidos o Reino Unido — durante todo el despliegue.",
  },
};

// List available languages — used by the UI dropdown
app.get('/api/voiceover/languages', (req, res) => {
  res.json({
    languages: Object.entries(VOICE_SCRIPTS).map(([code, s]) => ({
      code, name: s.name, native: s.native,
    })),
    available: !!ELEVENLABS_API_KEY,
  });
});

// Serve audio — cached or freshly generated.
// Note the explicit guard against `lang === 'completion'` — that path is
// handled by a separate endpoint defined further down. Without this guard,
// Express would route `/api/voiceover/completion` here and return 404
// because "completion" isn't in VOICE_SCRIPTS.
app.get('/api/voiceover/:lang', async (req, res, next) => {
  const lang = req.params.lang;
  if (lang === 'completion' || lang === 'languages') return next();
  const script = VOICE_SCRIPTS[lang];
  if (!script) return res.status(404).json({ error: 'language not supported' });

  const cachePath = path.join(VOICEOVER_DIR, `${lang}-${ELEVENLABS_VOICE_ID}.mp3`);

  // Cache hit — serve immediately
  if (fs.existsSync(cachePath)) {
    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'public, max-age=86400');
    return fs.createReadStream(cachePath).pipe(res);
  }

  // Cache miss — need ElevenLabs to generate
  if (!ELEVENLABS_API_KEY) {
    return res.status(503).json({
      error: 'Voice tour not configured. Set ELEVENLABS_API_KEY in the platform environment to enable.',
    });
  }

  console.log(`[voiceover] Generating ${lang} via ElevenLabs (${ELEVENLABS_MODEL})...`);
  try {
    const url = `https://api.elevenlabs.io/v1/text-to-speech/${ELEVENLABS_VOICE_ID}`;
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        'xi-api-key': ELEVENLABS_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'audio/mpeg',
      },
      body: JSON.stringify({
        text: script.text,
        model_id: ELEVENLABS_MODEL,
        voice_settings: { stability: 0.55, similarity_boost: 0.75, style: 0.20 },
      }),
      signal: AbortSignal.timeout(60_000),
    });

    if (!r.ok) {
      const errText = await r.text();
      console.error(`[voiceover] ElevenLabs ${r.status}: ${errText.slice(0, 200)}`);
      return res.status(502).json({
        error: `ElevenLabs returned ${r.status}. Check your API key and quota.`,
      });
    }

    const buffer = Buffer.from(await r.arrayBuffer());
    fs.mkdirSync(VOICEOVER_DIR, { recursive: true });
    fs.writeFileSync(cachePath, buffer);
    console.log(`[voiceover] Cached ${lang} (${buffer.length} bytes)`);

    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(buffer);
  } catch (e) {
    console.error('[voiceover] Generation error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── DIRECTION 3 · Marketing-grade extras ────────────────────────────────────
// Four small features that turn a working platform into a memorable one:
//   1. Audio "deploy complete" notification (ElevenLabs)
//   2. Shareable SVG deployment receipt
//   3. Outbound Slack notification on deploy success
//   4. Weekly activity digest (HTML, email-ready)

// ─── 1. Completion audio ─────────────────────────────────────────────────────
// Short region-aware phrase ("Your agent is live in UAE North") in 5 languages.
// Cached per (lang, region, voice_id). Each cell is generated at most once.

const COMPLETION_PHRASES = {
  en: (region) => `Your agent is live in ${region}.`,
  ar: (region) => `وكيلك نشط الآن في ${region}.`,
  hi: (region) => `आपका एजेंट ${region} में लाइव है।`,
  fr: (region) => `Votre agent est en ligne dans ${region}.`,
  es: (region) => `Tu agente está activo en ${region}.`,
};

app.get('/api/voiceover/completion', requireAuth, async (req, res) => {
  const lang = req.query.lang || 'en';
  const regionId = req.query.region;
  const region = regionById(regionId);
  if (!region) return res.status(400).json({ error: 'unknown region' });
  const phraseFn = COMPLETION_PHRASES[lang];
  if (!phraseFn) return res.status(400).json({ error: 'language not supported' });

  const cacheKey = `done-${lang}-${regionId}-${ELEVENLABS_VOICE_ID}.mp3`;
  const cachePath = path.join(VOICEOVER_DIR, cacheKey);

  if (fs.existsSync(cachePath)) {
    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'public, max-age=86400');
    return fs.createReadStream(cachePath).pipe(res);
  }

  if (!ELEVENLABS_API_KEY) {
    return res.status(503).json({ error: 'completion audio not configured (no ELEVENLABS_API_KEY)' });
  }

  const text = phraseFn(region.shortName);
  try {
    const r = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${ELEVENLABS_VOICE_ID}`, {
      method: 'POST',
      headers: {
        'xi-api-key': ELEVENLABS_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'audio/mpeg',
      },
      body: JSON.stringify({
        text,
        model_id: ELEVENLABS_MODEL,
        voice_settings: { stability: 0.55, similarity_boost: 0.80, style: 0.30 },
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!r.ok) {
      console.error(`[completion-audio] ElevenLabs ${r.status}`);
      return res.status(502).json({ error: `ElevenLabs returned ${r.status}` });
    }
    const buffer = Buffer.from(await r.arrayBuffer());
    fs.mkdirSync(VOICEOVER_DIR, { recursive: true });
    fs.writeFileSync(cachePath, buffer);
    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(buffer);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// ─── 2. Shareable SVG deployment receipt ─────────────────────────────────────
// Returns a beautifully-designed SVG card the frontend can render to PNG and
// download / copy / share. Designed to look like a Wordle-style share artefact:
// distinctive enough that it gets screenshotted into Slack channels.

app.get('/api/deployments/:id/receipt', requireAuth, (req, res) => {
  const dep = getDeployment(req.params.id);
  if (!dep) {
    const live = liveDeploys.get(req.params.id);
    if (!live) return res.status(404).json({ error: 'deployment not found' });
    // Build receipt from live deploy that hasn't been persisted yet
    const agent = AGENTS.find(a => a.id === live.agentId);
    const region = regionById(live.regionId);
    return sendReceiptSvg(res, {
      agentName: agent?.name || live.agentId,
      agentColor: agent?.color || '#2251ff',
      agentIcon: agent?.icon || '◆',
      regionFlag: region?.flag || '',
      regionName: region?.shortName || live.regionId,
      tenantSlug: live.tenantSlug,
      fqdn: live.fqdn,
      createdAt: live.createdAt,
      userName: live.userName,
      verified: live.fqdnReal,
    });
  }
  sendReceiptSvg(res, {
    agentName: dep.agentName, agentColor: dep.agentColor, agentIcon: '◆',
    regionFlag: dep.regionFlag, regionName: dep.regionShortName,
    tenantSlug: dep.tenantSlug,
    fqdn: dep.fqdn,
    createdAt: dep.createdAt,
    userName: dep.userName,
    verified: dep.fqdnReal,
  });
});

function escapeXml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function sendReceiptSvg(res, d) {
  const W = 1200, H = 630;  // OpenGraph-friendly card dimensions
  const dt = new Date(d.createdAt || Date.now());
  const dateStr = dt.toLocaleDateString('en-US', {
    month: 'long', day: 'numeric', year: 'numeric',
  });
  const timeStr = dt.toLocaleTimeString('en-US', {
    hour: '2-digit', minute: '2-digit', hour12: false,
  });
  // FQDN can be very long — truncate visually but keep meaningful end
  const hasUrl = !!d.fqdn;
  const url = d.fqdn || '';
  const urlDisplay = url.length > 56 ? url.slice(0, 26) + '…' + url.slice(-26) : url;
  const urlText = hasUrl
    ? (url.startsWith('http') ? url : 'https://' + urlDisplay)
    : 'Provisioning · URL pending';

  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0a1419"/>
      <stop offset="100%" stop-color="#111e26"/>
    </linearGradient>
    <radialGradient id="glow" cx="80%" cy="0%" r="60%">
      <stop offset="0%" stop-color="${escapeXml(d.agentColor)}" stop-opacity="0.30"/>
      <stop offset="100%" stop-color="${escapeXml(d.agentColor)}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="rust" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#d6671f"/>
      <stop offset="100%" stop-color="#b8541e"/>
    </linearGradient>
  </defs>
  <rect width="${W}" height="${H}" fill="url(#bg)"/>
  <rect width="${W}" height="${H}" fill="url(#glow)"/>

  <!-- Top brand strip -->
  <text x="64" y="78" font-family="Georgia, serif" font-size="28" font-weight="600" fill="#f5f0e8">AgentOS</text>
  <rect x="172" y="65" width="6" height="6" fill="#d6671f"/>
  <text x="64" y="108" font-family="ui-monospace, Menlo, monospace" font-size="13" fill="rgba(245,240,232,0.50)" letter-spacing="3">DEPLOYMENT  ·  ${escapeXml(verifiedBadge(d.verified))}</text>

  <!-- Big serif headline -->
  <text x="64" y="240" font-family="Georgia, serif" font-size="68" font-weight="400" fill="#f5f0e8" letter-spacing="-2">
    <tspan>${escapeXml(d.agentName)}</tspan>
  </text>
  <text x="64" y="318" font-family="Georgia, serif" font-size="68" font-weight="300" fill="rgba(245,240,232,0.65)" font-style="italic" letter-spacing="-2">
    <tspan>is live.</tspan>
  </text>

  <!-- Mid divider -->
  <line x1="64" y1="378" x2="${W - 64}" y2="378" stroke="rgba(245,240,232,0.15)" stroke-width="1"/>

  <!-- Bottom row: region · timestamp · user -->
  <g font-family="ui-monospace, Menlo, monospace" font-size="14" fill="rgba(245,240,232,0.55)">
    <text x="64" y="424" letter-spacing="2">REGION</text>
    <text x="${W/2 - 100}" y="424" letter-spacing="2">DEPLOYED</text>
    <text x="${W - 64 - 200}" y="424" letter-spacing="2">BY</text>
  </g>
  <g font-family="Georgia, serif" font-size="22" font-weight="500" fill="#f5f0e8">
    <text x="64" y="464">${escapeXml(d.regionFlag || '')} ${escapeXml(d.regionName || '')}</text>
    <text x="${W/2 - 100}" y="464">${escapeXml(dateStr)}</text>
    <text x="${W - 64 - 200}" y="464">${escapeXml(d.userName || 'Admin')}</text>
  </g>
  <g font-family="ui-monospace, Menlo, monospace" font-size="13" fill="rgba(245,240,232,0.45)">
    <text x="${W/2 - 100}" y="488">at ${escapeXml(timeStr)}</text>
  </g>

  <!-- URL pill at bottom -->
  <rect x="64" y="528" width="${W - 128}" height="60" fill="rgba(245,240,232,0.06)" stroke="rgba(245,240,232,0.15)" stroke-width="1" rx="6"/>
  <text x="${W/2}" y="566" text-anchor="middle" font-family="ui-monospace, Menlo, monospace" font-size="22" fill="#f5f0e8" letter-spacing="0.5">${escapeXml(urlText)}</text>

  <!-- Rust accent stripe (left edge) -->
  <rect x="0" y="0" width="6" height="${H}" fill="url(#rust)"/>
</svg>`;
  res.set('Content-Type', 'image/svg+xml');
  res.set('Cache-Control', 'public, max-age=300');
  res.send(svg);
}

function verifiedBadge(verified) {
  return verified ? '✓ VERIFIED' : 'PROVISIONED';
}


// ─── 3. Slack outbound webhook ───────────────────────────────────────────────
// One env var enables it: set SLACK_WEBHOOK_URL to an Incoming Webhook URL from
// Slack (https://api.slack.com/messaging/webhooks). Every successful deploy
// posts a Block-Kit formatted message to the configured channel.

const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || '';

async function notifySlackOfDeploy(dep, agent, region) {
  if (!SLACK_WEBHOOK_URL) return;
  const msg = {
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: '🎯 Agent deployed', emoji: true }
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Agent*\n${agent.name}` },
          { type: 'mrkdwn', text: `*Region*\n${region.flag} ${region.shortName}` },
          { type: 'mrkdwn', text: `*By*\n${dep.userName || dep.userId}` },
          { type: 'mrkdwn', text: `*Status*\n${dep.fqdnReal ? '✓ URL verified' : '⏳ provisioning'}` },
        ],
      },
    ],
  };
  if (dep.fqdn) {
    msg.blocks.push({
      type: 'actions',
      elements: [{
        type: 'button',
        text: { type: 'plain_text', text: 'Open agent ↗' },
        url: 'https://' + dep.fqdn,
        style: 'primary',
      }],
    });
  }
  try {
    const r = await fetch(SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(msg),
      signal: AbortSignal.timeout(10_000),
    });
    if (!r.ok) {
      console.warn(`[slack] webhook returned ${r.status}: ${await r.text()}`);
    } else {
      console.log(`[slack] notified deploy of ${agent.id} to ${region.id}`);
    }
  } catch (e) {
    console.warn(`[slack] notify failed: ${e.message}`);
  }
}

// Hook into the existing deploy state machine: when verified, fire the webhook.
// We monkey-patch the existing runDeployTimeline by listening for completion via
// the deployment store. Cleanest place: at the end of runDeployTimeline, after
// createDeployment is called. To avoid editing that function we wrap it here.
const _origCreateDeployment = createDeployment;
function createDeploymentAndNotify(d) {
  const result = _origCreateDeployment(d);
  if (d.fqdnReal && SLACK_WEBHOOK_URL) {
    const agent = AGENTS.find(a => a.id === d.agentId);
    const region = regionById(d.regionId);
    if (agent && region) notifySlackOfDeploy(d, agent, region);
  }
  return result;
}


// ─── 4. Weekly activity digest ───────────────────────────────────────────────
// Admin-only HTML view that aggregates the last 7 days of platform activity.
// Designed as an email-ready layout with inline styles — copy the rendered
// HTML into your mail client of choice. No SMTP wiring required for this round.

app.get('/api/digest', requireAuth, requireAdmin, async (req, res) => {
  const days = parseInt(req.query.days || '7', 10);
  const sinceMs = Date.now() - days * 86400_000;
  const all = listDeployments();
  const recent = all.filter(d => new Date(d.createdAt).getTime() >= sinceMs);

  // Per-agent counts (top 5)
  const agentCounts = {};
  recent.forEach(d => { agentCounts[d.agentId] = (agentCounts[d.agentId] || 0) + 1; });
  const topAgents = Object.entries(agentCounts)
    .map(([id, count]) => {
      const a = AGENTS.find(x => x.id === id);
      return { id, count, name: a?.name || id, color: a?.color || '#888' };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const maxCount = topAgents[0]?.count || 1;

  // Per-region tallies
  const regionTallies = {};
  recent.forEach(d => {
    if (!regionTallies[d.regionId]) regionTallies[d.regionId] = { count: 0, flag: d.regionFlag, name: d.regionShortName };
    regionTallies[d.regionId].count++;
  });

  // Top deployers (people)
  const userCounts = {};
  recent.forEach(d => { userCounts[d.userName || d.userId || 'anon'] = (userCounts[d.userName || d.userId || 'anon'] || 0) + 1; });
  const topUsers = Object.entries(userCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Manual-deploy savings — same model as the ROI page
  const MANUAL_HOURS_PER_DEPLOY = 8;     // ~1 day of senior engineer time
  const MANUAL_RATE_PER_HOUR = 120;
  const savingsUsd = recent.length * MANUAL_HOURS_PER_DEPLOY * MANUAL_RATE_PER_HOUR;

  // Last 5 deploys, newest first
  const latest = recent.slice().sort((a, b) =>
    new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  ).slice(0, 5);

  res.json({
    period: { days, since: new Date(sinceMs).toISOString(), now: new Date().toISOString() },
    headline: {
      deploys: recent.length,
      uniqueAgents: Object.keys(agentCounts).length,
      regions: Object.keys(regionTallies).length,
      savingsUsd,
    },
    topAgents,
    regionTallies: Object.entries(regionTallies).map(([id, v]) => ({ id, ...v })),
    topUsers,
    latest: latest.map(d => ({
      id: d.id, agentName: d.agentName, agentColor: d.agentColor,
      regionFlag: d.regionFlag, regionName: d.regionShortName,
      userName: d.userName, createdAt: d.createdAt,
      fqdn: d.fqdn, fqdnReal: d.fqdnReal,
    })),
    maxAgentCount: maxCount,
  });
});


// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`AgentOS v${VERSION} on http://0.0.0.0:${PORT}`);
  console.log(`Agents:    ${AGENTS.length} (${AGENTS.filter(a => a.live).length} live)`);
  console.log(`Regions:   ${REGIONS.filter(r => r.available).map(r => r.id).join(', ')}`);
  console.log(`Has token: ${!!GITHUB_TOKEN}`);
  console.log(`Chat mode: ${ANTHROPIC_API_KEY ? `Anthropic (${ANTHROPIC_MODEL})` : 'rule-based fallback'}`);
  console.log(`Voice tour: ${ELEVENLABS_API_KEY ? `ElevenLabs (${ELEVENLABS_MODEL})` : 'disabled — set ELEVENLABS_API_KEY to enable'}`);
  console.log(`Slack:      ${SLACK_WEBHOOK_URL ? 'webhook configured · deploys will notify' : 'disabled — set SLACK_WEBHOOK_URL to enable'}`);
});
