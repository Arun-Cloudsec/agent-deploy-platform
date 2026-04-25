/**
 * deployment-store.js
 *
 * Persistent store for deployment records and their log streams. Backed by
 * better-sqlite3 (synchronous), which matches how cicd-connector.js and
 * server-with-auth.js invoke the methods (no awaits).
 *
 * Lives in agent-deploy-platform/src/. The DB file defaults to
 * ./data/deployments.db (sibling of users.db) and can be overridden via
 * DEPLOYMENT_DB_PATH.
 *
 * Schema is created on first import — no separate migration step needed.
 *
 * Public API (do not break — cicd-connector.js depends on these):
 *   createDeployment(record)             insert a new deployment
 *   getDeployment(id)                    fetch one + recent logs
 *   updateDeployment(id, fields)         patch any column except id
 *   listDeployments()                    all rows, newest first
 *   addLog(id, message, level?)          append a log line
 *   getDeploymentLogs(id)                all logs for a deployment
 *   getDeploymentStats()                 counts by status
 *   getCostSummary(userId | null)        cost rollup, scoped by user if given
 *   deleteDeployment(id)                 hard-delete (admin only path)
 */

const path     = require("path");
const fs       = require("fs");
const Database = require("better-sqlite3");

// ── DB SETUP ──────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DEPLOYMENT_DB_PATH ||
                path.join(process.cwd(), "data", "deployments.db");

// Ensure the directory exists (./data is created by deploy.sh, but be safe)
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");   // better concurrency for read-while-write
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS deployments (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    agent_name    TEXT,
    target        TEXT,                 -- e.g. 'azure-container-apps', 'aws-ecs'
    region        TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
                                        -- pending | deploying | running | failed | destroyed
    config        TEXT,                 -- JSON blob (stringified by caller)
    env_vars      TEXT,                 -- JSON array (stringified by caller)
    deployed_by   TEXT,                 -- user id from auth layer
    url           TEXT,                 -- live agent URL once deployed
    error         TEXT,                 -- last error message, if any
    resource_ids  TEXT,                 -- JSON of pipeline run info / azure resource ids
    cost_usd      REAL DEFAULT 0,       -- accumulated cost (if your engine reports it)
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_deployments_status      ON deployments(status);
  CREATE INDEX IF NOT EXISTS idx_deployments_deployed_by ON deployments(deployed_by);
  CREATE INDEX IF NOT EXISTS idx_deployments_created_at  ON deployments(created_at DESC);

  CREATE TABLE IF NOT EXISTS deployment_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id  TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    message        TEXT NOT NULL,
    level          TEXT NOT NULL DEFAULT 'info',   -- info | warn | error
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_deployment_logs_deployment_id
    ON deployment_logs(deployment_id, created_at);
`);

// ── PREPARED STATEMENTS ──────────────────────────────────────────────────────
const stmts = {
  insert: db.prepare(`
    INSERT INTO deployments
      (id, agent_id, agent_name, target, region, status, config, env_vars, deployed_by)
    VALUES
      (@id, @agent_id, @agent_name, @target, @region, @status, @config, @env_vars, @deployed_by)
  `),

  getById: db.prepare(`SELECT * FROM deployments WHERE id = ?`),
  getAll:  db.prepare(`SELECT * FROM deployments ORDER BY created_at DESC`),
  delete:  db.prepare(`DELETE FROM deployments WHERE id = ?`),

  insertLog: db.prepare(`
    INSERT INTO deployment_logs (deployment_id, message, level)
    VALUES (?, ?, ?)
  `),

  getLogs: db.prepare(`
    SELECT id, message, level, created_at
    FROM deployment_logs
    WHERE deployment_id = ?
    ORDER BY created_at ASC, id ASC
  `),

  statsByStatus: db.prepare(`
    SELECT status, COUNT(*) AS n FROM deployments GROUP BY status
  `),

  totalCount: db.prepare(`SELECT COUNT(*) AS n FROM deployments`),

  costSummaryAll: db.prepare(`
    SELECT COUNT(*)        AS deployments,
           COALESCE(SUM(cost_usd), 0) AS total_cost,
           COALESCE(AVG(cost_usd), 0) AS avg_cost
    FROM deployments
    WHERE status != 'destroyed'
  `),

  costSummaryByUser: db.prepare(`
    SELECT COUNT(*)        AS deployments,
           COALESCE(SUM(cost_usd), 0) AS total_cost,
           COALESCE(AVG(cost_usd), 0) AS avg_cost
    FROM deployments
    WHERE status != 'destroyed' AND deployed_by = ?
  `),

  costByAgent: db.prepare(`
    SELECT agent_id,
           agent_name,
           COUNT(*)                   AS deployments,
           COALESCE(SUM(cost_usd), 0) AS total_cost
    FROM deployments
    WHERE status != 'destroyed'
      AND (? IS NULL OR deployed_by = ?)
    GROUP BY agent_id, agent_name
    ORDER BY total_cost DESC
  `),
};

// ── PUBLIC API ───────────────────────────────────────────────────────────────

/**
 * Insert a new deployment record. Caller already JSON.stringify()s config and
 * env_vars (matches what server-with-auth.js does today).
 *
 * Required: id, agent_id
 * Optional: everything else
 */
function createDeployment(record) {
  if (!record || !record.id) throw new Error("createDeployment: 'id' is required");
  if (!record.agent_id)      throw new Error("createDeployment: 'agent_id' is required");

  stmts.insert.run({
    id:          record.id,
    agent_id:    record.agent_id,
    agent_name:  record.agent_name  ?? null,
    target:      record.target      ?? null,
    region:      record.region      ?? null,
    status:      record.status      ?? "pending",
    config:      record.config      ?? null,
    env_vars:    record.env_vars    ?? null,
    deployed_by: record.deployed_by ?? null,
  });

  return getDeployment(record.id);
}

/**
 * Fetch a single deployment by id. Returns null if not found.
 * Includes a `logs` array (most recent ~200) for convenience —
 * cicd-connector.js only reads `.status`, so the extra payload is harmless.
 */
function getDeployment(id) {
  const row = stmts.getById.get(id);
  if (!row) return null;
  row.logs = stmts.getLogs.all(id).slice(-200);
  return row;
}

/**
 * Patch any subset of allowed columns. Unknown keys are ignored (so callers
 * can pass through extra metadata without crashing the store).
 *
 * Always bumps updated_at.
 */
const UPDATABLE = new Set([
  "agent_name", "target", "region", "status", "config", "env_vars",
  "deployed_by", "url", "error", "resource_ids", "cost_usd",
]);

function updateDeployment(id, fields) {
  if (!fields || typeof fields !== "object") return getDeployment(id);

  const sets = [];
  const vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (!UPDATABLE.has(k)) continue;
    sets.push(`${k} = ?`);
    vals.push(v);
  }
  if (sets.length === 0) return getDeployment(id);

  sets.push(`updated_at = datetime('now')`);
  vals.push(id);

  const sql = `UPDATE deployments SET ${sets.join(", ")} WHERE id = ?`;
  db.prepare(sql).run(...vals);

  return getDeployment(id);
}

/**
 * All deployments, newest first. Returns plain rows (no nested logs) since
 * the UI lists hundreds and we don't want N×log fetches.
 */
function listDeployments() {
  return stmts.getAll.all();
}

/**
 * Append a log line to a deployment.
 * level is optional and defaults to "info"; cicd-connector passes "warn"/"error".
 *
 * Silently no-ops if the deployment id doesn't exist — we don't want a
 * stray log call to crash the connector.
 */
function addLog(deploymentId, message, level) {
  if (!deploymentId || !message) return;
  const lvl = (level === "warn" || level === "error") ? level : "info";
  try {
    stmts.insertLog.run(deploymentId, String(message), lvl);
  } catch (e) {
    // Most likely cause: FK violation because deployment row doesn't exist yet.
    // Log to console rather than throwing — the connector treats logging as
    // best-effort.
    if (process.env.DEBUG_DEPLOYMENT_STORE) {
      console.warn("[deployment-store] addLog skipped:", e.message);
    }
  }
}

function getDeploymentLogs(deploymentId) {
  return stmts.getLogs.all(deploymentId);
}

/**
 * Counts per status, plus a `total`. Shape is friendly for the dashboard:
 *   { total: 12, pending: 1, deploying: 2, running: 7, failed: 1, destroyed: 1 }
 */
function getDeploymentStats() {
  const rows  = stmts.statsByStatus.all();
  const total = stmts.totalCount.get().n;

  const out = { total, pending: 0, deploying: 0, running: 0, failed: 0, destroyed: 0 };
  for (const r of rows) out[r.status] = r.n;
  return out;
}

/**
 * Cost summary. Pass null to get org-wide totals; pass a userId to scope.
 *
 * Returns:
 *   {
 *     deployments: <count of non-destroyed deployments>,
 *     total_cost:  <SUM(cost_usd)>,
 *     avg_cost:    <AVG(cost_usd)>,
 *     by_agent:    [ { agent_id, agent_name, deployments, total_cost }, ... ]
 *   }
 *
 * cost_usd is whatever your deploy engine writes — if nothing writes it,
 * everything stays at 0 and the dashboard just shows zeros. That's fine
 * until cost ingestion is wired up.
 */
function getCostSummary(userId) {
  const summary = userId
    ? stmts.costSummaryByUser.get(userId)
    : stmts.costSummaryAll.get();

  const by_agent = stmts.costByAgent.all(userId ?? null, userId ?? null);

  return {
    deployments: summary.deployments,
    total_cost:  summary.total_cost,
    avg_cost:    summary.avg_cost,
    by_agent,
  };
}

function deleteDeployment(id) {
  stmts.delete.run(id);
}

// ── EXPORTS ──────────────────────────────────────────────────────────────────
module.exports = {
  createDeployment,
  getDeployment,
  updateDeployment,
  listDeployments,
  addLog,
  getDeploymentLogs,
  getDeploymentStats,
  getCostSummary,
  deleteDeployment,
  // Exposed for tests / debugging only:
  _db: db,
};
