// src/deployment-store.js
//
// Persists deployments to disk so they survive container restarts.
// Keyed by deploymentId. Each record carries the region info needed to
// query the right Azure resource group later.

import fs from 'fs';
import path from 'path';

const DATA_DIR = process.env.DATA_DIR || '/app/data';
const DB_PATH = path.join(DATA_DIR, 'deployments.json');

let cache = null;

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function load() {
  if (cache) return cache;
  ensureDir();
  try {
    cache = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    cache = {};
  }
  return cache;
}

function save() {
  ensureDir();
  fs.writeFileSync(DB_PATH, JSON.stringify(cache, null, 2));
}

export function createDeployment(record) {
  const all = load();
  all[record.id] = {
    ...record,
    createdAt: record.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  save();
  return all[record.id];
}

export function getDeployment(id) {
  return load()[id] || null;
}

export function updateDeployment(id, fields) {
  const all = load();
  if (!all[id]) return null;
  all[id] = {
    ...all[id],
    ...fields,
    updatedAt: new Date().toISOString(),
  };
  save();
  return all[id];
}

export function listDeployments(filters = {}) {
  const all = load();
  let rows = Object.values(all);
  if (filters.userId) rows = rows.filter(d => d.userId === filters.userId);
  if (filters.tenantId) rows = rows.filter(d => d.tenantId === filters.tenantId);
  if (filters.regionId) rows = rows.filter(d => d.regionId === filters.regionId);
  return rows.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
}

export function deleteDeployment(id) {
  const all = load();
  delete all[id];
  save();
}

export function addLog(id, msg, level = 'info') {
  const all = load();
  const dep = all[id];
  if (!dep) return;
  dep.logs = dep.logs || [];
  dep.logs.push({
    ts: Date.now(),
    level,
    msg,
  });
  // Cap log size
  if (dep.logs.length > 500) dep.logs = dep.logs.slice(-500);
  dep.updatedAt = new Date().toISOString();
  save();
}

export function getDeploymentLogs(id) {
  const dep = getDeployment(id);
  return dep?.logs || [];
}
