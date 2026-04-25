/**
 * cicd-connector.js
 * Real integration between the Deploy button and Azure DevOps / GitHub.
 *
 * When Deploy is clicked:
 * 1. Platform calls Azure DevOps pipeline API OR GitHub workflow dispatch API
 * 2. Pipeline runs: checkout → build image → push to ACR → deploy Container App
 * 3. Pipeline calls back /api/webhooks/cicd when done
 * 4. Platform updates deployment status and notifies UI via WebSocket
 *
 * Add to agent-deploy-platform/src/cicd-connector.js
 */

const store = require("./deployment-store");

// ─── CONFIG (set in .env) ─────────────────────────────────────────────────────
const AZURE_DEVOPS_ORG   = process.env.AZURE_DEVOPS_ORG;       // e.g. "mycompany"
const AZURE_DEVOPS_PAT   = process.env.AZURE_DEVOPS_PAT;       // Personal Access Token
const GITHUB_TOKEN       = process.env.GITHUB_TOKEN;
const GITHUB_ORG         = process.env.GITHUB_ORG;             // e.g. "mycompany"
const PLATFORM_WEBHOOK_URL = process.env.PLATFORM_WEBHOOK_URL; // e.g. "https://myplatform.azurewebsites.net"

// ─── AZURE DEVOPS ─────────────────────────────────────────────────────────────

/**
 * Trigger an Azure DevOps pipeline run for an agent
 * Looks for a pipeline named the same as the agent ID
 */
async function triggerAzureDevOpsPipeline({ agentId, project, deploymentId, target, region, envVars }) {
  if (!AZURE_DEVOPS_ORG || !AZURE_DEVOPS_PAT) {
    throw new Error("AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT must be set in .env");
  }

  const projectName = project || agentId;
  const baseUrl     = `https://dev.azure.com/${AZURE_DEVOPS_ORG}/${projectName}/_apis`;
  const authHeader  = "Basic " + Buffer.from(`:${AZURE_DEVOPS_PAT}`).toString("base64");

  // 1. Find the pipeline by name (same name as agent repo)
  const pipelines = await azureDevOpsGet(`${baseUrl}/pipelines?api-version=7.1`, authHeader);
  const pipeline  = pipelines.value?.find(p =>
    p.name === agentId || p.name === `deploy-${agentId}` || p.name === "deploy-agent"
  );

  if (!pipeline) {
    throw new Error(`No Azure DevOps pipeline found named '${agentId}' or 'deploy-agent' in project '${projectName}'. Create it first.`);
  }

  // 2. Trigger the pipeline run with parameters
  const runBody = {
    resources: { repositories: { self: { refName: "refs/heads/main" } } },
    variables: {
      AGENT_ID:            { value: agentId },
      DEPLOY_TARGET:       { value: target },
      DEPLOY_REGION:       { value: region || "uaenorth" },
      DEPLOYMENT_ID:       { value: deploymentId },
      PLATFORM_WEBHOOK:    { value: `${PLATFORM_WEBHOOK_URL}/api/webhooks/cicd` },
      // Env vars passed as a JSON string — pipeline extracts them
      AGENT_ENV_VARS:      { value: JSON.stringify(envVars || []) },
    },
  };

  const run = await azureDevOpsPost(
    `${baseUrl}/pipelines/${pipeline.id}/runs?api-version=7.1`,
    authHeader,
    runBody
  );

  store.addLog(deploymentId, `Azure DevOps pipeline triggered. Run ID: ${run.id}`);
  store.addLog(deploymentId, `Pipeline URL: ${run._links?.web?.href || "check Azure DevOps"}`);

  return {
    provider:   "azuredevops",
    runId:      run.id,
    runUrl:     run._links?.web?.href,
    pipelineId: pipeline.id,
    status:     "running",
  };
}

/**
 * Get the current status of an Azure DevOps pipeline run
 */
async function getAzureDevOpsRunStatus({ project, agentId, pipelineId, runId }) {
  const projectName = project || agentId;
  const baseUrl     = `https://dev.azure.com/${AZURE_DEVOPS_ORG}/${projectName}/_apis`;
  const authHeader  = "Basic " + Buffer.from(`:${AZURE_DEVOPS_PAT}`).toString("base64");

  const run = await azureDevOpsGet(
    `${baseUrl}/pipelines/${pipelineId}/runs/${runId}?api-version=7.1`,
    authHeader
  );

  // Azure DevOps run states: inProgress, completed, canceling
  // Result: succeeded, failed, canceled, partiallySucceeded
  return {
    state:   run.state,
    result:  run.result,
    url:     run._links?.web?.href,
    done:    run.state === "completed",
    success: run.result === "succeeded",
  };
}

// ─── GITHUB ────────────────────────────────────────────────────────────────────

/**
 * Trigger a GitHub Actions workflow for an agent
 * Looks for a workflow file named deploy-agent.yml or deploy.yml
 */
async function triggerGitHubWorkflow({ agentId, repo, deploymentId, target, region, envVars }) {
  if (!GITHUB_TOKEN || !GITHUB_ORG) {
    throw new Error("GITHUB_TOKEN and GITHUB_ORG must be set in .env");
  }

  const repoName = repo || agentId;  // repo name = agent ID by convention
  const baseUrl  = `https://api.github.com/repos/${GITHUB_ORG}/${repoName}`;

  // 1. Find the deploy workflow
  const workflows = await githubGet(`${baseUrl}/actions/workflows`);
  const workflow  = workflows.workflows?.find(w =>
    w.path.includes("deploy-agent") || w.path.includes("deploy.yml")
  );

  if (!workflow) {
    throw new Error(`No GitHub Actions workflow found in ${GITHUB_ORG}/${repoName}. Add deploy-agent.yml first.`);
  }

  // 2. Dispatch the workflow with inputs
  await githubPost(`${baseUrl}/actions/workflows/${workflow.id}/dispatches`, {
    ref:    "main",
    inputs: {
      deploy_target:    target,
      deploy_region:    region || "uaenorth",
      deployment_id:    deploymentId,
      platform_webhook: `${PLATFORM_WEBHOOK_URL}/api/webhooks/cicd`,
    },
  });

  // 3. Get the run ID (GitHub dispatches are async — poll for the run)
  await sleep(3000);
  const runs   = await githubGet(`${baseUrl}/actions/workflows/${workflow.id}/runs?per_page=1`);
  const latestRun = runs.workflow_runs?.[0];

  store.addLog(deploymentId, `GitHub Actions workflow triggered. Run: ${latestRun?.html_url || "check GitHub"}`);

  return {
    provider:   "github",
    runId:      latestRun?.id,
    runUrl:     latestRun?.html_url,
    workflowId: workflow.id,
    status:     "running",
  };
}

/**
 * Get current status of a GitHub Actions workflow run
 */
async function getGitHubRunStatus({ agentId, repo, runId }) {
  const repoName = repo || agentId;
  const run      = await githubGet(
    `https://api.github.com/repos/${GITHUB_ORG}/${repoName}/actions/runs/${runId}`
  );

  // GitHub states: queued, in_progress, completed
  // Conclusions: success, failure, cancelled, skipped
  return {
    state:   run.status,
    result:  run.conclusion,
    url:     run.html_url,
    done:    run.status === "completed",
    success: run.conclusion === "success",
  };
}

// ─── UNIFIED TRIGGER ──────────────────────────────────────────────────────────

/**
 * Main entry point — called by the deploy engine instead of simulating
 * Detects whether to use Azure DevOps or GitHub based on agent config / env
 */
async function triggerCiCd({ ws, deploymentId, agent, target, config }) {
  const cicdProvider = agent.cicdProvider || process.env.DEFAULT_CICD_PROVIDER || "azuredevops";
  const region       = config.region || "uaenorth";
  const envVars      = config.envVars || [];

  store.addLog(deploymentId, `Connecting to ${cicdProvider === "github" ? "GitHub Actions" : "Azure DevOps"}...`);

  ws.send(JSON.stringify({
    type:  "deploy_step",
    deploymentId,
    stepId: "cicd_trigger",
    label:  `Triggering ${cicdProvider === "github" ? "GitHub Actions" : "Azure DevOps"} pipeline`,
    progress: 10,
  }));

  let pipelineRun;

  try {
    if (cicdProvider === "github") {
      pipelineRun = await triggerGitHubWorkflow({
        agentId:      agent.id,
        repo:         agent.githubRepo || agent.id,
        deploymentId, target, region, envVars,
      });
    } else {
      pipelineRun = await triggerAzureDevOpsPipeline({
        agentId:      agent.id,
        project:      agent.azureDevOpsProject || agent.id,
        deploymentId, target, region, envVars,
      });
    }

    // Save pipeline info to deployment record
    store.updateDeployment(deploymentId, {
      resource_ids: JSON.stringify(pipelineRun),
      status: "deploying",
    });

    ws.send(JSON.stringify({
      type:       "deploy_step_done",
      deploymentId,
      stepId:     "cicd_trigger",
      progress:   15,
      pipelineUrl: pipelineRun.runUrl,
      message:    `Pipeline triggered. Run: ${pipelineRun.runId}`,
    }));

    // Poll for pipeline completion (fallback if webhook not received)
    await pollPipelineCompletion({ ws, deploymentId, agent, pipelineRun, cicdProvider });

  } catch (err) {
    store.addLog(deploymentId, `Pipeline trigger failed: ${err.message}`, "error");
    ws.send(JSON.stringify({
      type:  "agent_error",
      deploymentId,
      message: err.message,
    }));
    throw err;
  }
}

/**
 * Poll pipeline status every 5 seconds until complete
 * This runs as a fallback — if webhook fires first, polling stops
 */
async function pollPipelineCompletion({ ws, deploymentId, agent, pipelineRun, cicdProvider }) {
  const maxWait    = 20 * 60 * 1000; // 20 minutes max
  const pollInterval = 5000;
  const startTime  = Date.now();
  let   lastProgress = 15;

  store.addLog(deploymentId, "Polling pipeline status every 5 seconds...");

  while (Date.now() - startTime < maxWait) {
    // Check if webhook already updated the status
    const dep = store.getDeployment(deploymentId);
    if (dep?.status === "running" || dep?.status === "failed") {
      store.addLog(deploymentId, "Webhook received — pipeline complete");
      return;
    }

    await sleep(pollInterval);

    try {
      let status;
      if (cicdProvider === "github") {
        status = await getGitHubRunStatus({ agentId: agent.id, runId: pipelineRun.runId });
      } else {
        status = await getAzureDevOpsRunStatus({
          agentId:    agent.id,
          pipelineId: pipelineRun.pipelineId,
          runId:      pipelineRun.runId,
        });
      }

      // Progress increases while waiting
      lastProgress = Math.min(lastProgress + 5, 90);

      const stepLabel = getPipelineStepLabel(status.state, cicdProvider);
      ws.send(JSON.stringify({
        type:        "deploy_step",
        deploymentId,
        stepId:      `poll_${Date.now()}`,
        label:       stepLabel,
        progress:    lastProgress,
        pipelineUrl: pipelineRun.runUrl,
      }));

      store.addLog(deploymentId, `Pipeline ${status.state}: ${stepLabel}`);

      if (status.done) {
        if (status.success) {
          store.updateDeployment(deploymentId, { status: "running" });
          ws.send(JSON.stringify({ type: "deploy_complete", deploymentId, status: "running" }));
        } else {
          store.updateDeployment(deploymentId, { status: "failed", error: `Pipeline ${status.result}` });
          ws.send(JSON.stringify({ type: "deploy_failed", deploymentId, message: `Pipeline ${status.result}` }));
        }
        return;
      }
    } catch (e) {
      store.addLog(deploymentId, `Poll error: ${e.message}`, "warn");
    }
  }

  store.addLog(deploymentId, "Pipeline timed out after 20 minutes", "error");
  ws.send(JSON.stringify({ type: "deploy_failed", deploymentId, message: "Deployment timed out" }));
}

function getPipelineStepLabel(state, provider) {
  const labels = {
    azuredevops: { inProgress: "Pipeline running...", completed: "Pipeline complete" },
    github:      { queued: "Pipeline queued", in_progress: "Pipeline running...", completed: "Pipeline complete" },
  };
  return labels[provider]?.[state] || `Pipeline: ${state}`;
}

// ─── WEBHOOK HANDLER ──────────────────────────────────────────────────────────

/**
 * Handles incoming webhooks from Azure DevOps or GitHub when pipeline completes.
 * Register this route: app.post('/api/webhooks/cicd', handleCiCdWebhook)
 */
async function handleCiCdWebhook(req, res, wsClients) {
  const body     = req.body;
  const provider = detectProvider(req.headers);

  res.json({ ok: true }); // always respond quickly

  try {
    let deploymentId, success, url, agentId;

    if (provider === "azuredevops") {
      // Azure DevOps sends: eventType, resource.state, resource.result
      if (body.eventType !== "ms.vss-pipelines.run-state-changed-event") return;
      const vars   = body.resource?.variables || {};
      deploymentId = vars.DEPLOYMENT_ID?.value;
      success      = body.resource?.result === "succeeded";
      url          = body.resource?._links?.web?.href;

    } else if (provider === "github") {
      // GitHub sends: action: "completed", workflow_run.conclusion
      if (body.action !== "completed") return;
      deploymentId = body.workflow_run?.inputs?.deployment_id;
      success      = body.workflow_run?.conclusion === "success";
      url          = body.workflow_run?.url;
    }

    if (!deploymentId) return;

    if (success) {
      store.updateDeployment(deploymentId, { status: "running", url: url || "" });
      store.addLog(deploymentId, `Webhook: deployment successful. Agent live at ${url}`);

      // Notify all WebSocket clients watching this deployment
      broadcastToWs(wsClients, { type: "deploy_complete", deploymentId, url, status: "running" });
    } else {
      store.updateDeployment(deploymentId, { status: "failed" });
      store.addLog(deploymentId, "Webhook: deployment failed");
      broadcastToWs(wsClients, { type: "deploy_failed", deploymentId, message: "Pipeline failed" });
    }
  } catch (e) {
    console.error("[WEBHOOK] Error:", e.message);
  }
}

function detectProvider(headers) {
  if (headers["x-vss-activityid"] || headers["x-tfs-eventtype"]) return "azuredevops";
  if (headers["x-github-event"]) return "github";
  return "unknown";
}

function broadcastToWs(wsClients, message) {
  const data = JSON.stringify(message);
  wsClients?.forEach(ws => { try { ws.send(data); } catch {} });
}

// ─── HTTP HELPERS ─────────────────────────────────────────────────────────────
async function azureDevOpsGet(url, authHeader) {
  const res = await fetch(url, { headers: { Authorization: authHeader, Accept: "application/json" } });
  if (!res.ok) throw new Error(`Azure DevOps API error ${res.status}: ${await res.text()}`);
  return res.json();
}

async function azureDevOpsPost(url, authHeader, body) {
  const res = await fetch(url, {
    method:  "POST",
    headers: { Authorization: authHeader, "Content-Type": "application/json", Accept: "application/json" },
    body:    JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Azure DevOps API error ${res.status}: ${await res.text()}`);
  return res.json();
}

async function githubGet(url) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
  });
  if (!res.ok) throw new Error(`GitHub API error ${res.status}: ${await res.text()}`);
  return res.json();
}

async function githubPost(url, body) {
  const res = await fetch(url, {
    method:  "POST",
    headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28" },
    body:    JSON.stringify(body),
  });
  if (!res.ok && res.status !== 204) throw new Error(`GitHub API error ${res.status}: ${await res.text()}`);
  return res.status === 204 ? {} : res.json();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

module.exports = { triggerCiCd, handleCiCdWebhook };
