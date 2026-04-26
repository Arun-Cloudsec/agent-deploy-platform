// src/regions.js
//
// Canonical region registry. Every other module reads from here — never
// hardcode region IDs, env suffixes, or resource group names elsewhere.
//
// CLOUD COVERAGE:
//   azure: UAE North + UK South — full foundation (Container Apps, ACR,
//          Postgres, Redis, Key Vault).
//   aws:   UAE Central (me-central-1) + Bahrain (me-south-1) — foundation
//          deployed via aws-foundation.yaml CloudFormation stack. App Runner
//          is the runtime, ECR the registry, Secrets Manager replaces Key
//          Vault.

export const REGIONS = [
  // ─── AZURE ─────────────────────────────────────────────────────────────────
  {
    id: 'azure-uaenorth',
    cloud: 'azure',
    cloudLabel: 'Azure',
    region: 'uaenorth',
    displayName: 'Azure — UAE North',
    shortName: 'UAE North',
    flag: '🇦🇪',
    description: 'Lower latency for Gulf customers',
    resourceGroup: 'ai-platform-rg',
    containerEnvName: 'aiplatform-env-prod',
    containerEnvId: '/subscriptions/ead28ade-e9f9-4bde-8f35-63c4f4b53992/resourceGroups/ai-platform-rg/providers/Microsoft.App/managedEnvironments/aiplatform-env-prod',
    envSuffix: 'wonderfulwave-cd164572',
    keyVaultUri: 'https://aiplatform-kv-prod.vault.azure.net/',
    keyVaultName: 'aiplatform-kv-prod',
    identityName: 'aiplatform-identity-prod',
    identityId: '/subscriptions/ead28ade-e9f9-4bde-8f35-63c4f4b53992/resourceGroups/ai-platform-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aiplatform-identity-prod',
    acrLoginServer: 'aiplatformacrkrz6di3sepgjo.azurecr.io',
    dataResidency: 'AE',
    compliance: ['general'],
    foundationCostMonthly: 120,
    available: true,
  },
  {
    id: 'azure-uksouth',
    cloud: 'azure',
    cloudLabel: 'Azure',
    region: 'uksouth',
    displayName: 'Azure — UK South',
    shortName: 'UK South',
    flag: '🇬🇧',
    description: 'UK data residency, 30-day backups, GRS storage',
    resourceGroup: 'ai-platform-rg-uksouth',
    containerEnvName: 'aiplatform-env-uksouth',
    containerEnvId: '/subscriptions/ead28ade-e9f9-4bde-8f35-63c4f4b53992/resourceGroups/ai-platform-rg-uksouth/providers/Microsoft.App/managedEnvironments/aiplatform-env-uksouth',
    envSuffix: 'livelycoast-930986ee',
    keyVaultUri: 'https://aiplatform-kv-uksouth.vault.azure.net/',
    keyVaultName: 'aiplatform-kv-uksouth',
    identityName: 'aiplatform-identity-uksouth',
    identityId: '/subscriptions/ead28ade-e9f9-4bde-8f35-63c4f4b53992/resourceGroups/ai-platform-rg-uksouth/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aiplatform-identity-uksouth',
    acrLoginServer: 'aiplatformacrkrz6di3sepgjo.azurecr.io',
    dataResidency: 'UK',
    compliance: ['general', 'uk-residency'],
    foundationCostMonthly: 120,
    available: true,
  },

  // ─── AWS ───────────────────────────────────────────────────────────────────
  // App Runner is the runtime (serverless containers, scales to zero, public
  // HTTPS URL out of the box — closest equivalent to Container Apps). ECR
  // is the registry, Secrets Manager replaces Key Vault.
  //
  // Foundation cost is dramatically lower than Azure (~$35/mo vs ~$120/mo)
  // because RDS db.t4g.micro and ElastiCache cache.t4g.micro are cheaper
  // than their Azure-managed equivalents. Worth highlighting in marketing.
  {
    id: 'aws-me-central-1',
    cloud: 'aws',
    cloudLabel: 'AWS',
    region: 'me-central-1',
    displayName: 'AWS — UAE (me-central-1)',
    shortName: 'UAE Central',
    flag: '🇦🇪',
    description: 'AWS UAE — Dubai infrastructure, full data residency',
    ecrRegistry: '${AWS_ACCOUNT_ID}.dkr.ecr.me-central-1.amazonaws.com',
    secretsManagerArnPrefix: 'arn:aws:secretsmanager:me-central-1:${AWS_ACCOUNT_ID}:secret:',
    appRunnerRoleArn: 'arn:aws:iam::${AWS_ACCOUNT_ID}:role/AgentOS-AppRunner-Role',
    githubDeployRoleArn: 'arn:aws:iam::${AWS_ACCOUNT_ID}:role/AgentOS-GitHub-Deployer',
    dataResidency: 'AE',
    compliance: ['general', 'aws-uae-residency'],
    foundationCostMonthly: 35,
    available: true,
  },
  {
    id: 'aws-me-south-1',
    cloud: 'aws',
    cloudLabel: 'AWS',
    region: 'me-south-1',
    displayName: 'AWS — Bahrain (me-south-1)',
    shortName: 'Bahrain',
    flag: '🇧🇭',
    description: 'AWS Middle East — Bahrain, broader service catalog',
    ecrRegistry: '${AWS_ACCOUNT_ID}.dkr.ecr.me-south-1.amazonaws.com',
    secretsManagerArnPrefix: 'arn:aws:secretsmanager:me-south-1:${AWS_ACCOUNT_ID}:secret:',
    appRunnerRoleArn: 'arn:aws:iam::${AWS_ACCOUNT_ID}:role/AgentOS-AppRunner-Role',
    githubDeployRoleArn: 'arn:aws:iam::${AWS_ACCOUNT_ID}:role/AgentOS-GitHub-Deployer',
    dataResidency: 'BH',
    compliance: ['general', 'aws-bahrain-residency'],
    foundationCostMonthly: 35,
    available: true,
  },

  // ─── GCP — stub, not yet provisioned ───────────────────────────────────────
  {
    id: 'gcp-me-central1',
    cloud: 'gcp',
    cloudLabel: 'GCP',
    region: 'me-central1',
    displayName: 'GCP — Doha',
    shortName: 'GCP me-central1',
    flag: '🇶🇦',
    description: 'Coming soon',
    available: false,
    dataResidency: 'QA',
    foundationCostMonthly: 0,
  },
];

export function regionById(id) {
  return REGIONS.find(r => r.id === id);
}

export function regionsByCloud(cloud) {
  return REGIONS.filter(r => r.cloud === cloud && r.available);
}

export const DEFAULT_REGION_ID = 'azure-uaenorth';

// Construct the public FQDN for a deployed agent in a given region.
//   Azure → <containerAppName>.<envSuffix>.<region>.azurecontainerapps.io
//   AWS   → <8charHash>.<region>.awsapprunner.com  (predicted; real URL
//           is captured by the workflow and posted back to the store)
export function fqdnFor(containerAppName, regionId) {
  const r = regionById(regionId);
  if (!r) return null;
  if (r.cloud === 'azure' && r.envSuffix) {
    return `${containerAppName}.${r.envSuffix}.${r.region}.azurecontainerapps.io`;
  }
  if (r.cloud === 'aws') {
    const suffix = simpleHash(containerAppName).slice(0, 8);
    return `${suffix}.${r.region}.awsapprunner.com`;
  }
  return null;
}

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h) + str.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h).toString(36).padStart(8, '0');
}
