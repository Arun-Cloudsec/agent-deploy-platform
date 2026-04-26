# AgentOS — AWS region setup

One-time setup to enable an AWS region as a deploy target. Repeat for each
region you want to enable (recommended: `me-central-1` for UAE residency,
`me-south-1` for Bahrain).

Total time: **~30 minutes** the first time, **~5 minutes** for each
additional region.

## What you'll have at the end

- A VPC with public/private subnets in 2 AZs
- An ECR repository for agent images
- IAM roles (one for GitHub Actions to deploy, one for App Runner to pull
  ECR + read Secrets Manager + write CloudWatch logs)
- A GitHub OIDC trust provider (one per AWS account, idempotent)
- RDS Postgres (db.t4g.micro) and ElastiCache Redis (cache.t4g.micro)
  for tenant data and caching
- The marketplace shows AWS regions as fully deployable

## Prerequisites

- An AWS account with admin access for the bootstrap (one-time)
- AWS CLI installed and configured (`aws configure` with admin creds)
- The agent repos exist on GitHub already (e.g. `Arun-Cloudsec/rfp-agent`)

## Step 1 — Deploy the foundation in your first AWS region

```bash
# Pick a region: me-central-1 (UAE) or me-south-1 (Bahrain) recommended
export AWS_REGION=me-central-1
export DB_PASSWORD="$(openssl rand -base64 24)"

# Deploy the CloudFormation stack
aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name agentos-foundation \
  --template-file aws-foundation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOrg=Arun-Cloudsec \
    GitHubRepo=agent-deploy-platform \
    AllowedBranches=main \
    DBMasterPassword="$DB_PASSWORD" \
    EnableRDS=true

# Save the password somewhere — you'll need it to connect to Postgres
echo "DB password: $DB_PASSWORD"
```

This takes ~10 minutes (RDS provisioning is the slow part).

## Step 2 — Read the stack outputs

```bash
aws cloudformation describe-stacks \
  --region "$AWS_REGION" \
  --stack-name agentos-foundation \
  --query 'Stacks[0].Outputs' \
  --output table
```

You'll see ARNs you need in the next step:

- `GitHubDeployerRoleArn` — used by GitHub Actions
- `AppRunnerAccessRoleArn` — App Runner uses this to pull from ECR
- `AppRunnerInstanceRoleArn` — runtime role for App Runner instances
- `PostgresEndpoint`, `RedisEndpoint` — for tenant config

## Step 3 — Configure GitHub repo variables

In **each agent repo** (e.g. `Arun-Cloudsec/rfp-agent`) → Settings → Secrets
and variables → Actions → Variables tab → New repository variable:

| Variable | Value |
|---|---|
| `AWS_DEPLOYER_ROLE_ARN` | the `GitHubDeployerRoleArn` from above |
| `AWS_APPRUNNER_ROLE_ARN` | the `AppRunnerInstanceRoleArn` from above |

No AWS access keys needed anywhere — the workflow uses OIDC to assume the
deployer role at deploy time.

## Step 4 — Configure AgentOS env

In the AgentOS Container App, set:

```bash
az containerapp update \
  --name agent-deploy-platform \
  --resource-group ai-platform-rg \
  --set-env-vars AWS_ACCOUNT_ID=123456789012
```

(Replace `123456789012` with your AWS account ID. AgentOS uses this when
building the predicted ECR registry URL for display.)

## Step 5 — Enable additional AWS regions

To add `me-south-1` (Bahrain) after you've done me-central-1:

```bash
export AWS_REGION=me-south-1
aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name agentos-foundation \
  --template-file aws-foundation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOrg=Arun-Cloudsec \
    GitHubRepo=agent-deploy-platform \
    AllowedBranches=main \
    DBMasterPassword="$DB_PASSWORD"
```

The second region reuses the same GitHub OIDC provider (it's a
top-level account resource, not regional). The IAM roles, ECR repo, RDS,
and Redis are per-region.

## Step 6 — Try a deploy

In AgentOS marketplace → RFP Agent → Deploy → pick **AWS → UAE Central** →
Deploy now. You should see the timeline run through with AWS-specific log
lines ("Assuming role AgentOS-GitHub-Deployer via OIDC", "Logging in to
Amazon ECR", etc.) and end at a `*.me-central-1.awsapprunner.com` URL.

## Costs

| Component | Monthly cost (idle) |
|---|---|
| VPC + subnets | $0 |
| ECR storage | $0.10/GB stored |
| RDS db.t4g.micro | ~$15 |
| ElastiCache cache.t4g.micro | ~$13 |
| Secrets Manager | $0.40/secret |
| CloudWatch | ~$5 baseline |
| GitHub OIDC provider | $0 |
| IAM roles | $0 |
| **Foundation total** | **~$35/month** |

Each App Runner service adds **~$5-50/month** depending on traffic. Idle
services scale to zero compute cost (you pay only for the provisioning
overhead, ~$5/month).

## Troubleshooting

**`AccessDenied: User is not authorized to perform: sts:AssumeRoleWithWebIdentity`**

The trust policy on `AgentOS-GitHub-Deployer` doesn't allow your repo.
Check `AllowedBranches` parameter in the stack — make sure it includes the
branch you're deploying from.

**`ResourceNotFoundException: Repository does not exist`**

The first deploy creates the ECR repo automatically (idempotent in the
workflow). If you see this on subsequent deploys, the repo was deleted —
re-run the workflow and it'll recreate it.

**App Runner stuck in `OPERATION_IN_PROGRESS` for a long time**

Initial App Runner service creation takes 3-5 minutes (longer than Container
Apps). The timeline pads to 5 minutes total so this should fit; if it
exceeds, check `aws apprunner describe-service` for the actual status. The
most common cause is the runtime role not having permission to pull from
ECR — verify `AppRunnerAccessRoleArn` is correct.

**RDS endpoint shows `not-deployed`**

You set `EnableRDS=false`. Re-deploy the stack with `EnableRDS=true` to
provision Postgres.

## Tear-down

```bash
aws cloudformation delete-stack \
  --region me-central-1 \
  --stack-name agentos-foundation

# Note: RDS may have deletion protection — disable in console first if so
```
