# Overview

This Action mimics a compromised third-party GitHub Action in the same job as an OIDC deploy.

It:

1. Scans job environment variables for IAM role ARNs.
2. Obtains a GitHub OIDC token when the job has `id-token: write`.
3. Calls `AssumeRoleWithWebIdentity` for each discovered role ARN.
4. Reuses AWS credentials that `configure-aws-credentials` already placed in the environment.

The Action only calls `aws sts get-caller-identity`. It does not print tokens or secret keys. It does not call other AWS APIs.

Use this only in an AWS account and GitHub repository that you control.

## Result

| Log line | Meaning |
|---|---|
| `THREAT ACTIVE` and OIDC assume | A third-party Action obtained an OIDC token and assumed at least one role ARN found in the job environment. |
| `THREAT ACTIVE` and credential reuse | A later Action in the same job can reuse temporary AWS credentials. |
| `PARTIAL` | The Action can obtain the OIDC token. Assume failed, or no role ARN was found. |
| `NOT CONFIRMED` | This job did not expose an OIDC token or AWS credentials to the Action. |

## How to run

1. Copy `example-workflow.yml` to `.github/workflows/`.
2. Replace the role ARN in path B if you use that job.
3. Run the workflow with `workflow_dispatch`.
4. Read the job log. Then delete the workflow.

STS uses `AWS_REGION` or `AWS_DEFAULT_REGION` from the job. If neither is set, it uses `us-east-1`.

## Inputs

| Input | Required | Default | Purpose |
|---|---|---|---|
| `role-to-assume` | No | empty | Extra role ARN to include in the scan |
