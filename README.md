# Step Functions Project (AWS CDK, Python)

A production-ready AWS CDK stack that provisions a serverless workflow to fetch, process, and validate PagerDuty incident data using AWS Step Functions orchestrating Lambda functions, with persistence in an RDS PostgreSQL database. The workflow is triggered via an API Gateway HTTP API endpoint and includes robust error handling.

## Architecture Overview

- API Gateway HTTP API exposes a POST endpoint to start executions.
- AWS Step Functions runs a three-step workflow:
  1. Fetch initial data and create base DB schema.
  2. Fetch complete incident data and populate DB.
  3. Validate data in the DB.
- A dedicated error-handler Lambda captures failures and marks the execution as failed.
- RDS PostgreSQL runs inside an existing VPC and private subnets.
- Lambdas run in private subnets with a security group allowing DB access.
- Secrets Manager stores DB credentials; Lambdas read the secret at runtime.


## Prerequisites

- AWS account with permission to deploy CDK stacks (CloudFormation, IAM, RDS, Lambda, API Gateway, Step Functions, Secrets Manager, CloudWatch).
- Node.js (for CDK CLI) and Python 3.13 (project uses Python 3.13 runtime).
- AWS CDK v2 installed:
  - npm install -g aws-cdk
- Python tooling:
  - pip install -r requirements.txt (ensure aws-cdk-lib and constructs)

Ensure the specified VPC and subnet IDs exist and are correct:
- VPC: `vpc-0e01c3c7ae69fd92b`
- Private subnets:
  - `subnet-0e2842b86fa358d19` (eu-west-2c)
  - `subnet-0ff5a9d643e0b97c8` (eu-west-2b)
- Route table IDs as configured in the code.

Lambdas need internet access (e.g., to reach PagerDuty APIs), ensure these private subnets have a NAT gateway route for egress.

## Project Structure

- cdk stack: StepFuncProjectStack
- lambdas/
  - lambda_1/ (initial fetch + base schema)
  - lambda_2/ (complete data fetch + populate)
  - lambda_3/ (validate)
  - lambda_error_handler/ (handle workflow failures)
- layer/ (shared Python layer dependencies)

## Key Configuration

- Project name: `stepfuncproject`
- Database:
  - Engine: PostgreSQL 17.5
  - Instance type: t4g.micro
  - Storage: 20 GB (max 30 GB)
  - Private, non-publicly accessible
  - Credentials: Generated and stored in Secrets Manager
  - IAM authentication: Enabled
- Lambda:
  - Runtime: Python 3.13
  - Timeout: 10 minutes
  - VPC-attached, private with egress
  - Env vars:
    - DB_SECRET_ARN: ARN of Secrets Manager secret
    - DB_NAME: `postgres_db_stepfuncproject`
- Step Functions:
  - Timeout: 45 minutes
  - Retry config on LambdaInvoke: 3 attempts, 1s base, backoff 2.0, full jitter
  - Control flow depends on each Lambda returning a JSON with `success: true|false`
- API Gateway HTTP API:
  - Route: POST `/invoke`
  - Integration: Starts Step Functions execution
  - Input mapping: Request body becomes state input

## Security Notes

- Current IAM role for Lambda uses broad managed policies (AmazonRDSFullAccess, SecretsManagerReadWrite, CloudWatchFullAccessV2). For production, replace with scoped, least-privilege inline policies.
- RDS storage encryption is commented out; enable if required by your compliance.
- API route is unauthenticated by default; add an authorizer (JWT, IAM, or Lambda) before exposing publicly.


## Invocation

After deployment, note the CloudFormation outputs:
- HttpApiEndpoint-stepfuncproject
- DatabaseEndpoint-stepfuncproject
- StateMachineArn-stepfuncproject

Trigger the workflow:
- curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"some":"input"}' \
  https://{api-id}.execute-api.{region}.amazonaws.com/invoke

The JSON payload is passed to Lambda 1 as input. Each Lambda should return an object with at least:
- { "success": true, ... }

If any Lambda returns `success: false` (or omits it), the error-handler Lambda is invoked, and the state machine fails.


## Troubleshooting

- Lambdas cannot reach the internet: Ensure private subnets have NAT and correct route tables.
- Cannot connect to DB: Verify security group rule (lambda_sg -> rds_sg on 5432), subnet routing, and that Lambdas use the correct VPC/subnets.
- Secrets access denied: Ensure the specific Lambda has read permissions to the Secrets Manager secret.
- State machine not starting: Confirm API Gateway role has StartExecution permission and integration mapping is correct.
