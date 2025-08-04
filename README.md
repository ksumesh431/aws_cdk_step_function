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

## Configuration Management

This project uses a centralized configuration approach with `variables.yml` for environment-specific settings. All infrastructure parameters, AWS account details, and deployment settings are externalized from the code.

### Configuration File Structure

Create a `variables.yml` file in the project root with the following structure:

```yaml
# Project Configuration
project:
  name: "stepfuncproject"
  
# AWS Environment Configuration
aws:
  account_id: "YOUR_ACCOUNT_ID"
  region: "YOUR_REGION"

# Tags Configuration
tags:
  created_by: "cdk"
  project: "step-function-project"  
  app_manager_cfn_stack_key: "step-function-project"  # for aws cost explorer
  
# Database Configuration
database:
  name_suffix: "postgres_db"
  secret_name_suffix: "rds_postgres_creds"
  port: 5432

# Lambda Configuration
lambda:
  timeout_minutes: 10

# Step Functions Configuration
step_functions:
  timeout_minutes: 45

# VPC Configuration
vpc:
  id: "vpc-YOUR_VPC_ID"

# Subnet Configuration
subnets:
  private_subnet_1:
    subnet_id: "subnet-YOUR_SUBNET_ID_1"
    availability_zone: "YOUR_AZ_1"
    route_table_id: "rtb-YOUR_ROUTE_TABLE_ID"
  private_subnet_2:
    subnet_id: "subnet-YOUR_SUBNET_ID_2"
    availability_zone: "YOUR_AZ_2"
    route_table_id: "rtb-YOUR_ROUTE_TABLE_ID"