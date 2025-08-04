import yaml
from pathlib import Path
from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_iam as iam,
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_lambda as lambda_,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_logs as logs,
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_integrations as integ,
    CfnOutput,
)
from constructs import Construct
from typing import List, Dict, Any


class StepFuncProjectStack(Stack):
    """
    AWS CDK Stack for a Step Functions project with Lambda functions,
    RDS PostgreSQL database, and API Gateway integration.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Load configuration from variables.yml
        self.config = self._load_config()

        #######################################################
        ############### VARIABLES FROM CONFIG  ################
        #######################################################

        self.PROJECT_NAME = self.config["project"]["name"]
        self.DB_NAME = f"{self.config['database']['name_suffix']}_{self.PROJECT_NAME}"
        self.SECRET_NAME = (
            f"{self.config['database']['secret_name_suffix']}_{self.PROJECT_NAME}"
        )
        self.POSTGRES_PORT = self.config["database"]["port"]
        self.LAMBDA_TIMEOUT_MINUTES = self.config["lambda"]["timeout_minutes"]
        self.STATE_MACHINE_TIMEOUT_MINUTES = self.config["step_functions"][
            "timeout_minutes"
        ]
        self.VPC_ID = self.config["vpc"]["id"]

        # Subnet configuration from config
        self.SUBNET_CONFIG = {}
        for subnet_name, subnet_config in self.config["subnets"].items():
            self.SUBNET_CONFIG[subnet_name] = {
                "subnet_id": subnet_config["subnet_id"],
                "availability_zone": subnet_config["availability_zone"],
                "route_table_id": subnet_config["route_table_id"],
            }

        ###########################################################
        ############### INFRASTRUCTURE COMPONENTS  ################
        ###########################################################
        self.vpc = self._create_vpc()
        self.subnets = self._create_subnets()
        self.security_groups = self._create_security_groups()
        self.database = self._create_database()
        self.iam_role = self._create_iam_role()
        self.lambda_layer = self._create_lambda_layer()
        self.lambda_functions = self._create_lambda_functions()
        self.state_machine = self._create_state_machine()
        self.api_gateway = self._create_api_gateway()

        self._create_outputs()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from variables.yml file."""
        # Go up one directory level to reach the root where variables.yml is located
        current_dir = Path(__file__).parent.parent  # Note the extra .parent
        config_path = current_dir / "variables.yml"

        try:
            with open(config_path, "r") as file:
                config = yaml.safe_load(file)
                return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found at: {config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML configuration: {e}")

    def _create_vpc(self) -> ec2.IVpc:
        """Create or import existing VPC."""
        return ec2.Vpc.from_lookup(
            self,
            f"Existing_Vpc_{self.PROJECT_NAME}",
            vpc_id=self.VPC_ID,
        )

    def _create_subnets(self) -> Dict[str, ec2.ISubnet]:
        """Create subnet references from existing subnets."""
        subnets = {}
        for name, config in self.SUBNET_CONFIG.items():
            subnets[name] = ec2.Subnet.from_subnet_attributes(
                self,
                f"{name.title()}_{self.PROJECT_NAME}",
                subnet_id=config["subnet_id"],
                availability_zone=config["availability_zone"],
                route_table_id=config["route_table_id"],
            )
        return subnets

    def _create_security_groups(self) -> Dict[str, ec2.SecurityGroup]:
        """Create security groups for RDS and Lambda."""
        # RDS Security Group
        rds_sg = ec2.SecurityGroup(
            self,
            f"Rds_SG_{self.PROJECT_NAME}",
            security_group_name=f"Rds_SG_{self.PROJECT_NAME}",
            vpc=self.vpc,
            description="Allow PostgreSQL access",
            allow_all_outbound=True,
        )

        # Lambda Security Group
        lambda_sg = ec2.SecurityGroup(
            self,
            f"lambda_SG_{self.PROJECT_NAME}",
            security_group_name=f"lambda_SG_{self.PROJECT_NAME}",
            vpc=self.vpc,
            description="Outbound to RDS",
            allow_all_outbound=True,
        )

        # Allow Lambda to connect to RDS
        rds_sg.add_ingress_rule(
            peer=lambda_sg,
            connection=ec2.Port.tcp(self.POSTGRES_PORT),
            description="Allow Lambda functions to reach Postgres",
        )

        return {"rds": rds_sg, "lambda": lambda_sg}

    def _create_database(self) -> rds.DatabaseInstance:
        """Create RDS PostgreSQL instance."""
        return rds.DatabaseInstance(
            self,
            f"rds_postgres_{self.PROJECT_NAME}",
            database_name=self.DB_NAME,
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_17_5
            ),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=list(self.subnets.values())),
            security_groups=[self.security_groups["rds"]],
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE4_GRAVITON, ec2.InstanceSize.MICRO
            ),
            allocated_storage=20,
            max_allocated_storage=30,
            multi_az=False,
            publicly_accessible=False,
            credentials=rds.Credentials.from_generated_secret(
                "postgres", secret_name=self.SECRET_NAME
            ),
            deletion_protection=False,
            iam_authentication=True,
            # storage_encrypted=True,  # Enable encryption for security
        )

    def _create_iam_role(self) -> iam.Role:
        """Create IAM role for Lambda functions."""
        return iam.Role(
            self,
            f"lambda_role_{self.PROJECT_NAME}",
            role_name=f"lambda_role_{self.PROJECT_NAME}",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "CloudWatchFullAccessV2"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "SecretsManagerReadWrite"
                ),
            ],
        )

    def _create_lambda_layer(self) -> lambda_.LayerVersion:
        """Create Lambda layer for shared dependencies."""
        return lambda_.LayerVersion(
            self,
            f"layer_{self.PROJECT_NAME}",
            code=lambda_.Code.from_asset("layer"),
            description="Common helper utility",
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_13],
            removal_policy=RemovalPolicy.DESTROY,
        )

    def _get_lambda_configs(self) -> List[Dict[str, str]]:
        """Get Lambda function configurations."""
        return [
            {
                "id": f"LambdaFunction_1_{self.PROJECT_NAME}",
                "description": "1st Lambda in the step functions to fetch Pagerduty data and create basic db schema with few columns data population.",
                "name": f"LambdaFunction_1_{self.PROJECT_NAME}",
                "asset": "lambdas/lambda_1",
            },
            {
                "id": f"LambdaFunction_2_{self.PROJECT_NAME}",
                "description": "2nd Lambda in the step functions to fetch Pagerduty complete incident data and populate everything in the database.",
                "name": f"LambdaFunction_2_{self.PROJECT_NAME}",
                "asset": "lambdas/lambda_2",
            },
            {
                "id": f"LambdaFunction_3_{self.PROJECT_NAME}",
                "description": "3rd Lambda in the step functions to validate data from the database.",
                "name": f"LambdaFunction_3_{self.PROJECT_NAME}",
                "asset": "lambdas/lambda_3",
            },
            {
                "id": f"LambdaErrorHandler_{self.PROJECT_NAME}",
                "description": "Lambda function to handle errors in the step functions",
                "name": f"LambdaErrorHandler_{self.PROJECT_NAME}",
                "asset": "lambdas/lambda_error_handler",
            },
        ]

    def _create_lambda_functions(self) -> List[lambda_.Function]:
        """Create Lambda functions."""
        lambda_functions = []

        for config in self._get_lambda_configs():
            function = lambda_.Function(
                self,
                config["id"],
                function_name=config["name"],
                runtime=lambda_.Runtime.PYTHON_3_13,
                code=lambda_.Code.from_asset(config["asset"]),
                handler="index.lambda_handler",
                role=self.iam_role,
                layers=[self.lambda_layer],
                vpc=self.vpc,
                security_groups=[self.security_groups["lambda"]],
                log_retention=logs.RetentionDays.TWO_YEARS,
                timeout=Duration.minutes(self.LAMBDA_TIMEOUT_MINUTES),
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                environment={
                    "DB_SECRET_ARN": self.database.secret.secret_arn,
                    "DB_NAME": self.DB_NAME,
                },
                description=config["description"],
            )
            lambda_functions.append(function)

        # Grant database access to Lambda functions (excluding error handler)
        for function in lambda_functions[:3]:  # First 3 functions need DB access
            self.database.secret.grant_read(function)

        return lambda_functions

    def _create_retry_config(self) -> Dict[str, Any]:
        """Create common retry configuration for Step Functions tasks."""
        return {
            "interval": Duration.seconds(1),
            "max_attempts": 3,
            "backoff_rate": 2.0,
            "errors": [
                "Lambda.ServiceException",
                "Lambda.AWSLambdaException",
                "Lambda.SdkClientException",
                "Lambda.TooManyRequestsException",
            ],
            "jitter_strategy": sfn.JitterType.FULL,
        }

    def _create_lambda_invoke_task(
        self, name: str, function: lambda_.Function
    ) -> tasks.LambdaInvoke:
        """Create a Lambda invoke task with retry configuration."""
        return tasks.LambdaInvoke(
            self,
            f"Lambda_Invoke_{name}_{self.PROJECT_NAME}",
            lambda_function=function,
            payload=sfn.TaskInput.from_json_path_at("$"),
            output_path="$.Payload",
        ).add_retry(**self._create_retry_config())

    def _create_state_machine(self) -> sfn.StateMachine:
        """Create Step Functions state machine."""
        (
            lambda_function_1,
            lambda_function_2,
            lambda_function_3,
            lambda_error_handler,
        ) = self.lambda_functions

        # Create Lambda invoke tasks
        invoke_1 = self._create_lambda_invoke_task("1", lambda_function_1)
        invoke_2 = self._create_lambda_invoke_task("2", lambda_function_2)
        invoke_3 = self._create_lambda_invoke_task("3", lambda_function_3)

        # Error handling
        fail_state = sfn.Fail(self, "Fail")

        error_handler_task = tasks.LambdaInvoke(
            self,
            f"Lambda_error_handler_invoke_{self.PROJECT_NAME}",
            lambda_function=lambda_error_handler,
            payload=sfn.TaskInput.from_object(
                {
                    "failedStep.$": "$$.State.Name",
                    "executionId.$": "$$.Execution.Id",
                    "executionName.$": "$$.Execution.Name",
                    "startTime.$": "$$.Execution.StartTime",
                    "payload.$": "$",
                }
            ),
            output_path="$.Payload",
        ).add_retry(**self._create_retry_config())

        error_branch = sfn.Chain.start(error_handler_task).next(fail_state)

        # Create choice states
        choice_3 = (
            sfn.Choice(self, f"Choice_3_{self.PROJECT_NAME}")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(sfn.Succeed(self, "Success"))
        )

        choice_2 = (
            sfn.Choice(self, f"Choice_2_{self.PROJECT_NAME}")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(invoke_3.next(choice_3))
        )

        choice_1 = (
            sfn.Choice(self, f"Choice_1_{self.PROJECT_NAME}")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(invoke_2.next(choice_2))
        )

        # Create state machine
        definition = invoke_1.next(choice_1)

        state_machine = sfn.StateMachine(
            self,
            f"StateMachine_{self.PROJECT_NAME}",
            state_machine_name=f"StateMachine_{self.PROJECT_NAME}",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.minutes(self.STATE_MACHINE_TIMEOUT_MINUTES),
        )

        # Grant invoke permissions to Lambda functions
        for function in self.lambda_functions:
            function.grant_invoke(state_machine.role)

        return state_machine

    def _create_api_gateway(self) -> apigwv2.HttpApi:
        """Create API Gateway HTTP API."""
        # Create HTTP API
        http_api = apigwv2.HttpApi(
            self,
            f"HttpApi_{self.PROJECT_NAME}",
            api_name=f"HttpApi_{self.PROJECT_NAME}",
        )

        # Create API Gateway role
        api_gw_role = iam.Role(
            self,
            f"HttpApi_Role_{self.PROJECT_NAME}",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            role_name=f"HTTPApi_Role_{self.PROJECT_NAME}",
        )

        self.state_machine.grant_start_execution(api_gw_role)

        # Create Step Functions integration
        start_exec_integration = integ.HttpStepFunctionsIntegration(
            f"Start_SF_Integration_{self.PROJECT_NAME}",
            state_machine=self.state_machine,
            parameter_mapping=apigwv2.ParameterMapping()
            .custom("Input", "$request.body")
            .custom("StateMachineArn", self.state_machine.state_machine_arn),
        )

        # Add route
        http_api.add_routes(
            path="/invoke",
            methods=[apigwv2.HttpMethod.POST],
            integration=start_exec_integration,
        )

        return http_api

    def _create_outputs(self) -> None:
        """Create CloudFormation outputs."""
        CfnOutput(
            self,
            f"HttpApiEndpoint_{self.PROJECT_NAME}",
            value=self.api_gateway.api_endpoint,
            description="HTTP API endpoint for Step Functions project",
            export_name=f"HttpApiEndpoint-{self.PROJECT_NAME}",
        )

        CfnOutput(
            self,
            f"DatabaseEndpoint_{self.PROJECT_NAME}",
            value=self.database.db_instance_endpoint_address,
            description="RDS PostgreSQL endpoint",
            export_name=f"DatabaseEndpoint-{self.PROJECT_NAME}",
        )

        CfnOutput(
            self,
            f"StateMachineArn_{self.PROJECT_NAME}",
            value=self.state_machine.state_machine_arn,
            description="Step Functions State Machine ARN",
            export_name=f"StateMachineArn-{self.PROJECT_NAME}",
        )
