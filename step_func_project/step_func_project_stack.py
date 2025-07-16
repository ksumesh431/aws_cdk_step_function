from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_iam as iam,
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_apigateway as apigateway,
    aws_lambda as lambda_,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_logs as logs,
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_integrations as integ,
)
from constructs import Construct
from aws_cdk import CfnOutput


class StepFuncProjectStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        #################################################
        # Networking (VPC & Security Groups)
        #################################################
        # Create a VPC for the RDS instance
        # vpc = ec2.Vpc(self, "StepFuncProjectVpc", max_azs=2)

        # Use existing vpc
        vpc = ec2.Vpc.from_lookup(
            self,
            "Existing_Vpc_stepfuncproject",
            vpc_id="vpc-0e01c3c7ae69fd92b",
        )

        # import the two subnets by ID (atleast two subnets in different zones is required for RDS)
        priv_subnet_1 = ec2.Subnet.from_subnet_attributes(
            self,
            "PrivSubnet1",
            subnet_id="subnet-0e2842b86fa358d19",
            availability_zone="eu-west-2c",  # required param
            route_table_id="rtb-091951509bec3c07f",
        )

        priv_subnet_2 = ec2.Subnet.from_subnet_attributes(
            self,
            "PrivSubnet2",
            subnet_id="subnet-0ff5a9d643e0b97c8",
            availability_zone="eu-west-2b",  # required param
            route_table_id="rtb-091951509bec3c07f",
        )

        # Create a security group for the RDS instance
        rds_sg = ec2.SecurityGroup(
            self,
            "Rds_SG_stepfuncproject",
            security_group_name="Rds_SG_stepfuncproject",
            vpc=vpc,
            description="Allow PostgreSQL access",
            allow_all_outbound=True,
        )

        # Security Group for Lambda Functions
        lambda_sg = ec2.SecurityGroup(
            self,
            "lambda_SG_stepfuncproject",
            security_group_name="lambda_SG_stepfuncproject",
            vpc=vpc,  # the existing VPC you imported
            description="Outbound to RDS",
            allow_all_outbound=True,
        )

        rds_sg.add_ingress_rule(
            peer=lambda_sg,
            connection=ec2.Port.tcp(5432),
            description="Allow Lambda functions to reach Postgres",
        )

        #################################################
        # Database (Amazon RDS for PostgreSQL)
        #################################################
        db_instance = rds.DatabaseInstance(
            self,
            "rds_postgres_stepfuncproject",
            database_name="postgres_db_stepfuncproject",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_17_5
            ),
            vpc=vpc,
            # vpc_subnets=ec2.SubnetSelection(
            #     subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            # ),
            vpc_subnets=ec2.SubnetSelection(subnets=[priv_subnet_1, priv_subnet_2]),
            security_groups=[rds_sg],
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE4_GRAVITON, ec2.InstanceSize.MICRO
            ),
            allocated_storage=20,
            max_allocated_storage=30,
            multi_az=False,
            publicly_accessible=False,
            credentials=rds.Credentials.from_generated_secret(
                "postgres", secret_name="rds_postgres_creds_stepfuncproject"
            ),
            deletion_protection=False,
            iam_authentication=True,
            # storage_encrypted=True, # Optional, but recommended
        )

        #################################################
        # IAM Roles & Permissions
        #################################################
        role = iam.Role(
            self,
            "lambda_role_stepfuncproject",
            role_name="lambda_role_stepfuncproject",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                # ➊ VPC-ENI permissions
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                # ➋ Basic logs (CreateLogGroup/Stream + PutLogEvents)
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                # ➌ DB permissions
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess"),
                # ➍ Step Functions permissions
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaRole"
                ),
                # ➎ Cloudwatch permissions
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "CloudWatchFullAccessV2"
                ),
                # ➏ Secrets Manager full access
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "SecretsManagerReadWrite"
                ),
            ],
        )

        #################################################
        # Lambda Layer
        #################################################
        layer = lambda_.LayerVersion(
            self,
            "layer_stepfuncproject",
            code=lambda_.Code.from_asset("layer"),
            description="Common helper utility",
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_13],
            removal_policy=RemovalPolicy.DESTROY,
        )

        #################################################
        # Lambda Functions
        #################################################
        lambda_configs = [
            {
                "id": "LambdaFunction_1_stepfuncproject",
                "desc": "1st Lambda in the step functions to fetch Pagerduty data and create absic db schema with few columns data population.",
                "name": "LambdaFunction_1_stepfuncproject",
                "asset": "lambdas/lambda_1",
            },
            {
                "id": "LambdaFunction_2_stepfuncproject",
                "desc": "2nd Lambda in the step functions to fetch Pagerduty complete indident data and populate everything in the database.",
                "name": "LambdaFunction_2_stepfuncproject",
                "asset": "lambdas/lambda_2",
            },
            {
                "id": "LambdaFunction_3_stepfuncproject",
                "desc": "3rd Lambda in the step functions to validate data from the database.",
                "name": "LambdaFunction_3_stepfuncproject",
                "asset": "lambdas/lambda_3",
            },
            {
                "id": "LambdaErrorHandler_stepfuncproject",
                "desc": "Lambda function to handle errors in the step functions",
                "name": "LambdaErrorHandler_stepfuncproject",
                "asset": "lambdas/lambda_error_handler",
            },
        ]

        lambda_functions = []
        for cfg in lambda_configs:
            kwargs = (
                {
                    "description": cfg["desc"],
                }
                if cfg["desc"]
                else {}
            )
            fn = lambda_.Function(
                self,
                cfg["id"],
                function_name=cfg["name"],
                runtime=lambda_.Runtime.PYTHON_3_13,
                code=lambda_.Code.from_asset(cfg["asset"]),
                handler="index.lambda_handler",
                role=role,
                layers=[layer],
                vpc=vpc,
                security_groups=[lambda_sg],
                log_retention=logs.RetentionDays.TWO_YEARS,
                timeout=Duration.minutes(10),
                vpc_subnets=ec2.SubnetSelection(  # must keep in subnet with nat gateway egress
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                environment={
                    "DB_SECRET_ARN": db_instance.secret.secret_arn,
                    "DB_NAME": "postgres_db_stepfuncproject",
                },
                **kwargs,
            )
            lambda_functions.append(fn)

        (
            lambda_function_1,
            lambda_function_2,
            lambda_function_3,
            lambda_error_handler,
        ) = lambda_functions

        # Allow Lambdas to connect to the database
        for fn in [lambda_function_1, lambda_function_2, lambda_function_3]:
            # db_instance.grant_connect(fn) # iam auth
            # This allows the Lambda functions to read the database credentials
            db_instance.secret.grant_read(fn)

        #################################################
        # Step Functions State Machine
        #################################################

        # 1️⃣ Lambda-invoke tasks ---------------------------------------------------
        invoke_1 = tasks.LambdaInvoke(
            self,
            "Lambda_Invoke_1_stepfuncproject",
            lambda_function=lambda_function_1,
            payload=sfn.TaskInput.from_json_path_at("$"),
            output_path="$.Payload",
        ).add_retry(
            interval=Duration.seconds(1),
            max_attempts=3,
            backoff_rate=2.0,
            errors=[
                "Lambda.ServiceException",
                "Lambda.AWSLambdaException",
                "Lambda.SdkClientException",
                "Lambda.TooManyRequestsException",
            ],
            jitter_strategy=sfn.JitterType.FULL,
        )

        invoke_2 = tasks.LambdaInvoke(
            self,
            "Lambda_Invoke_2_stepfuncproject",
            lambda_function=lambda_function_2,
            payload=sfn.TaskInput.from_json_path_at("$"),
            output_path="$.Payload",
        ).add_retry(
            interval=Duration.seconds(1),
            max_attempts=3,
            backoff_rate=2.0,
            errors=[
                "Lambda.ServiceException",
                "Lambda.AWSLambdaException",
                "Lambda.SdkClientException",
                "Lambda.TooManyRequestsException",
            ],
            jitter_strategy=sfn.JitterType.FULL,
        )

        invoke_3 = tasks.LambdaInvoke(
            self,
            "Lambda_Invoke_3_stepfuncproject",
            lambda_function=lambda_function_3,
            payload=sfn.TaskInput.from_json_path_at("$"),
            output_path="$.Payload",
        ).add_retry(
            interval=Duration.seconds(1),
            max_attempts=3,
            backoff_rate=2.0,
            errors=[
                "Lambda.ServiceException",
                "Lambda.AWSLambdaException",
                "Lambda.SdkClientException",
                "Lambda.TooManyRequestsException",
            ],
            jitter_strategy=sfn.JitterType.FULL,
        )

        # 2️⃣  Shared error branch ---------------------------------------------------
        fail_state = sfn.Fail(self, "Fail")

        error_handler_task = tasks.LambdaInvoke(
            self,
            "Lambda_error_handler_invoke_stepfuncproject",
            lambda_function=lambda_error_handler,
            #  ⬇️  Pass extra context so the Slack msg can say what blew up
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
        ).add_retry(
            interval=Duration.seconds(1),
            max_attempts=3,
            backoff_rate=2.0,
            errors=[
                "Lambda.ServiceException",
                "Lambda.AWSLambdaException",
                "Lambda.SdkClientException",
                "Lambda.TooManyRequestsException",
            ],
            jitter_strategy=sfn.JitterType.FULL,
        )

        # Chain makes it easier to reference from the Choice states
        error_branch: sfn.IChainable = sfn.Chain.start(error_handler_task).next(
            fail_state
        )

        # 3️⃣ Choice states ----------------------------------------------------------
        choice_3 = (
            sfn.Choice(self, "Choice_3_stepfuncproject")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(sfn.Succeed(self, "Success"))
        )

        choice_2 = (
            sfn.Choice(self, "Choice_2_stepfuncproject")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(invoke_3.next(choice_3))
        )

        choice_1 = (
            sfn.Choice(self, "Choice_1_stepfuncproject")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(invoke_2.next(choice_2))
        )

        # 4️⃣ Glue everything together ----------------------------------------------
        definition = invoke_1.next(choice_1)

        state_machine = sfn.StateMachine(
            self,
            "StateMachine_stepfuncproject",
            state_machine_name="StateMachine_stepfuncproject",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.minutes(45),
        )

        # Allow Step Functions to call Lambdas
        for fn in [
            lambda_function_1,
            lambda_function_2,
            lambda_function_3,
            lambda_error_handler,
        ]:
            fn.grant_invoke(state_machine.role)

        #############################################################################
        #  API Gateway  →  HTTP API (v2)  →  Step Functions StartExecution
        #############################################################################

        # 1️⃣ Create an HTTP API
        http_api = apigwv2.HttpApi(
            self,
            "HttpApi_stepfuncproject",
            api_name="HttpApi_stepfuncproject",
        )

        # 2️⃣ Give API Gateway permission to call StartExecution on your state machine
        api_gw_role = iam.Role(
            self,
            "HttpApi_Role_stepfuncproject",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            role_name="HTTPApi_Role_stepfuncproject",
        )
        state_machine.grant_start_execution(api_gw_role)

        # 3️⃣ Define the Step Functions integration
        start_exec_integration = integ.HttpStepFunctionsIntegration(
            "Start_SF_Integration_stepfuncproject",
            state_machine=state_machine,
            parameter_mapping=apigwv2.ParameterMapping()
            # The 'StartExecution' API requires the 'Input' parameter (capital "I").
            .custom("Input", "$request.body")
            # The 'StartExecution' API also requires the 'StateMachineArn'.
            .custom("StateMachineArn", state_machine.state_machine_arn),
        )

        # 4️⃣ Wire up POST /invoke
        http_api.add_routes(
            path="/invoke",
            methods=[apigwv2.HttpMethod.POST],
            integration=start_exec_integration,
        )

        # Output the HTTP API endpoint URL

        CfnOutput(
            self,
            "HttpApiEndpoint_stepfuncproject",
            value=http_api.api_endpoint,
            description="HTTP API endpoint for Step Functions project",
            export_name="HttpApiEndpoint-stepfuncproject",
        )

        """
        This explains the data flow from the client API call to the first Lambda.

        A client does:

        curl -X POST 'https://{api-id}.execute-api.eu-west-2.amazonaws.com/invoke' \
            -H 'Content-Type: application/json' \
            -d '{"task":"sync", "data":"some-value"}'

        HTTP API calls the AWS 'StartExecution' API with a payload like this:
        (Note how the 'Input' field is a stringified version of the client's JSON)

        {
            "Input": "{\"task\":\"sync\", \"data\":\"some-value\"}",
            "StateMachineArn": "arn:aws:states:..."
        }

        Step Functions then parses the "Input" string. Because the first Lambda task
        is configured to receive the entire state (`$`), the Lambda's 'event' will be
        the original JSON object sent by the client:

        {
            "task": "sync",
            "data": "some-value"
        }
        """

        """
        to do
        What You Need Instead: Slack Request Verification

        While you don't need CORS, you absolutely must implement a different security mechanism to ensure that the requests hitting your API are genuinely from Slack and not from a malicious actor.

        also change names of resources
        """
