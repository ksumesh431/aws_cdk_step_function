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
)
from constructs import Construct


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
            "ExistingVpc",
            vpc_id="vpc-0e01c3c7ae69fd92b",  #  <-- your real VPC ID here
        )

        # import the two subnets by ID
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
            "StepFuncProjectRdsSG",
            vpc=vpc,
            description="Allow PostgreSQL access",
            allow_all_outbound=True,
        )

        # Security Group for Lambda Functions
        lambda_sg = ec2.SecurityGroup(
            self,
            "LambdaSecurityGroup",
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
            "StepFuncProjectPostgres",
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
            credentials=rds.Credentials.from_generated_secret("postgres"),
            removal_policy=RemovalPolicy.DESTROY,
            deletion_protection=False,
            iam_authentication=True,
        )

        #################################################
        # IAM Roles & Permissions
        #################################################
        role = iam.Role(
            self,
            "LambdaExecutionRole",
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
            ],
        )

        #################################################
        # Lambda Layer
        #################################################
        layer = lambda_.LayerVersion(
            self,
            "helper_layer",
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
                "id": "StepFuncProject_LambdaFunction_1",
                "desc": "1st Lambda in the step functions to interact with RDS",
                "name": "StepFuncProject_LambdaFunction_1",
                "asset": "lambdas/lambda_1",
            },
            {
                "id": "StepFuncProject_LambdaFunction_2",
                "desc": None,
                "name": "StepFuncProject_LambdaFunction_2",
                "asset": "lambdas/lambda_2",
            },
            {
                "id": "StepFuncProject_LambdaFunction_3",
                "desc": None,
                "name": "StepFuncProject_LambdaFunction_3",
                "asset": "lambdas/lambda_3",
            },
            {
                "id": "StepFuncProject_LambdaErrorHandler",
                "desc": "Lambda function to handle errors in the step functions",
                "name": "StepFuncProject_LambdaErrorHandler",
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
                timeout=Duration.seconds(30),
                vpc_subnets=ec2.SubnetSelection(  # optional; keeps them in the NAT gateway subnets
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                environment={
                    "DB_SECRET_ARN": db_instance.secret.secret_arn,
                    "DB_HOST": db_instance.db_instance_endpoint_address,
                    "DB_PORT": str(db_instance.db_instance_endpoint_port),
                    "DB_NAME": "postgres",
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
            # db_instance.grant_connect(fn) # This allows the Lambda functions to connect to the database using IAM authentication
            db_instance.secret.grant_read(
                fn
            )  # This allows the Lambda functions to read the database credentials

        #################################################
        # API Gateway
        #################################################
        api = apigateway.RestApi(self, "StepFuncProjectApi")
        invoke_resource = api.root.add_resource("invoke")
        invoke_resource.add_method(
            "POST", apigateway.LambdaIntegration(lambda_function_1)
        )

        #################################################
        # Step Functions State Machine
        #################################################

        # 1️⃣ Lambda-invoke tasks ---------------------------------------------------
        invoke_1 = tasks.LambdaInvoke(
            self,
            "Lambda Invoke 1",
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
            "Lambda Invoke 2",
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
            "Lambda Invoke 3",
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
            "Lambda error handler",
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
            sfn.Choice(self, "Choice 3")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(sfn.Succeed(self, "Success"))
        )

        choice_2 = (
            sfn.Choice(self, "Choice 2")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(invoke_3.next(choice_3))
        )

        choice_1 = (
            sfn.Choice(self, "Choice 1")
            .when(sfn.Condition.boolean_equals("$.success", False), error_branch)
            .otherwise(invoke_2.next(choice_2))
        )

        # 4️⃣ Glue everything together ----------------------------------------------
        definition = invoke_1.next(choice_1)

        state_machine = sfn.StateMachine(
            self,
            "StepFuncProjectStateMachine",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.minutes(5),
        )

        # Allow Step Functions to call Lambdas
        for fn in [
            lambda_function_1,
            lambda_function_2,
            lambda_function_3,
            lambda_error_handler,
        ]:
            fn.grant_invoke(state_machine.role)
