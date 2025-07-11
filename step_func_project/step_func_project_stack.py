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
)
from constructs import Construct


class StepFuncProjectStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        #################################################
        # Networking (VPC & Security Groups)
        #################################################
        # Create a VPC for the RDS instance
        vpc = ec2.Vpc(self, "StepFuncProjectVpc", max_azs=2)

        # Create a security group for the RDS instance
        rds_sg = ec2.SecurityGroup(
            self,
            "StepFuncProjectRdsSG",
            vpc=vpc,
            description="Allow PostgreSQL access",
            allow_all_outbound=True,
        )
        rds_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(5432),
            description="Allow PostgreSQL access from anywhere",
        )

        #################################################
        # Database (Amazon RDS for PostgreSQL)
        #################################################
        db_instance = rds.DatabaseInstance(
            self,
            "StepFuncProjectPostgres",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_17_4
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
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
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "CloudWatchFullAccessV2"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess"),
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
            db_instance.grant_connect(fn)

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

        # Reusable branch for error handling -------------------------------------
        def make_error_branch(scope: Construct, idx: int) -> sfn.Chain:
            err_invoke = tasks.LambdaInvoke(
                scope,
                f"Lambda error handler ({idx})",
                lambda_function=lambda_error_handler,
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
            return err_invoke.next(sfn.Fail(scope, f"Fail {idx}"))

        # 2️⃣ Choice states --------------------------------------------------------
        choice_3 = (
            sfn.Choice(self, "Choice 3")
            .when(
                sfn.Condition.boolean_equals("$.success", False),
                make_error_branch(self, 3),
            )
            .otherwise(sfn.Succeed(self, "Success"))
        )

        choice_2 = (
            sfn.Choice(self, "Choice 2")
            .when(
                sfn.Condition.boolean_equals("$.success", False),
                make_error_branch(self, 2),
            )
            .otherwise(invoke_3.next(choice_3))
        )

        choice_1 = (
            sfn.Choice(self, "Choice 1")
            .when(
                sfn.Condition.boolean_equals("$.success", False),
                make_error_branch(self, 1),
            )
            .otherwise(invoke_2.next(choice_2))
        )

        # 3️⃣ Glue everything together --------------------------------------------
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
