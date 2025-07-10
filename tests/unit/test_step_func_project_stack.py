import aws_cdk as core
import aws_cdk.assertions as assertions

from step_func_project.step_func_project_stack import StepFuncProjectStack

# example tests. To run these tests, uncomment this file along with the example
# resource in step_func_project/step_func_project_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = StepFuncProjectStack(app, "step-func-project")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
