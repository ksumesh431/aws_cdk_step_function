#!/usr/bin/env python3
import os
import yaml
from pathlib import Path
import aws_cdk as cdk
from aws_cdk import Tags
from step_func_project.step_func_project_stack import StepFuncProjectStack


# Load configuration
def load_config():
    config_path = Path(__file__).parent / "variables.yml"
    with open(config_path, "r") as file:
        return yaml.safe_load(file)


config = load_config()

app = cdk.App()

# Global tags
for tag_key, tag_value in config["tags"].items():
    Tags.of(app).add(tag_key, tag_value)

StepFuncProjectStack(
    app,
    "StepFuncProjectStack",
    env=cdk.Environment(
        account=config["aws"]["account_id"], region=config["aws"]["region"]
    ),
)

app.synth()
