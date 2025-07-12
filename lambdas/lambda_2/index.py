import json
import logging
from datetime import datetime

# Use the Lambda logger so messages appear in CloudWatch Logs
log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    event  ==  exact JSON returned by Lambda 1
               (because the Step-Functions task uses output_path="$.Payload")

    All we do is log it and forward a slightly enriched object.
    """
    log.info("=== Lambda 2 received from Lambda 1 ===")
    log.info(json.dumps(event, indent=2, default=str))

    # Pull out whatever Lambda 1 inserted (optional)
    inserted_row = event.get("row")  # {'id': '...', 'created_at': '...'}
    success_flag = event.get("success")

    # Pass downstream – keep success=True so Choice 2 stays on the happy path
    return {
        "success": bool(success_flag),  # should already be True
        "row_from_lambda1": inserted_row,
        "checked_at": datetime.now(datetime.timezone.utc).isoformat() + "Z",
    }
