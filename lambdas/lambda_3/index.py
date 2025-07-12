import json
import logging
from datetime import datetime

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    event  ==  JSON returned by Lambda 2
               (row_from_lambda1 plus Lambda 2’s own metadata)
    """
    log.info("=== Lambda 3 received from Lambda 2 ===")
    log.info(json.dumps(event, indent=2, default=str))

    return {
        "success": True,  # final Choice 3 will see this and Succeed
        "received_from_lambda2": event,
        "finished_at": datetime.now(datetime.timezone.utc).isoformat() + "Z",
    }
