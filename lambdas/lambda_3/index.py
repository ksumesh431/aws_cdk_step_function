import json
import logging
from datetime import datetime, timezone


log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, context):
    try:
        """
        event  ==  JSON returned by Lambda 2
                (row_from_lambda1 plus Lambda 2’s own metadata)
        """
        log.info("=== Lambda 3 received from Lambda 2 ===")
        log.info(json.dumps(event, indent=2, default=str))

        return {
            "success": True,  # final Choice 3 will see this and Succeed
            "received_from_lambda2": event,
            "finished_at": datetime.now(timezone.utc).isoformat() + "Z",
        }
    except Exception as exc:
        log.error(f"Error: {exc}")
        return {
            "success": False,
            "error": str(exc),
            "type": exc.__class__.__name__,
            "error_from": "Lambda 3",
        }