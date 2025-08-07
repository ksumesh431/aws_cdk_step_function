# index.py
import json
import datetime
from typing import Any, Dict, Tuple


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _as_dict(value: Any) -> Any:
    """
    If value is a JSON string, try to parse it to dict. Otherwise return as-is.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _extract_error(payload: Any) -> Tuple[str, str]:
    """
    Normalize an error type and message from various payload shapes.

    Supported shapes:
    - {"success": False, "error": "...", "type": "..."}  (your Lambda returns)
    - {"Error": "...", "Cause": "..."}                   (SFN task failure)
    - {"error": {...}}                                   (from add_catch result_path="$.error")
    - JSON string-encoded variants of the above
    - Arbitrary dict or string payloads
    """
    payload = _as_dict(payload)

    def _unpack_cause(val: Any) -> str:
        # Cause/message may be a JSON string with {"errorMessage": "..."} etc.
        if isinstance(val, str):
            try:
                obj = json.loads(val)
            except Exception:
                return val
            if isinstance(obj, str):
                return obj
            if isinstance(obj, dict):
                return (
                    obj.get("errorMessage")
                    or obj.get("message")
                    or obj.get("Message")
                    or json.dumps(obj)
                )
            return str(obj)
        if isinstance(val, dict):
            return (
                val.get("errorMessage")
                or val.get("message")
                or val.get("Message")
                or json.dumps(val)
            )
        return str(val)

    if isinstance(payload, dict):
        # 1) From add_catch(..., result_path="$.error") -> nested error object
        if "error" in payload:
            nested = _as_dict(payload.get("error"))
            if isinstance(nested, dict):
                err_type = (
                    nested.get("Error")
                    or nested.get("errorType")
                    or nested.get("type")
                    or "UnknownError"
                )
                msg = (
                    _unpack_cause(nested.get("Cause"))
                    if "Cause" in nested
                    else (nested.get("error") or nested.get("message") or "")
                )
                if not msg:
                    msg = _unpack_cause(nested)
                return str(err_type), str(msg)
            else:
                return "UnknownError", _unpack_cause(nested)

        # 2) Direct SFN task failure shape
        if "Error" in payload or "Cause" in payload:
            err_type = (
                payload.get("Error") or payload.get("errorType") or "UnknownError"
            )
            msg = (
                _unpack_cause(payload.get("Cause"))
                or payload.get("message")
                or payload.get("error")
                or ""
            )
            return str(err_type), str(msg)

        # 3) Your Lambda's structured failure
        if payload.get("success") is False:
            err_type = payload.get("type") or payload.get("errorType") or "UnknownError"
            msg = payload.get("error") or payload.get("message") or ""
            return str(err_type), str(msg)

        # 4) Fallback best-effort
        err_type = (
            payload.get("type")
            or payload.get("errorType")
            or payload.get("status")
            or "UnknownError"
        )
        msg = (
            payload.get("error") or payload.get("message") or payload.get("Cause") or ""
        )
        if not msg:
            try:
                msg = json.dumps(payload)
            except Exception:
                msg = str(payload)
        return str(err_type), str(msg)

    # Non-dict payloads
    return "UnknownError", str(payload)


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Error handler for the Step Functions workflow.

    Expected event shape (as configured in the state machine):
    {
        "failedStep": "<State.Name>",
        "executionId": "<Execution.Id>",
        "executionName": "<Execution.Name>",
        "startTime": "<Execution.StartTime>",
        "payload": { ... original lambda output ... }
    }
    """
    # Log the raw event for troubleshooting
    print("Received error handler event:")
    print(json.dumps(event, default=str))

    failed_step = event.get("failedStep", "UnknownStep")
    execution_id = event.get("executionId")
    execution_name = event.get("executionName")
    start_time = event.get("startTime")
    original_payload = event.get("payload")

    err_type, err_message = _extract_error(original_payload)

    response = {
        "success": False,
        "handledAt": _now_iso(),
        "failedStep": failed_step,
        "execution": {
            "id": execution_id,
            "name": execution_name,
            "startTime": start_time,
            "requestId": getattr(context, "aws_request_id", None),
        },
        "error": {
            "type": err_type,
            "message": err_message,
            "originalPayload": _as_dict(original_payload),
        },
    }

    # Print a concise line for CloudWatch filtering
    print(
        json.dumps(
            {
                "event": "StepFunctionErrorHandled",
                "failedStep": failed_step,
                "executionId": execution_id,
                "errorType": err_type,
                "message": err_message,
            }
        )
    )

    return response
