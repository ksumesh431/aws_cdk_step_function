import os
import json
import time
import datetime
import requests
import concurrent.futures

import boto3
from sqlalchemy import create_engine, Index, Column, String, DateTime, Float, func
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy import text

# --- Concurrency ---
MAX_WORKERS = 13

# --- ORM Model (aligned with Lambda 1) ---
Base = declarative_base()


class PagerDutyIncident(Base):
    __tablename__ = "pagerduty_incidents"
    __table_args__ = (Index("ix_pdi_last_updated", "last_updated"),)

    id = Column(String, primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    severity = Column(String)
    duration = Column(String)

    last_updated = Column(DateTime(timezone=True), index=True)

    # Enriched fields
    incident_summary = Column(String)
    ack_noc_minutes = Column(Float)
    escalate_noc_minutes = Column(Float)
    ack_pythian_sre_minutes = Column(Float)
    escalate_pythian_sre_minutes = Column(Float)
    detect_time_minutes = Column(Float)
    restore_time_minutes = Column(Float)
    recover_time_minutes = Column(Float)

    Engineering_time_spent_on_incident = Column(String)
    Number_of_engineers = Column(String)
    Entity = Column(String)
    Platform = Column(String)
    Customer_Experience = Column(String)
    Incident_Category = Column(String)
    incident_detection_type_auto = Column(String)
    Pythian_resolution_without_lytx = Column(String)
    Alert_Autoresolved = Column(String)
    Incident_Resolution = Column(String)  # included per latest script

    # Timeline + custom timestamps
    trigger_time = Column(DateTime(timezone=True))
    noc_acknowledge_time = Column(DateTime(timezone=True))
    noc_escalate_time = Column(DateTime(timezone=True))
    pythian_sre_acknowledge_time = Column(DateTime(timezone=True))
    pythian_sre_escalate_time = Column(DateTime(timezone=True))
    Time_of_Detection = Column(DateTime(timezone=True))
    Time_of_Resolution = Column(DateTime(timezone=True))
    Time_of_Recovery = Column(DateTime(timezone=True))


def get_engine(secret: dict):
    user, password, host, port = (
        secret["username"],
        secret["password"],
        secret.get("host"),
        secret.get("port"),
    )
    dbname = os.environ.get("DB_NAME", "postgres")
    url = f"postgresql+pg8000://{user}:{password}@{host}:{port}/{dbname}"
    return create_engine(url, pool_pre_ping=True, future=True)


def ensure_expected_columns(engine):
    """
    Ensure new columns added to the ORM also exist in the DB table.
    This is a lightweight migration helper for simple additive schema changes.
    """
    expected_columns_sql = {
        # Additive columns introduced after the table already existed:
        "Incident_Resolution": "VARCHAR",
        # If you add more in the future, list them here:
        # "Some_New_Column": "VARCHAR",
        # "Some_New_Float": "DOUBLE PRECISION",
        # "Some_New_Timestamp": "TIMESTAMPTZ",
    }

    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'pagerduty_incidents'
        """)).fetchall()
        existing = {r[0] for r in rows}

        for col_name, col_type in expected_columns_sql.items():
            if col_name not in existing:
                sql = f'ALTER TABLE pagerduty_incidents ADD COLUMN IF NOT EXISTS "{col_name}" {col_type}'
                print(f"Applying schema change: {sql}")
                conn.execute(text(sql))


# ==============================================================================
# === PAGERDUTY CORE LOGIC (aligned with your manual script) ===
# ==============================================================================
BASE_URL = "https://api.pagerduty.com"

TARGET_CUSTOM_FIELD_DISPLAY_NAMES = [
    "Time_of_Detection",
    "Time_of_Resolution",
    "Time_of_Recovery",
    "Engineering_time_spent_on_incident",
    "Number_of_engineers",
    "Entity",
    "Platform",
    "Customer_Experience",
    "Incident_Category",
    "incident_detection_type_auto",
    "Pythian_resolution_without_lytx",
    "Alert_Autoresolved",
    "Incident_Resolution",
]

PYTHIAN_SRE_USERS = [
    "Anand Kamath",
    "Rachana Rangineni",
    "Shahid Azeez",
    "Shikha Sonkar",
    "Sri Penumuchu",
    "Vikas Vats",
    "Jason Ramsey",
]

# OLD categories (still used in codebase per your note)
INCIDENT_CATEGORIES = [
    "Release",
    "Deficient_Maintainence",
    "Feature_Toggle",
    "Security",
    "Soft_Misconfiguration",
    "External_Service",
    "Platform_Misconfiguration",
    "Service_Decommission",
    "Saturation",
]

ENTITIES = ["WNS", "Drivecam", "Surfsight"]
PLATFORMS = ["AWS", "Onprem", "Thirdparty"]


def _pd_headers(api_key: str) -> dict:
    return {
        "Authorization": f"Token token={api_key}",
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
    }


def _retrying_get(
    url: str, headers: dict, params: dict, timeout: int = 30, max_attempts: int = 3
):
    for attempt in range(max_attempts):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 429:
                wait = min(2**attempt, 8)
                print(f"[429] Rate limited at {url}. Backing off {wait}s...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            if attempt == max_attempts - 1:
                raise
            wait = min(2**attempt, 8)
            print(
                f"GET {url} failed (attempt {attempt+1}/{max_attempts}): {e}. Retrying in {wait}s..."
            )
            time.sleep(wait)
    return None  # not reached


def get_incident_details_with_custom_fields(incident_id, api_key):
    url = f"{BASE_URL}/incidents/{incident_id}"
    params = {"include[]": "custom_fields"}
    try:
        resp = _retrying_get(url, headers=_pd_headers(api_key), params=params)
        return resp.json().get("incident") if resp is not None else None
    except Exception as e:
        print(f"Error fetching details for incident {incident_id}: {e}")
        return None


def get_incident_log_entries(incident_id, api_key):
    all_log_entries = []
    offset = 0
    limit = 100
    url = f"{BASE_URL}/incidents/{incident_id}/log_entries"
    while True:
        params = {
            "offset": offset,
            "limit": limit,
            "is_overview": "false",
            "include[]": ["channels"],
        }
        try:
            resp = _retrying_get(url, headers=_pd_headers(api_key), params=params)
            if resp is None:
                return all_log_entries
            data = resp.json()
            page = data.get("log_entries", [])
            all_log_entries.extend(page)
            if not data.get("more", False):
                break
            if not page:
                print(
                    f"Warning: API indicates more entries for {incident_id} but returned empty page. Stopping."
                )
                break
            offset += len(page)
        except Exception as e:
            print(f"Error fetching logs for incident {incident_id}: {e}")
            return all_log_entries
    return all_log_entries


def parse_iso_datetime(timestamp_str):
    if not timestamp_str:
        return None
    try:
        # supports "...Z" & "+00:00"
        return datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        print(f"Warning: Could not parse timestamp: {timestamp_str}")
        return None


def extract_data_from_timeline(log_entries):
    """
    Matches your manual script:
    - Records earliest trigger/ack/escalate times
    - Distinguishes NOC ('Pythian PagerDuty') vs SRE (name in PYTHIAN_SRE_USERS)
    - If not escalated by agent, checks assignees
    """
    extracted = {
        "trigger_time": None,
        "noc_acknowledge_time": None,
        "noc_escalate_time": None,
        "pythian_sre_acknowledge_time": None,
        "pythian_sre_escalate_time": None,
    }

    for entry in log_entries:
        entry_type = entry.get("type")
        created_at = entry.get("created_at")
        if not created_at:
            continue

        agent_info = entry.get("agent") or {}
        agent_type = agent_info.get("type")
        agent_summary = agent_info.get("summary")

        if entry_type == "trigger_log_entry":
            if (
                extracted["trigger_time"] is None
                or created_at < extracted["trigger_time"]
            ):
                extracted["trigger_time"] = created_at

        elif entry_type == "acknowledge_log_entry":
            if agent_type == "user_reference":
                if agent_summary == "Pythian PagerDuty":
                    if (
                        extracted["noc_acknowledge_time"] is None
                        or created_at < extracted["noc_acknowledge_time"]
                    ):
                        extracted["noc_acknowledge_time"] = created_at
                elif agent_summary in PYTHIAN_SRE_USERS:
                    if (
                        extracted["pythian_sre_acknowledge_time"] is None
                        or created_at < extracted["pythian_sre_acknowledge_time"]
                    ):
                        extracted["pythian_sre_acknowledge_time"] = created_at

        elif entry_type == "escalate_log_entry":
            escalated_by_user_agent = False
            if agent_type == "user_reference":
                if agent_summary == "Pythian PagerDuty":
                    if (
                        extracted["noc_escalate_time"] is None
                        or created_at < extracted["noc_escalate_time"]
                    ):
                        extracted["noc_escalate_time"] = created_at
                        escalated_by_user_agent = True
                elif agent_summary in PYTHIAN_SRE_USERS:
                    if (
                        extracted["pythian_sre_escalate_time"] is None
                        or created_at < extracted["pythian_sre_escalate_time"]
                    ):
                        extracted["pythian_sre_escalate_time"] = created_at
                        escalated_by_user_agent = True

            if not escalated_by_user_agent:
                assignees = entry.get("assignees", [])
                for assignee in assignees:
                    if assignee.get("type") == "user_reference":
                        s = assignee.get("summary")
                        if s == "Pythian PagerDuty":
                            if (
                                extracted["noc_escalate_time"] is None
                                or created_at < extracted["noc_escalate_time"]
                            ):
                                extracted["noc_escalate_time"] = created_at
                        elif s in PYTHIAN_SRE_USERS:
                            if (
                                extracted["pythian_sre_escalate_time"] is None
                                or created_at < extracted["pythian_sre_escalate_time"]
                            ):
                                extracted["pythian_sre_escalate_time"] = created_at

    return extracted


def calculate_time_difference_minutes(end_time_str, start_time_str):
    if start_time_str is None or end_time_str is None:
        return None
    start_dt = parse_iso_datetime(start_time_str)
    end_dt = parse_iso_datetime(end_time_str)
    if not start_dt or not end_dt:
        return None
    return round((end_dt - start_dt).total_seconds() / 60.0, 2)


def process_single_incident(incident_id, api_key):
    """
    Fetches details, logs, and computes enriched metrics for one incident.
    Returns a dict to upsert into the DB.
    """
    incident_details = get_incident_details_with_custom_fields(incident_id, api_key)
    if not incident_details:
        return None

    # Custom fields extraction (initialize all to None)
    custom_fields = {key: None for key in TARGET_CUSTOM_FIELD_DISPLAY_NAMES}
    for field in incident_details.get("custom_fields") or []:
        if isinstance(field, dict):
            dn = field.get("display_name")
            if dn in custom_fields:
                custom_fields[dn] = field.get("value")

    # Logs → timeline
    incident_logs = get_incident_log_entries(incident_id, api_key)
    timeline = extract_data_from_timeline(incident_logs)

    trigger_time = timeline.get("trigger_time")
    noc_ack = timeline.get("noc_acknowledge_time")
    noc_esc = timeline.get("noc_escalate_time")
    sre_ack = timeline.get("pythian_sre_acknowledge_time")
    sre_esc = timeline.get("pythian_sre_escalate_time")

    # Metrics
    ack_noc_minutes = calculate_time_difference_minutes(noc_ack, trigger_time)
    escalate_noc_minutes = calculate_time_difference_minutes(noc_esc, noc_ack)
    if escalate_noc_minutes is not None and escalate_noc_minutes < 0:
        # fallback to trigger baseline like your script
        escalate_noc_minutes = calculate_time_difference_minutes(noc_esc, trigger_time)

    ack_pythian_sre_minutes = calculate_time_difference_minutes(sre_ack, noc_esc)
    if ack_pythian_sre_minutes is not None and ack_pythian_sre_minutes < 0:
        ack_pythian_sre_minutes = calculate_time_difference_minutes(
            sre_ack, trigger_time
        )

    escalate_pythian_sre_minutes = calculate_time_difference_minutes(sre_esc, sre_ack)
    if escalate_pythian_sre_minutes is not None and escalate_pythian_sre_minutes < 0:
        escalate_pythian_sre_minutes = calculate_time_difference_minutes(
            sre_esc, trigger_time
        )

    detect_time_minutes = calculate_time_difference_minutes(
        custom_fields.get("Time_of_Detection"), trigger_time
    )
    restore_time_minutes = calculate_time_difference_minutes(
        custom_fields.get("Time_of_Resolution"), trigger_time
    )
    # IMPORTANT: Recover time is Recovery - Resolution (updated logic)
    recover_time_minutes = calculate_time_difference_minutes(
        custom_fields.get("Time_of_Recovery"), custom_fields.get("Time_of_Resolution")
    )

    # Base DB update dict
    db_update = {
        "id": incident_id,
        "incident_summary": incident_details.get("title"),
        "ack_noc_minutes": ack_noc_minutes,
        "escalate_noc_minutes": escalate_noc_minutes,
        "ack_pythian_sre_minutes": ack_pythian_sre_minutes,
        "escalate_pythian_sre_minutes": escalate_pythian_sre_minutes,
        "detect_time_minutes": detect_time_minutes,
        "restore_time_minutes": restore_time_minutes,
        "recover_time_minutes": recover_time_minutes,
        # timeline timestamps
        **{k: parse_iso_datetime(v) for k, v in timeline.items() if v is not None},
    }

    # Custom fields → DB: include even if None for completeness, but set some defaults
    # Defaults for booleans-as-strings
    for key in ("incident_detection_type_auto", "Pythian_resolution_without_lytx"):
        val = custom_fields.get(key)
        db_update[key] = "FALSE" if val is None else val

    # Pass-through fields
    passthrough = [
        "Engineering_time_spent_on_incident",
        "Number_of_engineers",
        "Customer_Experience",
        "Alert_Autoresolved",
        "Incident_Resolution",
    ]
    for key in passthrough:
        db_update[key] = custom_fields.get(key)

    # Enum-restricted fields
    if custom_fields.get("Entity") in ENTITIES:
        db_update["Entity"] = custom_fields.get("Entity")
    if custom_fields.get("Platform") in PLATFORMS:
        db_update["Platform"] = custom_fields.get("Platform")
    if custom_fields.get("Incident_Category") in INCIDENT_CATEGORIES:
        db_update["Incident_Category"] = custom_fields.get("Incident_Category")

    # Custom timestamp fields
    db_update["Time_of_Detection"] = parse_iso_datetime(
        custom_fields.get("Time_of_Detection")
    )
    db_update["Time_of_Resolution"] = parse_iso_datetime(
        custom_fields.get("Time_of_Resolution")
    )
    db_update["Time_of_Recovery"] = parse_iso_datetime(
        custom_fields.get("Time_of_Recovery")
    )

    return db_update


secrets_client = boto3.client("secretsmanager")


# === Main Lambda Handler ===
def lambda_handler(event, context):
    try:
        print("=== PagerDuty Incident ENRICHMENT Lambda Started (Parallel) ===")

        # Extract parameters from event
        force_refresh = event.get("force_refresh", False)
        freshness_threshold_minutes = event.get("freshness_threshold_minutes", 30)

        print(f"Force refresh: {force_refresh}")
        print(f"Freshness threshold: {freshness_threshold_minutes} minutes")

        # Secrets
        pagerduty_secret_payload = secrets_client.get_secret_value(
            SecretId="pagerduty/API_KEY"
        )
        pagerduty_api_key = json.loads(pagerduty_secret_payload["SecretString"])[
            "API_KEY"
        ]

        db_secret_arn = os.environ["DB_SECRET_ARN"]
        db_secret_payload = secrets_client.get_secret_value(SecretId=db_secret_arn)
        db_secret = json.loads(db_secret_payload["SecretString"])

        engine = get_engine(db_secret)
        Base.metadata.create_all(engine)
        ensure_expected_columns(engine)
        
        # Choose incidents to enrich
        with Session(engine) as session:
            if not force_refresh:
                latest_enrichment = (
                    session.query(func.max(PagerDutyIncident.last_updated))
                    .filter(PagerDutyIncident.incident_summary.isnot(None))
                    .scalar()
                )
                if latest_enrichment:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    minutes_since = (now - latest_enrichment).total_seconds() / 60
                    if minutes_since < freshness_threshold_minutes:
                        print(
                            f"Enriched data is fresh ({minutes_since:.1f} minutes). Skipping enrichment."
                        )
                        return {
                            "success": True,
                            "skipped": True,
                            "reason": "enriched_data_is_fresh",
                            "minutes_since_enrichment": round(minutes_since, 1),
                            "incidents_updated": 0,
                            "force_refresh": force_refresh,
                            "freshness_threshold_minutes": freshness_threshold_minutes,
                        }

            if force_refresh:
                # Re-enrich all useful incidents (filter out empty placeholders)
                incidents_to_enrich = (
                    session.query(PagerDutyIncident)
                    .filter(PagerDutyIncident.severity != "N/A")
                    .all()
                )
                print(
                    f"Force refresh: {len(incidents_to_enrich)} incidents to re-enrich."
                )
            else:
                # Only those missing enrichment
                incidents_to_enrich = (
                    session.query(PagerDutyIncident)
                    .filter(
                        PagerDutyIncident.severity != "N/A",
                        PagerDutyIncident.incident_summary.is_(None),
                    )
                    .all()
                )
                print(
                    f"Normal mode: {len(incidents_to_enrich)} incidents need enrichment."
                )

        if not incidents_to_enrich:
            print("No incidents to enrich found.")
            return {
                "success": True,
                "message": "No incidents to enrich.",
                "incidents_updated": 0,
                "force_refresh": force_refresh,
                "freshness_threshold_minutes": freshness_threshold_minutes,
            }

        incident_ids = [i.id for i in incidents_to_enrich]
        print(f"Processing {len(incident_ids)} incidents with {MAX_WORKERS} workers...")

        all_enriched = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_id = {
                executor.submit(
                    process_single_incident, inc_id, pagerduty_api_key
                ): inc_id
                for inc_id in incident_ids
            }
            for future in concurrent.futures.as_completed(future_to_id):
                inc_id = future_to_id[future]
                try:
                    res = future.result()
                    if res:
                        all_enriched.append(res)
                    else:
                        print(f"Incident {inc_id}: no enrichment produced.")
                except Exception as e:
                    print(f"Incident {inc_id} raised exception: {e}")

        if not all_enriched:
            print("No incidents were successfully enriched.")
            return {
                "success": True,
                "message": "No incidents were successfully enriched.",
                "incidents_updated": 0,
                "force_refresh": force_refresh,
                "freshness_threshold_minutes": freshness_threshold_minutes,
            }

        # Upsert into DB
        now_ts = datetime.datetime.now(datetime.timezone.utc)
        updated = 0
        with Session(engine) as session:
            for data in all_enriched:
                data["last_updated"] = now_ts
                session.merge(PagerDutyIncident(**data))
                updated += 1
            session.commit()

        print(f"SUCCESS: Updated {updated} incidents with enriched data.")
        return {
            "success": True,
            "incidents_updated": updated,
            "force_refresh": force_refresh,
            "freshness_threshold_minutes": freshness_threshold_minutes,
        }

    except Exception as exc:
        error_message = f"An unexpected error occurred in Lambda 2: {exc}"
        print(error_message)
        return {"success": False, "error": str(exc), "type": exc.__class__.__name__}
