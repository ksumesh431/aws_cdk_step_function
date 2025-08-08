import os
import json
import datetime
import requests
import concurrent.futures  # Import the concurrency library

import boto3
from sqlalchemy import create_engine, Index, Column, String, DateTime, Float, func
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy.exc import SQLAlchemyError

# --- Configuration for Concurrency ---
# Start with a conservative number. PagerDuty has API rate limits.
# 10 is a reasonable starting point.
MAX_WORKERS = 15

# --- SQLAlchemy Model and Helper functions are IDENTICAL to your original code ---
# (Keeping them here for completeness)

Base = declarative_base()


class PagerDutyIncident(Base):
    __tablename__ = "pagerduty_incidents"
    __table_args__ = (Index("ix_pdi_last_updated", "last_updated"),)

    # --- Columns from First Lambda ---
    id = Column(String, primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    severity = Column(String)
    duration = Column(String)

    # --- NEW: Last Updated Timestamp ---
    last_updated = Column(DateTime(timezone=True), index=True)

    # --- NEW Columns for Enriched Data (from reference code) ---
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

    # Timestamps from timeline and custom fields
    trigger_time = Column(DateTime(timezone=True))
    noc_acknowledge_time = Column(DateTime(timezone=True))
    noc_escalate_time = Column(DateTime(timezone=True))
    pythian_sre_acknowledge_time = Column(DateTime(timezone=True))
    pythian_sre_escalate_time = Column(DateTime(timezone=True))
    Time_of_Detection = Column(DateTime(timezone=True))
    Time_of_Resolution = Column(DateTime(timezone=True))
    Time_of_Recovery = Column(DateTime(timezone=True))


def get_engine(secret: dict):
    # ... (No changes needed) ...
    user, password, host, port = (
        secret["username"],
        secret["password"],
        secret.get("host"),
        secret.get("port"),
    )
    dbname = os.environ.get("DB_NAME", "postgres")
    url = f"postgresql+pg8000://{user}:{password}@{host}:{port}/{dbname}"
    return create_engine(url, pool_pre_ping=True, future=True)


# ==============================================================================
# === PAGERDUTY CORE LOGIC (FROM YOUR REFERENCE CODE) ===
# ==============================================================================

# --- Configuration ---
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
# --- End of Configuration ---


def get_headers(api_key):
    """Generates the headers dictionary dynamically."""
    return {
        "Authorization": f"Token token={api_key}",
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
    }


def get_incident_details_with_custom_fields(incident_id, api_key):
    incident_url = f"{BASE_URL}/incidents/{incident_id}"
    params = {"include[]": "custom_fields"}
    try:
        response = requests.get(
            incident_url, headers=get_headers(api_key), params=params, timeout=30
        )
        response.raise_for_status()
        return response.json().get("incident")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching details for incident {incident_id}: {e}")
        return None


def get_incident_log_entries(incident_id, api_key):
    all_log_entries = []
    offset = 0
    limit = 100
    log_entries_url = f"{BASE_URL}/incidents/{incident_id}/log_entries"
    while True:
        params = {
            "offset": offset,
            "limit": limit,
            "is_overview": "false",
            "include[]": ["channels"],
        }
        try:
            response = requests.get(
                log_entries_url, headers=get_headers(api_key), params=params, timeout=30
            )
            response.raise_for_status()
            data = response.json()
            log_entries_page = data.get("log_entries", [])
            all_log_entries.extend(log_entries_page)
            if not data.get("more", False):
                break
            offset += len(log_entries_page)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching logs for incident {incident_id}: {e}")
            return []
    return all_log_entries


def parse_iso_datetime(timestamp_str):
    if not timestamp_str:
        return None
    try:
        return datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        print(f"Warning: Could not parse timestamp: {timestamp_str}")
        return None


def extract_data_from_timeline(log_entries):
    extracted_times = {
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

        agent_summary = (entry.get("agent") or {}).get("summary")

        if entry_type == "trigger_log_entry" and not extracted_times["trigger_time"]:
            extracted_times["trigger_time"] = created_at
        elif entry_type == "acknowledge_log_entry":
            if (
                agent_summary == "Pythian PagerDuty"
                and not extracted_times["noc_acknowledge_time"]
            ):
                extracted_times["noc_acknowledge_time"] = created_at
            elif (
                agent_summary in PYTHIAN_SRE_USERS
                and not extracted_times["pythian_sre_acknowledge_time"]
            ):
                extracted_times["pythian_sre_acknowledge_time"] = created_at
        elif entry_type == "escalate_log_entry":
            if (
                agent_summary == "Pythian PagerDuty"
                and not extracted_times["noc_escalate_time"]
            ):
                extracted_times["noc_escalate_time"] = created_at
            elif (
                agent_summary in PYTHIAN_SRE_USERS
                and not extracted_times["pythian_sre_escalate_time"]
            ):
                extracted_times["pythian_sre_escalate_time"] = created_at
    return extracted_times


def calculate_time_difference_minutes(end_time_str, start_time_str):
    start_dt = parse_iso_datetime(start_time_str)
    end_dt = parse_iso_datetime(end_time_str)
    if not start_dt or not end_dt:
        return None
    return round((end_dt - start_dt).total_seconds() / 60.0, 2)


def process_single_incident(incident_id, api_key):
    """Worker function to process a single incident and return a dictionary of fields to update."""
    incident_details = get_incident_details_with_custom_fields(incident_id, api_key)
    if not incident_details:
        return None

    custom_fields = {key: None for key in TARGET_CUSTOM_FIELD_DISPLAY_NAMES}
    for field in incident_details.get("custom_fields", []):
        if (display_name := field.get("display_name")) in custom_fields:
            custom_fields[display_name] = field.get("value")

    incident_logs = get_incident_log_entries(incident_id, api_key)
    timeline = extract_data_from_timeline(incident_logs)

    metrics = {}
    trigger_time = timeline.get("trigger_time")

    metrics["ack_noc_minutes"] = calculate_time_difference_minutes(
        timeline.get("noc_acknowledge_time"), trigger_time
    )
    metrics["escalate_noc_minutes"] = calculate_time_difference_minutes(
        timeline.get("noc_escalate_time"), timeline.get("noc_acknowledge_time")
    )
    metrics["ack_pythian_sre_minutes"] = calculate_time_difference_minutes(
        timeline.get("pythian_sre_acknowledge_time"), timeline.get("noc_escalate_time")
    )
    metrics["escalate_pythian_sre_minutes"] = calculate_time_difference_minutes(
        timeline.get("pythian_sre_escalate_time"),
        timeline.get("pythian_sre_acknowledge_time"),
    )
    metrics["detect_time_minutes"] = calculate_time_difference_minutes(
        custom_fields.get("Time_of_Detection"), trigger_time
    )
    metrics["restore_time_minutes"] = calculate_time_difference_minutes(
        custom_fields.get("Time_of_Resolution"), trigger_time
    )
    metrics["recover_time_minutes"] = calculate_time_difference_minutes(
        custom_fields.get("Time_of_Recovery"), trigger_time
    )

    db_update_data = {
        "id": incident_id,
        "incident_summary": incident_details.get("title"),
        **metrics,
        **{k: v for k, v in custom_fields.items() if v is not None},
        **{k: parse_iso_datetime(v) for k, v in timeline.items() if v is not None},
    }

    db_update_data["Time_of_Detection"] = parse_iso_datetime(
        custom_fields.get("Time_of_Detection")
    )
    db_update_data["Time_of_Resolution"] = parse_iso_datetime(
        custom_fields.get("Time_of_Resolution")
    )
    db_update_data["Time_of_Recovery"] = parse_iso_datetime(
        custom_fields.get("Time_of_Recovery")
    )

    for field_name in ["Entity", "Platform", "Incident_Category"]:
        if val := custom_fields.get(field_name):
            if (
                (field_name == "Entity" and val in ENTITIES)
                or (field_name == "Platform" and val in PLATFORMS)
                or (field_name == "Incident_Category" and val in INCIDENT_CATEGORIES)
            ):
                db_update_data[field_name] = val
            else:
                db_update_data.pop(field_name, None)

    return db_update_data


secrets_client = boto3.client("secretsmanager")


# === Main Lambda Handler ===
def lambda_handler(event, context):
    try:
        print("=== PagerDuty Incident ENRICHMENT Lambda Started (Concurrent Mode) ===")

        # Extract parameters from event
        force_refresh = event.get("force_refresh", False)
        freshness_threshold_minutes = event.get("freshness_threshold_minutes", 30)

        print(f"Force refresh: {force_refresh}")
        print(f"Freshness threshold: {freshness_threshold_minutes} minutes")

        # Get secrets and setup
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

        with Session(engine) as session:
            # Check freshness if not forcing refresh
            if not force_refresh:
                # Check if we have recent enrichments
                latest_enrichment = (
                    session.query(func.max(PagerDutyIncident.last_updated))
                    .filter(
                        PagerDutyIncident.incident_summary.isnot(None)
                    )  # Only enriched records
                    .scalar()
                )

                if latest_enrichment:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    minutes_since_enrichment = (
                        now - latest_enrichment
                    ).total_seconds() / 60

                    if minutes_since_enrichment < freshness_threshold_minutes:
                        print(
                            f"Enriched data is fresh (updated {minutes_since_enrichment:.1f} minutes ago). Skipping enrichment."
                        )
                        return {
                            "success": True,
                            "skipped": True,
                            "reason": "enriched_data_is_fresh",
                            "minutes_since_enrichment": round(
                                minutes_since_enrichment, 1
                            ),
                            "incidents_updated": 0,
                            "force_refresh": force_refresh,
                            "freshness_threshold_minutes": freshness_threshold_minutes,
                        }

            # Find incidents to enrich
            if force_refresh:
                # If forcing refresh, enrich all incidents (or recent ones)
                incidents_to_enrich = (
                    session.query(PagerDutyIncident)
                    .filter(PagerDutyIncident.severity != "N/A")
                    .all()
                )
                print(
                    f"Force refresh: Found {len(incidents_to_enrich)} total incidents to re-enrich"
                )
            else:
                # Normal mode: only enrich incidents missing enrichment data
                incidents_to_enrich = (
                    session.query(PagerDutyIncident)
                    .filter(
                        PagerDutyIncident.severity != "N/A",
                        PagerDutyIncident.incident_summary == None,
                    )
                    .all()
                )
                print(
                    f"Normal mode: Found {len(incidents_to_enrich)} incidents needing enrichment"
                )

        if not incidents_to_enrich:
            print("No incidents to enrich found in the database.")
            return {
                "success": True,
                "message": "No incidents to enrich.",
                "incidents_updated": 0,
                "force_refresh": force_refresh,
                "freshness_threshold_minutes": freshness_threshold_minutes,
            }

        # Extract incident IDs for processing
        incident_ids = [incident.id for incident in incidents_to_enrich]
        print(f"Processing {len(incident_ids)} incidents with parallel processing.")

        # Process incidents in parallel (existing logic)
        all_enriched_data = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_id = {
                executor.submit(
                    process_single_incident, incident_id, pagerduty_api_key
                ): incident_id
                for incident_id in incident_ids
            }

            for future in concurrent.futures.as_completed(future_to_id):
                incident_id = future_to_id[future]
                try:
                    enriched_data = future.result()
                    if enriched_data:
                        all_enriched_data.append(enriched_data)
                    else:
                        print(f"Worker for incident {incident_id} returned no data.")
                except Exception as exc:
                    print(f"Incident {incident_id} generated an exception: {exc}")

        if not all_enriched_data:
            print("No incidents were successfully enriched.")
            return {
                "success": True,
                "message": "No incidents were successfully enriched.",
                "incidents_updated": 0,
                "force_refresh": force_refresh,
                "freshness_threshold_minutes": freshness_threshold_minutes,
            }

        # Update database
        updated_count = 0
        with Session(engine) as session:
            print(
                f"Updating {len(all_enriched_data)} enriched incidents in the database..."
            )
            for data in all_enriched_data:
                data["last_updated"] = datetime.datetime.now(datetime.timezone.utc)
                session.merge(PagerDutyIncident(**data))
                updated_count += 1
            session.commit()

        print(f"SUCCESS: Processed and updated {updated_count} incidents.")
        return {
            "success": True,
            "incidents_updated": updated_count,
            "force_refresh": force_refresh,
            "freshness_threshold_minutes": freshness_threshold_minutes,
        }

    except Exception as exc:
        error_message = f"An unexpected error occurred in the handler: {exc}"
        print(error_message)
        return {"success": False, "error": str(exc), "type": exc.__class__.__name__}
