import os
import json
import datetime
import time
import requests
import boto3
from sqlalchemy import (
    create_engine,
    Index,
    Column,
    String,
    Float,
    DateTime,
    Table,
    MetaData,
    func,
)
from sqlalchemy.orm import declarative_base, Session

# === SQLAlchemy Setup: Define the Database Table Model ===
Base = declarative_base()


class PagerDutyIncident(Base):
    __tablename__ = "pagerduty_incidents"
    __table_args__ = (Index("ix_pdi_last_updated", "last_updated"),)

    # --- Columns from First Lambda ---
    id = Column(String, primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    severity = Column(String)  # PagerDuty priority (name/summary)
    duration = Column(String)

    # --- Last Updated Timestamp ---
    last_updated = Column(DateTime(timezone=True), index=True)

    # --- Columns used by enrichment (populated by Lambda 2) ---
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
    Incident_Resolution = Column(String)  # <-- added to match latest script

    # Timestamps from timeline and custom fields (populated by Lambda 2)
    trigger_time = Column(DateTime(timezone=True))
    noc_acknowledge_time = Column(DateTime(timezone=True))
    noc_escalate_time = Column(DateTime(timezone=True))
    pythian_sre_acknowledge_time = Column(DateTime(timezone=True))
    pythian_sre_escalate_time = Column(DateTime(timezone=True))
    Time_of_Detection = Column(DateTime(timezone=True))
    Time_of_Resolution = Column(DateTime(timezone=True))
    Time_of_Recovery = Column(DateTime(timezone=True))


# === Database Connection Function ===
def get_engine(secret: dict):
    user = secret["username"]
    password = secret["password"]
    host = secret.get("host")
    port = secret.get("port")
    dbname = os.environ.get("DB_NAME", "postgres")

    url = f"postgresql+pg8000://{user}:{password}@{host}:{port}/{dbname}"
    return create_engine(url, pool_pre_ping=True, future=True)


# === PagerDuty Helper Functions ===
def calculate_duration(start_time_str: str, end_time_str: str) -> str:
    if not end_time_str:
        return "Still Open"

    start_dt = datetime.datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
    end_dt = datetime.datetime.fromisoformat(end_time_str.replace("Z", "+00:00"))
    duration_delta = end_dt - start_dt

    total_seconds = int(duration_delta.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")

    return " ".join(parts) if parts else "0m"


def _pd_headers(api_key: str) -> dict:
    return {
        "Authorization": f"Token token={api_key}",
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
    }


def fetch_pagerduty_incidents(api_key: str, days: int = 30) -> list:
    """
    Fetch incidents created/updated in the past `days`.
    Paginates with 'offset'/'limit'. Simple retry for transient HTTP errors.
    """
    print(f"Fetching incidents from the last {days} days from PagerDuty...")
    now = datetime.datetime.now(datetime.timezone.utc)
    since_time = now - datetime.timedelta(days=days)

    all_incidents = []
    offset = 0
    limit = 100

    while True:
        params = {
            "since": since_time.isoformat(),
            "until": now.isoformat(),
            "limit": limit,
            "offset": offset,
            "total": "true",
        }

        # lightweight retry loop for transient failures
        for attempt in range(3):
            try:
                response = requests.get(
                    "https://api.pagerduty.com/incidents",
                    headers=_pd_headers(api_key),
                    params=params,
                    timeout=30,
                )
                # handle rate limiting explicitly
                if response.status_code == 429:
                    wait = min(2**attempt, 8)
                    print(f"Rate limited (429). Backing off {wait}s...")
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                break
            except requests.exceptions.RequestException as e:
                if attempt == 2:
                    raise
                wait = min(2**attempt, 8)
                print(f"Fetch attempt {attempt+1} failed: {e}. Retrying in {wait}s...")
                time.sleep(wait)

        data = response.json()
        incidents_on_page = data.get("incidents", [])
        if not incidents_on_page:
            # if 'more' is True but we got an empty page, stop to avoid loops
            if data.get("more"):
                print(
                    "Warning: API indicated more results but page was empty. Stopping."
                )
            break

        all_incidents.extend(incidents_on_page)

        # Paging
        more = bool(data.get("more"))
        total = data.get("total")
        print(
            f"Fetched {len(incidents_on_page)} (offset={offset}). Total so far: {len(all_incidents)}"
        )

        if more:
            offset += limit
        else:
            # as a fallback, if total present, verify we fetched all
            if total is not None and len(all_incidents) < int(total):
                offset += limit
                continue
            break

    print(f"Total incidents fetched: {len(all_incidents)}")
    return all_incidents


# === AWS Secrets Manager Client ===
secrets_client = boto3.client("secretsmanager")


# === Main Lambda Handler ===
def lambda_handler(event, context):
    try:
        print("=== PagerDuty Incident Ingestion Lambda Started ===")

        # Extract parameters from event
        force_refresh = event.get("force_refresh", False)
        freshness_threshold_minutes = event.get(
            "freshness_threshold_minutes", 30
        )  # Default 30 minutes
        days = event.get("days", 30)  # Default to last 30 days

        print(f"Force refresh: {force_refresh}")
        print(f"Freshness threshold: {freshness_threshold_minutes} minutes")
        print(f"Window (days): {days}")

        # Get secrets and database connection
        pagerduty_secret_payload = secrets_client.get_secret_value(
            SecretId="pagerduty/API_KEY"
        )
        pagerduty_secret = json.loads(pagerduty_secret_payload["SecretString"])
        pagerduty_api_key = pagerduty_secret.get("API_KEY")
        if not pagerduty_api_key:
            raise KeyError(
                "Secret from Secrets Manager does not contain the key 'API_KEY'"
            )

        db_secret_arn = os.environ["DB_SECRET_ARN"]
        db_secret_payload = secrets_client.get_secret_value(SecretId=db_secret_arn)
        db_secret = json.loads(db_secret_payload["SecretString"])

        engine = get_engine(db_secret)
        Base.metadata.create_all(engine)

        # Ensure index exists
        meta = MetaData()
        tbl = Table("pagerduty_incidents", meta, autoload_with=engine)
        idx = Index("ix_pdi_last_updated", tbl.c.last_updated)
        idx.create(bind=engine, checkfirst=True)

        # Freshness gate: skip if recently updated (unless force_refresh)
        if not force_refresh:
            with Session(engine) as session:
                latest_update = session.query(
                    func.max(PagerDutyIncident.last_updated)
                ).scalar()
                if latest_update:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    minutes_since_update = (now - latest_update).total_seconds() / 60
                    if minutes_since_update < freshness_threshold_minutes:
                        print(
                            f"Data is fresh (updated {minutes_since_update:.1f} minutes ago). Skipping refresh."
                        )
                        return {
                            "success": True,
                            "skipped": True,
                            "reason": "data_is_fresh",
                            "force_refresh": False,  # unchanged here
                            "freshness_threshold_minutes": freshness_threshold_minutes,
                            "minutes_since_update": round(minutes_since_update, 1),
                            "incidents_processed": 0,
                        }

        # Proceed with normal processing
        # Important: set force_refresh True so downstream steps will run
        force_refresh = True

        incidents = fetch_pagerduty_incidents(pagerduty_api_key, days=days)
        if not incidents:
            print("No incidents returned by PagerDuty.")
            return {
                "success": True,
                "incidents_processed": 0,
                "message": "No incidents found in the requested window.",
                "force_refresh": force_refresh,
                "freshness_threshold_minutes": freshness_threshold_minutes,
            }

        print(
            f"Fetched {len(incidents)} incidents from PagerDuty. Upserting into database..."
        )

        # Process and save incidents
        now_ts = datetime.datetime.now(datetime.timezone.utc)
        upserted = 0
        with Session(engine) as session:
            for incident_data in incidents:
                created_at_raw = incident_data.get("created_at")
                resolved_at_raw = incident_data.get("resolved_at")

                created_at = (
                    datetime.datetime.fromisoformat(
                        created_at_raw.replace("Z", "+00:00")
                    )
                    if created_at_raw
                    else now_ts
                )

                priority = incident_data.get("priority") or {}
                severity_val = priority.get("name") or priority.get("summary") or "N/A"

                row = PagerDutyIncident(
                    id=incident_data.get("id"),
                    created_at=created_at,
                    severity=severity_val,
                    duration=calculate_duration(created_at_raw, resolved_at_raw),
                    last_updated=now_ts,
                )
                session.merge(row)
                upserted += 1

            session.commit()

        print(f"SUCCESS: Upserted {upserted} incidents.")
        return {
            "success": True,
            "force_refresh": force_refresh,
            "freshness_threshold_minutes": freshness_threshold_minutes,
            "incidents_processed": upserted,
        }

    except Exception as exc:
        error_message = f"An error occurred: {exc}"
        print(error_message)
        return {"success": False, "error": str(exc), "type": exc.__class__.__name__}
