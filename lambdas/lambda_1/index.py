import os
import json
import datetime
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


def fetch_pagerduty_incidents(api_key: str, days: int = 30) -> list:
    print(f"Fetching incidents from the last {days} days from PagerDuty...")
    now = datetime.datetime.now(datetime.timezone.utc)
    since_time = now - datetime.timedelta(days=days)

    headers = {
        "Authorization": f"Token token={api_key}",
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
    }

    # --- Pagination Logic ---
    all_incidents = []
    offset = 0
    limit = 100  # The number of results to get per API call

    while True:
        params = {
            "since": since_time.isoformat(),
            "until": now.isoformat(),
            "limit": limit,
            "offset": offset,
        }

        response = requests.get(
            "https://api.pagerduty.com/incidents",
            headers=headers,
            params=params,
            timeout=20,
        )
        response.raise_for_status()
        json_response = response.json()

        # Add the fetched incidents to our master list
        incidents_on_page = json_response.get("incidents", [])
        if not incidents_on_page:
            break  # Stop if a page is empty for any reason

        all_incidents.extend(incidents_on_page)

        # Check if there are more pages to fetch
        if not json_response.get("more"):
            break  # Exit the loop if the 'more' flag is false or missing

        # Prepare for the next iteration
        offset += limit
        print(f"Fetched {len(all_incidents)} incidents so far, getting next page...")

    return all_incidents


# === AWS Secrets Manager Client ===
secrets_client = boto3.client("secretsmanager")


# === Main Lambda Handler ===
def lambda_handler(event, context):
    try:
        print("=== PagerDuty Incident Ingestion Lambda Started ===")

        # 1. Fetch PagerDuty API Key from AWS Secrets Manager
        pagerduty_secret_payload = secrets_client.get_secret_value(SecretId="pagerduty")
        pagerduty_secret = json.loads(pagerduty_secret_payload["SecretString"])
        pagerduty_api_key = pagerduty_secret.get("PAGERDUTY_API_KEY")

        if not pagerduty_api_key:
            raise KeyError(
                "Secret from Secrets Manager does not contain the key 'PAGERDUTY_API_KEY'"
            )

        # 2. Get Database Credentials from AWS Secrets Manager
        db_secret_arn = os.environ["DB_SECRET_ARN"]
        print(
            f"Fetching Database credentials from Secrets Manager ARN: {db_secret_arn}"
        )
        db_secret_payload = secrets_client.get_secret_value(SecretId=db_secret_arn)
        db_secret = json.loads(db_secret_payload["SecretString"])

        # 3. Connect to the Database and Create Table if it doesn't exist
        engine = get_engine(db_secret)
        Base.metadata.create_all(engine)

        ###################################################################
        ################ code to set last_updated as index ################
        # reflect just that one table
        meta = MetaData()
        tbl = Table("pagerduty_incidents", meta, autoload_with=engine)

        # define your index
        idx = Index("ix_pdi_last_updated", tbl.c.last_updated)

        # create only if it doesn't exist already
        idx.create(bind=engine, checkfirst=True)
        ################ code to set last_updated as index ################
        ###################################################################

        # 4. Fetch Incidents from PagerDuty API
        incidents = fetch_pagerduty_incidents(pagerduty_api_key)
        if not incidents:
            print("No new incidents found in PagerDuty.")
            return {"success": True, "message": "No new incidents found."}

        print(
            f"Fetched {len(incidents)} incidents from PagerDuty. Processing for database."
        )

        # 5. Process and Save Incidents to the Database
        with Session(engine) as session:
            for incident_data in incidents:
                incident_to_save = PagerDutyIncident(
                    id=incident_data.get("id"),
                    created_at=datetime.datetime.fromisoformat(
                        incident_data.get("created_at").replace("Z", "+00:00")
                    ),
                    severity=(incident_data.get("priority") or {}).get(
                        "summary", "N/A"
                    ),
                    duration=calculate_duration(
                        incident_data.get("created_at"),
                        incident_data.get("resolved_at"),
                    ),
                )
                session.merge(incident_to_save)
            session.commit()

        print(f"SUCCESS: Processed and saved/updated {len(incidents)} incidents.")
        return {"success": True, "incidents_processed": len(incidents)}

    except Exception as exc:
        error_message = f"An error occurred: {exc}"
        print(error_message)
        return {"success": False, "error": str(exc), "type": exc.__class__.__name__}
