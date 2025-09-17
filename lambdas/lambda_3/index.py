import os, json, datetime
import boto3
from typing import Dict, Any, List
from sqlalchemy import create_engine, func, or_, and_, case, extract
from sqlalchemy.orm import Session, declarative_base
from sqlalchemy import Column, String, Float, DateTime, Index

# ---------- ORM model ----------
Base = declarative_base()


class PagerDutyIncident(Base):
    __tablename__ = "pagerduty_incidents"
    __table_args__ = (Index("ix_pdi_last_updated", "last_updated"),)

    id = Column(String, primary_key=True)
    created_at = Column(DateTime(timezone=True))
    severity = Column(String)
    duration = Column(String)

    last_updated = Column(DateTime(timezone=True), index=True)

    incident_summary = Column(String)
    ack_noc_minutes = Column(Float)
    escalate_noc_minutes = Column(Float)
    ack_pythian_sre_minutes = Column(Float)
    escalate_pythian_sre_minutes = Column(Float)
    detect_time_minutes = Column(Float)
    restore_time_minutes = Column(Float)
    recover_time_minutes = Column(Float)

    # enums/flags stored as strings
    Engineering_time_spent_on_incident = Column(String)
    Number_of_engineers = Column(String)
    Entity = Column(String)
    Platform = Column(String)
    Customer_Experience = Column(String)
    Incident_Category = Column(String)
    incident_detection_type_auto = Column(String)  # "TRUE"/"FALSE"
    Pythian_resolution_without_lytx = Column(String)  # "TRUE"/"FALSE"
    Alert_Autoresolved = Column(String)
    Incident_Resolution = Column(String)

    # timestamps
    trigger_time = Column(DateTime(timezone=True))
    noc_acknowledge_time = Column(DateTime(timezone=True))
    noc_escalate_time = Column(DateTime(timezone=True))
    pythian_sre_acknowledge_time = Column(DateTime(timezone=True))
    pythian_sre_escalate_time = Column(DateTime(timezone=True))
    Time_of_Detection = Column("Time_of_Detection", DateTime(timezone=True))
    Time_of_Resolution = Column("Time_of_Resolution", DateTime(timezone=True))
    Time_of_Recovery = Column("Time_of_Recovery", DateTime(timezone=True))


# ---------- engine helper ----------
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


secrets = boto3.client("secretsmanager")

ENTITIES = {"WNS", "Drivecam", "Surfsight"}
PLATFORMS = {"AWS", "Onprem", "Thirdparty"}
CATEGORIES = {
    "Release",
    "Deficient_Maintainence",
    "Feature_Toggle",
    "Security",
    "Soft_Misconfiguration",
    "External_Service",
    "Platform_Misconfiguration",
    "Service_Decommission",
    "Saturation",
}
BOOL_STR = {"TRUE", "FALSE"}


def lambda_handler(event, context):
    try:
        print("=== PagerDuty Data Validation Lambda Started ===")

        # Extract parameters from event
        force_refresh = event.get("force_refresh", False)
        freshness_threshold_minutes = event.get("freshness_threshold_minutes", 30)
        validation_threshold_minutes = event.get("validation_threshold_minutes", 15)

        print(f"Force refresh: {force_refresh}")
        print(f"Freshness threshold: {freshness_threshold_minutes} minutes")
        print(f"Validation threshold: {validation_threshold_minutes} minutes")

        # Get database connection
        db_secret_arn = os.environ["DB_SECRET_ARN"]
        secret = json.loads(
            secrets.get_secret_value(SecretId=db_secret_arn)["SecretString"]
        )
        engine = get_engine(secret)

        now = datetime.datetime.now(datetime.timezone.utc)
        issues: List[Dict[str, Any]] = []
        failed_checks = 0

        with Session(engine) as s:
            P = PagerDutyIncident  # alias

            # Optional quick-exit on recent updates (skip validation)
            if not force_refresh:
                latest_update = s.query(func.max(P.last_updated)).scalar()
                if latest_update:
                    minutes_since_update = (now - latest_update).total_seconds() / 60
                    if minutes_since_update < validation_threshold_minutes:
                        print(
                            f"Data was recently updated ({minutes_since_update:.1f} minutes ago). Skipping validation."
                        )
                        return {
                            "success": True,
                            "skipped": True,
                            "reason": "recently_validated",
                            "minutes_since_update": round(minutes_since_update, 1),
                            "failed_checks": 0,
                            "issues": [],
                            "validated_at": now.isoformat(),
                        }

            print("Proceeding with data validation checks...")

            # 1) Missing enrichments
            missing = (
                s.query(func.count())
                .filter(
                    P.severity != "N/A",
                    P.incident_summary.is_(None),
                )
                .scalar()
            )
            if missing and missing > 0:
                failed_checks += 1
                issues.append({"check": "enrichment_missing", "count": int(missing)})

            # 2) Duplicates (total - distinct)
            dup = s.query((func.count(P.id) - func.count(func.distinct(P.id)))).scalar()
            if dup and dup > 0:
                failed_checks += 1
                issues.append({"check": "duplicates", "count": int(dup)})

            # 3) Enumerations invalid
            bad_enum = (
                s.query(func.count())
                .filter(
                    or_(
                        and_(P.Entity.isnot(None), ~P.Entity.in_(list(ENTITIES))),
                        and_(P.Platform.isnot(None), ~P.Platform.in_(list(PLATFORMS))),
                        and_(
                            P.Incident_Category.isnot(None),
                            ~P.Incident_Category.in_(list(CATEGORIES)),
                        ),
                    )
                )
                .scalar()
            )
            if bad_enum and bad_enum > 0:
                failed_checks += 1
                issues.append({"check": "enum_invalid", "count": int(bad_enum)})

            # 4) Boolean-string fields invalid (if present, must be "TRUE"/"FALSE")
            invalid_bool = (
                s.query(func.count())
                .filter(
                    or_(
                        and_(
                            P.incident_detection_type_auto.isnot(None),
                            ~func.upper(P.incident_detection_type_auto).in_(
                                list(BOOL_STR)
                            ),
                        ),
                        and_(
                            P.Pythian_resolution_without_lytx.isnot(None),
                            ~func.upper(P.Pythian_resolution_without_lytx).in_(
                                list(BOOL_STR)
                            ),
                        ),
                    )
                )
                .scalar()
            )
            if invalid_bool and invalid_bool > 0:
                failed_checks += 1
                issues.append(
                    {"check": "invalid_boolean_strings", "count": int(invalid_bool)}
                )

            # 5) Negative minutes
            negative = (
                s.query(func.count())
                .filter(
                    or_(
                        func.coalesce(P.ack_noc_minutes, 0) < 0,
                        func.coalesce(P.escalate_noc_minutes, 0) < 0,
                        func.coalesce(P.ack_pythian_sre_minutes, 0) < 0,
                        func.coalesce(P.escalate_pythian_sre_minutes, 0) < 0,
                        func.coalesce(P.detect_time_minutes, 0) < 0,
                        func.coalesce(P.restore_time_minutes, 0) < 0,
                        func.coalesce(P.recover_time_minutes, 0) < 0,
                    )
                )
                .scalar()
            )
            if negative and negative > 0:
                failed_checks += 1
                issues.append({"check": "negative_durations", "count": int(negative)})

            # 6) Timestamp ordering violations
            ordering = (
                s.query(func.count())
                .filter(
                    or_(
                        and_(
                            P.Time_of_Detection.isnot(None),
                            P.trigger_time.isnot(None),
                            P.Time_of_Detection < P.trigger_time,
                        ),
                        and_(
                            P.Time_of_Resolution.isnot(None),
                            P.Time_of_Detection.isnot(None),
                            P.Time_of_Resolution < P.Time_of_Detection,
                        ),
                        and_(
                            P.Time_of_Recovery.isnot(None),
                            P.Time_of_Resolution.isnot(None),
                            P.Time_of_Recovery < P.Time_of_Resolution,
                        ),
                    )
                )
                .scalar()
            )
            if ordering and ordering > 0:
                failed_checks += 1
                issues.append({"check": "timestamp_ordering", "count": int(ordering)})

            # 6a) Recovery present without Resolution present
            recovery_wo_resolution = (
                s.query(func.count())
                .filter(
                    and_(
                        P.Time_of_Recovery.isnot(None),
                        P.Time_of_Resolution.is_(None),
                    )
                )
                .scalar()
            )
            if recovery_wo_resolution and recovery_wo_resolution > 0:
                failed_checks += 1
                issues.append(
                    {
                        "check": "recovery_without_resolution",
                        "count": int(recovery_wo_resolution),
                    }
                )

            # 7) Derived minutes drift (use tolerance to ignore tiny rounding errors)
            tol = 0.01  # minutes (~0.6 seconds)

            diff_ack = case(
                (
                    and_(
                        P.trigger_time.isnot(None), P.noc_acknowledge_time.isnot(None)
                    ),
                    func.abs(
                        (
                            extract("epoch", P.noc_acknowledge_time - P.trigger_time)
                            / 60.0
                        )
                        - P.ack_noc_minutes
                    ),
                ),
                else_=0.0,
            )
            diff_escalate_noc = case(
                (
                    and_(
                        P.noc_acknowledge_time.isnot(None),
                        P.noc_escalate_time.isnot(None),
                    ),
                    func.abs(
                        (
                            extract(
                                "epoch", P.noc_escalate_time - P.noc_acknowledge_time
                            )
                            / 60.0
                        )
                        - P.escalate_noc_minutes
                    ),
                ),
                else_=0.0,
            )
            diff_ack_pythian = case(
                (
                    and_(
                        P.noc_escalate_time.isnot(None),
                        P.pythian_sre_acknowledge_time.isnot(None),
                    ),
                    func.abs(
                        (
                            extract(
                                "epoch",
                                P.pythian_sre_acknowledge_time - P.noc_escalate_time,
                            )
                            / 60.0
                        )
                        - P.ack_pythian_sre_minutes
                    ),
                ),
                else_=0.0,
            )
            diff_escalate_pythian = case(
                (
                    and_(
                        P.pythian_sre_acknowledge_time.isnot(None),
                        P.pythian_sre_escalate_time.isnot(None),
                    ),
                    func.abs(
                        (
                            extract(
                                "epoch",
                                P.pythian_sre_escalate_time
                                - P.pythian_sre_acknowledge_time,
                            )
                            / 60.0
                        )
                        - P.escalate_pythian_sre_minutes
                    ),
                ),
                else_=0.0,
            )
            diff_detect = case(
                (
                    and_(P.Time_of_Detection.isnot(None), P.trigger_time.isnot(None)),
                    func.abs(
                        (extract("epoch", P.Time_of_Detection - P.trigger_time) / 60.0)
                        - P.detect_time_minutes
                    ),
                ),
                else_=0.0,
            )
            diff_restore = case(
                (
                    and_(P.Time_of_Resolution.isnot(None), P.trigger_time.isnot(None)),
                    func.abs(
                        (extract("epoch", P.Time_of_Resolution - P.trigger_time) / 60.0)
                        - P.restore_time_minutes
                    ),
                ),
                else_=0.0,
            )
            # IMPORTANT: Recover time is Recovery - Resolution (not Trigger)
            diff_recover = case(
                (
                    and_(
                        P.Time_of_Recovery.isnot(None), P.Time_of_Resolution.isnot(None)
                    ),
                    func.abs(
                        (
                            extract("epoch", P.Time_of_Recovery - P.Time_of_Resolution)
                            / 60.0
                        )
                        - P.recover_time_minutes
                    ),
                ),
                else_=0.0,
            )

            # subquery with diffs
            subq = s.query(
                P.id.label("id"),
                diff_ack.label("diff_ack"),
                diff_escalate_noc.label("diff_escalate_noc"),
                diff_ack_pythian.label("diff_ack_pythian"),
                diff_escalate_pythian.label("diff_escalate_pythian"),
                diff_detect.label("diff_detect"),
                diff_restore.label("diff_restore"),
                diff_recover.label("diff_recover"),
            ).subquery()

            drift = (
                s.query(func.count())
                .select_from(subq)
                .filter(
                    or_(
                        subq.c.diff_ack > tol,
                        subq.c.diff_escalate_noc > tol,
                        subq.c.diff_ack_pythian > tol,
                        subq.c.diff_escalate_pythian > tol,
                        subq.c.diff_detect > tol,
                        subq.c.diff_restore > tol,
                        subq.c.diff_recover > tol,
                    )
                )
                .scalar()
            )

            if drift and drift > 0:
                failed_checks += 1
                issues.append({"check": "derived_minutes_drift", "count": int(drift)})

            # Get total record count for context
            total_records = s.query(func.count(P.id)).scalar()

        print(
            f"Validation completed. Failed checks: {failed_checks}, Total records: {total_records}"
        )

        if issues:
            print("Issues found:")
            for issue in issues:
                print(f"  - {issue['check']}: {issue.get('count', 'N/A')}")

        return {
            "success": True,  # Keep Step Functions flowing; handle failures via counts
            "skipped": False,
            "failed_checks": failed_checks,
            "issues": issues,
            "validated_at": now.isoformat(),
            "total_records": total_records,
            "validation_summary": {
                "no_missing_enrichments": not any(
                    i["check"] == "enrichment_missing" for i in issues
                ),
                "no_duplicates": not any(i["check"] == "duplicates" for i in issues),
                "field_values_valid": not any(
                    i["check"] == "enum_invalid" for i in issues
                ),
                "boolean_strings_valid": not any(
                    i["check"] == "invalid_boolean_strings" for i in issues
                ),
                "no_negative_durations": not any(
                    i["check"] == "negative_durations" for i in issues
                ),
                "timestamps_ordered": not any(
                    i["check"] == "timestamp_ordering" for i in issues
                ),
                "no_recovery_without_resolution": not any(
                    i["check"] == "recovery_without_resolution" for i in issues
                ),
                "derived_minutes_accurate": not any(
                    i["check"] == "derived_minutes_drift" for i in issues
                ),
            },
        }

        # If you want Step Functions to branch on validation result, you could instead:
        # return {"success": failed_checks == 0, "failed_checks": failed_checks, "issues": issues, "validated_at": now.isoformat()}

    except Exception as e:
        print(f"Validation lambda error: {e}")
        return {"success": False, "error": str(e), "type": e.__class__.__name__}
