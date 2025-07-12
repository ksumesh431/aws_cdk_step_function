import os, json, uuid, datetime
import boto3
from sqlalchemy import create_engine, Column, DateTime, Uuid
from sqlalchemy.orm import declarative_base, Session

# ----------  SQLAlchemy setup  ----------
Base = declarative_base()


class Demo(Base):
    __tablename__ = "demo"
    id = Column(Uuid, primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


def get_engine(secret):
    # Build a pg8000 URL:  postgresql+pg8000://user:pass@host:port/dbname
    url = "postgresql+pg8000://{username}:{password}@{host}:{port}/{dbname}".format(
        **secret
    )
    return create_engine(url, pool_pre_ping=True, future=True)


# ----------  Lambda handler  ----------
secrets = boto3.client("secretsmanager")
_secret_arn = os.environ["DB_SECRET_ARN"]


def lambda_handler(event, context):
    try:
        secret = json.loads(
            secrets.get_secret_value(SecretId=_secret_arn)["SecretString"]
        )
        engine = get_engine(secret)

        Base.metadata.create_all(engine)  # auto-create table first time

        with Session(engine) as session:
            row = Demo(id=uuid.uuid4(), created_at=datetime.datetime.utcnow())
            session.add(row)
            session.commit()
            # read it back
            latest = session.query(Demo).order_by(Demo.created_at.desc()).first()

        return {
            "success": True,
            "row": {
                "id": str(latest.id),
                "created_at": latest.created_at.isoformat() + "Z",
            },
        }

    except Exception as exc:
        return {"success": False, "error": str(exc), "type": exc.__class__.__name__}
