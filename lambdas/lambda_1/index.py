import os, json, uuid, datetime
import boto3
from sqlalchemy import create_engine, Column, DateTime, Uuid
from sqlalchemy.orm import declarative_base, Session

Base = declarative_base()


class Demo(Base):
    __tablename__ = "demo"
    id = Column(Uuid, primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


def get_engine(secret: dict):
    user = secret["username"]
    password = secret["password"]
    host = secret.get("host")
    port = secret.get("port")
    dbname = "postgres"  # Hardcoded for simplicity, can be changed as needed

    url = f"postgresql+pg8000://{user}:{password}@{host}:{port}/{dbname}"
    return create_engine(url, pool_pre_ping=True, future=True)


secrets_client = boto3.client("secretsmanager")
_secret_arn = os.environ["DB_SECRET_ARN"]


def lambda_handler(event, context):
    try:
        print("=== Lambda received event ===")
        print(json.dumps(event, indent=2, default=str))

        secret = json.loads(
            secrets_client.get_secret_value(SecretId=_secret_arn)["SecretString"]
        )
        engine = get_engine(secret)
        Base.metadata.create_all(engine)

        new_row_id = uuid.uuid4()

        # === TRANSACTION 1: THE WRITE ===
        # We use a 'try' block just for the write operation.
        try:
            with Session(engine) as session:
                new_row = Demo(
                    id=new_row_id,
                    created_at=datetime.datetime.now(datetime.timezone.utc),
                )
                session.add(new_row)
                session.commit()
                print(f"DEBUG: 'commit' was called for ID: {new_row_id}")
        except Exception as e:
            # If the commit itself fails, we'll see this error.
            raise RuntimeError(f"Database WRITE operation failed: {e}")

        # === TRANSACTION 2: THE VERIFICATION READ ===
        # We now create a brand new session to verify the write.
        # This forces a real database query and bypasses the cache of the first session.
        latest = None
        with Session(engine) as session:
            print(f"DEBUG: Attempting to read back ID {new_row_id} in a NEW session.")
            # session.get is the most efficient way to query by primary key.
            latest = session.get(Demo, new_row_id)

        # === THE VERDICT ===
        if not latest:
            # If 'latest' is None, it PROVES the first transaction was rolled back.
            print(
                "!!! CRITICAL FAILURE: Row was NOT found after commit. Transaction was rolled back. !!!"
            )
            raise RuntimeError(
                "Data verification failed. The row was not found in the database after the commit call."
            )

        print("SUCCESS: Row was written and verified in a separate transaction.")
        return {
            "success": True,
            "row": {
                "id": str(latest.id),
                "created_at": latest.created_at.isoformat() + "Z",
            },
        }

    except Exception as exc:
        print(f"Error: {exc}")
        return {
            "success": False,
            "error": str(exc),
            "type": exc.__class__.__name__,
            "error_from": "Lambda 1",
        }
