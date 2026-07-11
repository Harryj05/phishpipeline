import os

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# On Railway, set DATABASE_PATH=/data/phishpipeline.db (with a persistent
# volume mounted at /data) so the database survives restarts.
_DB_PATH = os.environ.get("DATABASE_PATH", "./phishpipeline.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class URLQueue(Base):
    __tablename__ = "url_queue"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    source = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    status = Column(String, nullable=False, default="pending")
    label = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    stage = Column(String, nullable=True)
    suspicion_score = Column(Integer, nullable=True)
    true_label = Column(String, nullable=True)
    labeled_by = Column(String, nullable=True)
    labeled_at = Column(DateTime, nullable=True)
    reported_at = Column(DateTime, nullable=True)
    polling_status = Column(String, nullable=False, default="not_started")
    last_polled_at = Column(DateTime, nullable=True)
    takedown_at = Column(DateTime, nullable=True)
    time_to_takedown_mins = Column(Integer, nullable=True)
    attack_category = Column(String, nullable=True)


class RetrainQueue(Base):
    __tablename__ = "retrain_queue"

    id = Column(Integer, primary_key=True, index=True)
    triggered_at = Column(DateTime, nullable=False)
    fp_count = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    url_queue_id = Column(Integer, ForeignKey("url_queue.id"), nullable=False)
    channel = Column(String, nullable=False)  # gsb|phishtank|openphish|registrar
    status = Column(String, nullable=False, default="pending")
    submitted_at = Column(DateTime, nullable=True)
    response_code = Column(Integer, nullable=True)
    response_body = Column(String, nullable=True)
    error_message = Column(String, nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
