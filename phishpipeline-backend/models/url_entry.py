from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class URLEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    url: str
    source: str
    timestamp: datetime
    status: str = "pending"
    label: Optional[str] = None
    confidence: Optional[float] = None
    stage: Optional[str] = None
    suspicion_score: Optional[int] = None
    true_label: Optional[str] = None
    labeled_by: Optional[str] = None
    labeled_at: Optional[datetime] = None
    reported_at: Optional[datetime] = None
    polling_status: str = "not_started"
    last_polled_at: Optional[datetime] = None
    takedown_at: Optional[datetime] = None
    time_to_takedown_mins: Optional[int] = None
    attack_category: Optional[str] = None
