from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class EventInput(BaseModel):
    event_type: str
    user: Optional[str] = None
    raw_log: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


class EventBatchInput(BaseModel):
    events: List[EventInput]