from pydantic import BaseModel
from typing import Optional, Dict, Any


class AlertInput(BaseModel):
    title: str
    description: str
    source: str
    severity: str
    event_type: Optional[str] = None
    mitre_technique: Optional[str] = None
    raw_log: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None