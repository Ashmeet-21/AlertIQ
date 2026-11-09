from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class RawEventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)    # columns are VARCHAR(100)
    source_type: str = Field(min_length=1, max_length=100)
    payload: dict


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    source_type: str
    normalized_payload: dict
    severity: str | None
    status: str
    filter_reason: str | None
    triage_result: dict | None
    priority_score: int | None
    priority_queue: str | None
    analyst_verdict: str | None = None
    analyst_notes: str | None = None
    created_at: datetime


class AlertStats(BaseModel):
    total: int
    p1: int
    p2: int
    p3: int
    p4: int
    queued: int
    triage: int
    escalated: int
    suppressed: int
    error: int = 0


class IngestResponse(BaseModel):
    alert_id: str | None
    status: str          # "queued" | "duplicate"
    message: str


# --- Auth & RBAC ---

class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: str | None = None   # only honoured by admin endpoint


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    role: str


# --- Analyst feedback ---

class VerdictUpdate(BaseModel):
    analyst_verdict: str          # "true_positive" | "false_positive" | "needs_review"
    analyst_notes: str | None = Field(None, max_length=2000)
