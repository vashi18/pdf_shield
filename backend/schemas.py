from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class RiskReason(BaseModel):
    code: str
    label: str
    points: int
    evidence: str


class IOCOut(BaseModel):
    id: str
    type: str
    value: str
    normalized_value: str
    source: str
    matched: bool = False
    match_details: dict[str, Any] = Field(default_factory=dict)


class AnalysisOut(BaseModel):
    id: str
    filename: str
    size_bytes: int
    sha256: str
    status: str
    parsing_status: str
    risk_score: int
    risk_class: str
    risk_reasons: list[RiskReason]
    metadata: dict[str, Any]
    findings: list[dict[str, Any]]
    limitations: list[str]
    page_count: Optional[int]
    encrypted: Optional[bool]
    created_at: datetime
    iocs: list[IOCOut] = Field(default_factory=list)
    case_id: Optional[str] = None


class CasePatch(BaseModel):
    status: Optional[Literal["New", "In Review", "Resolved", "Archived"]] = None
    analyst_notes: Optional[str] = Field(default=None, max_length=20000)


class OSINTRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    indicator_type: Literal["sha256", "domain", "url", "ip"]
    consent: bool = False
    providers: list[str] = Field(default_factory=list)


class SettingUpdate(BaseModel):
    max_upload_mb: Optional[int] = Field(default=None, ge=1, le=250)
    external_lookup_consent: Optional[bool] = None
    demo_mode: Optional[bool] = None
    theme: Optional[Literal["dark", "light", "system"]] = None
    enabled_providers: Optional[list[str]] = None
    sync_interval_minutes: Optional[int] = Field(default=None, ge=5, le=1440)
