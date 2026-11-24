from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingOutput(BaseModel):
    file: str
    line: int = Field(default=1, ge=1)
    severity: FindingSeverity
    category: str
    issue: str
    recommendation: str


class AuditOutput(BaseModel):
    risk_level: RiskLevel
    security_score: int = Field(ge=0, le=100)
    summary: str
    findings: list[FindingOutput] = Field(default_factory=list)


class Finding(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    scan_id: int = SQLField(index=True, foreign_key="scan.id")
    file: str
    line: int = 1
    severity: str
    category: str
    issue: str
    recommendation: str


class Scan(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    repository: str = SQLField(index=True)
    pr_number: int
    pr_title: str
    pr_url: str
    head_sha: str
    risk_level: str = SQLField(index=True)
    security_score: int
    summary: str
    created_at: datetime = SQLField(default_factory=utc_now, index=True)


class ScanResponse(BaseModel):
    id: int
    repository: str
    pr_number: int
    pr_title: str
    pr_url: str
    head_sha: str
    risk_level: str
    security_score: int
    summary: str
    created_at: datetime
    findings: list[FindingOutput]
