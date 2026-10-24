from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class Status(StrEnum):
    PASS = "pass"
    WARN = "warning"
    FAIL = "fail"
    INFO = "info"
    SKIPPED = "skipped"
    ERROR = "error"
    UNVERIFIED = "unverified"


@dataclass(slots=True)
class Finding:
    check: str
    status: Status
    summary: str
    evidence: str = ""
    confidence: Confidence = Confidence.HIGH
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass(slots=True)
class AuditResult:
    input_url: str
    final_url: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def finish(self) -> None:
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

