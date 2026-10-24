from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AuditConfig:
    output_dir: Path
    max_internal_links: int = 20
    request_delay_seconds: float = 1.0
    timeout_seconds: float = 15.0
    retries: int = 2
    user_agent: str = "MINAS-Website-Auditor/1.0 (+nonintrusive-public-audit)"
    lighthouse: bool = True
    screenshots: bool = True
    max_concurrency: int = 2
    authorization_file: Path | None = None
    terms_confirmed: bool = False
    allow_private_hosts: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.max_internal_links <= 100:
            raise ValueError("max_internal_links must be between 1 and 100")
        if self.request_delay_seconds < 0.25:
            raise ValueError("request_delay_seconds must be at least 0.25")
        if not 3 <= self.timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 3 and 120")
        if not 1 <= self.max_concurrency <= 5:
            raise ValueError("max_concurrency must be between 1 and 5")

