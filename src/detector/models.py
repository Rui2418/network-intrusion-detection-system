from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Alert:
    alert_type: str
    category: str
    source_ip: str
    target: str
    level: str
    score: int
    confidence: float
    evidence: str
    rule_id: str
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    matched_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class Incident:
    source_ip: str
    stages: tuple[str, ...]
    level: str
    score: int
    confidence: float
    alert_types: tuple[str, ...]
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: str = ""
    recommended_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class BaselineMetric:
    source_ip: str
    metric: str
    value: float
    threshold: float
    evidence: str


@dataclass(frozen=True)
class AnalysisResult:
    events: int
    alerts: list[Alert]
    incidents: list[Incident]
    summary: dict[str, object]
    baseline: dict[str, object]
    metadata: dict[str, object]
    source: str = ""
    recommendations: list[dict[str, object]] = field(default_factory=list)
