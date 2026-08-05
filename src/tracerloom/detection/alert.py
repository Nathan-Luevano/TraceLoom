from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime


def compute_alert_id(rule_id: str, evidence_event_ids: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(rule_id.encode("utf-8"))
    for event_id in sorted(evidence_event_ids):
        digest.update(b"\x00")
        digest.update(event_id.encode("utf-8"))
    return digest.hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    rule_id: str
    severity: str
    confidence: float
    title: str
    explanation: str
    entities: dict[str, str]
    evidence_event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    recommended_investigation_steps: tuple[str, ...]
