from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.events.model import NormalizedEvent

_SENSITIVE_PATTERN = re.compile(
    r"(?i)(shadow|/etc/passwd|id_rsa|\.ssh/|gpg|private[-_]?key|cracklib|/etc/sudoers)"
)


@dataclass(slots=True)
class PrivilegedAccessDetector:
    rule_id: str = "privilege.sensitive_access.command_or_file"

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.source_type not in {"auth", "audit"}:
                continue
            candidate_text = " ".join(filter(None, [event.resource, event.process]))
            if not _SENSITIVE_PATTERN.search(candidate_text):
                continue

            evidence_ids = (event.event_id,)
            alerts.append(
                Alert(
                    alert_id=compute_alert_id(self.rule_id, evidence_ids),
                    rule_id=self.rule_id,
                    severity="high",
                    confidence=0.65,
                    title=f"Privileged command or sensitive file access on {event.host}",
                    explanation=(
                        f"Principal {event.principal or 'unknown'} triggered an event referencing "
                        f"a sensitive resource ({candidate_text!r}) via {event.source_type} on "
                        f"{event.host}."
                    ),
                    entities={
                        "host": event.host,
                        "principal": event.principal or "unknown",
                    },
                    evidence_event_ids=evidence_ids,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    recommended_investigation_steps=(
                        "Confirm whether this access matches a known administrative task.",
                        "Check the originating session for prior anomalous authentication.",
                        "Review file integrity monitoring output for the referenced path.",
                    ),
                )
            )
        return alerts
