from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.events.model import NormalizedEvent

_WEB_SERVICE_ACCOUNT_PATTERN = re.compile(
    r"(?i)^(www-data|apache|httpd|nginx|nobody|tomcat\d*|wp-?user)$"
)


@dataclass(slots=True)
class WebServiceUserSwitchDetector:
    rule_id: str = "auth.escalation.user_switch_from_web_context"

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.source_type != "auth" or event.action != "user_switch":
                continue
            if event.outcome != "success":
                continue
            actor = event.resource
            if actor is None or not _WEB_SERVICE_ACCOUNT_PATTERN.match(actor):
                continue

            evidence_ids = (event.event_id,)
            alerts.append(
                Alert(
                    alert_id=compute_alert_id(self.rule_id, evidence_ids),
                    rule_id=self.rule_id,
                    severity="critical",
                    confidence=0.75,
                    title=(
                        f"User switch to {event.principal} originating from "
                        f"web-service account {actor}"
                    ),
                    explanation=(
                        f"Account {actor}, which matches known web-service process identities, "
                        f"successfully switched to {event.principal} on {event.host}. Web "
                        "service accounts legitimately switching users is rare and often "
                        "indicates command execution through a compromised web application."
                    ),
                    entities={"host": event.host, "principal": event.principal or "unknown"},
                    evidence_event_ids=evidence_ids,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    recommended_investigation_steps=(
                        "Identify the parent process of the su/sudo invocation.",
                        "Correlate with web access logs on the same host in the preceding minutes.",
                        "Check for webshell or command-injection heuristics on the same host.",
                    ),
                )
            )
        return alerts
