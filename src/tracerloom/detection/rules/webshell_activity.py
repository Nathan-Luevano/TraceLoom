from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.events.model import NormalizedEvent

_COMMAND_PARAM_PATTERN = re.compile(r"(?i)[?&](cmd|exec|shell|system|passthru|eval)\s*=")
_SHELL_METACHARACTER_PATTERN = re.compile(r"[;&|`]|\$\(")
_SCRIPTLIKE_UPLOAD_PATTERN = re.compile(r"(?i)/(uploads?|tmp|cache)/[^?]*\.(php|jsp|asp|cgi)")


@dataclass(slots=True)
class WebshellActivityDetector:
    rule_id: str = "web.webshell.command_heuristic"

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.source_type != "web_access" or event.resource is None:
                continue
            resource = event.resource
            has_command_param = bool(_COMMAND_PARAM_PATTERN.search(resource))
            has_shell_metachar = bool(_SHELL_METACHARACTER_PATTERN.search(resource))
            has_scriptlike_upload = bool(_SCRIPTLIKE_UPLOAD_PATTERN.search(resource))

            signal_count = sum([has_command_param, has_shell_metachar, has_scriptlike_upload])
            if signal_count == 0 or not (has_command_param or has_shell_metachar):
                continue

            evidence_ids = (event.event_id,)
            confidence = min(1.0, 0.4 + 0.25 * signal_count)
            alerts.append(
                Alert(
                    alert_id=compute_alert_id(self.rule_id, evidence_ids),
                    rule_id=self.rule_id,
                    severity="high" if signal_count >= 2 else "medium",
                    confidence=round(confidence, 2),
                    title=f"Webshell-like command activity against {event.host}",
                    explanation=(
                        f"Request to {resource!r} from {event.source_ip} exhibits "
                        f"{signal_count} webshell heuristic signal(s): command-style query "
                        "parameters, shell metacharacters, or a script under an upload/temp path."
                    ),
                    entities={"host": event.host, "source_ip": event.source_ip or "unknown"},
                    evidence_event_ids=evidence_ids,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    recommended_investigation_steps=(
                        "Inspect the uploaded/served file on disk for webshell code.",
                        "Review the process tree spawned by the web server around this timestamp.",
                        "Search for repeated requests to the same resource from other source IPs.",
                    ),
                )
            )
        return alerts
