from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.events.model import NormalizedEvent


@dataclass(slots=True)
class WebScanningDetector:
    rule_id: str = "web.scanning.high_rate"
    min_requests: int = 20
    min_unique_paths: int = 10
    min_not_found_ratio: float = 0.5

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.source_type != "web_access" or event.source_ip is None:
                continue
            grouped[(event.host, event.source_ip)].append(event)

        alerts: list[Alert] = []
        for (host, source_ip), group in grouped.items():
            request_count = len(group)
            unique_paths = len({e.resource for e in group if e.resource is not None})
            not_found_count = sum(1 for e in group if e.outcome == "404")
            not_found_ratio = not_found_count / request_count if request_count else 0.0

            triggers_volume = (
                request_count >= self.min_requests and unique_paths >= self.min_unique_paths
            )
            triggers_probing = (
                request_count >= self.min_requests and not_found_ratio >= self.min_not_found_ratio
            )
            if not (triggers_volume or triggers_probing):
                continue

            evidence_ids = tuple(sorted(e.event_id for e in group))
            timestamps = [e.timestamp for e in group]
            severity = "high" if request_count >= self.min_requests * 3 else "medium"
            confidence = min(1.0, 0.4 + (unique_paths / max(self.min_unique_paths, 1)) * 0.2)
            alerts.append(
                Alert(
                    alert_id=compute_alert_id(self.rule_id, evidence_ids),
                    rule_id=self.rule_id,
                    severity=severity,
                    confidence=round(confidence, 2),
                    title=f"High-rate web scanning from {source_ip} against {host}",
                    explanation=(
                        f"{request_count} requests from {source_ip} touched {unique_paths} "
                        f"distinct paths with a {not_found_ratio:.0%} not-found ratio, consistent "
                        "with automated endpoint enumeration."
                    ),
                    entities={"host": host, "source_ip": source_ip},
                    evidence_event_ids=evidence_ids,
                    first_seen=min(timestamps),
                    last_seen=max(timestamps),
                    recommended_investigation_steps=(
                        "Review the full request path list from this source IP for scanners.",
                        "Check whether the source IP subsequently authenticated successfully.",
                        "Correlate with WAF or firewall logs for the same window.",
                    ),
                )
            )
        return alerts
