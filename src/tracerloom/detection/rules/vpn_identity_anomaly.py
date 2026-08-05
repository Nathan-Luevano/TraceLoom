from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.events.model import NormalizedEvent


@dataclass(slots=True)
class VpnIdentityAnomalyDetector:
    rule_id: str = "vpn.identity.baseline_deviation"
    baseline_session_count: int = 3

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.source_type != "vpn" or event.principal is None or event.source_ip is None:
                continue
            grouped[event.principal].append(event)

        alerts: list[Alert] = []
        for principal, group in grouped.items():
            ordered = sorted(group, key=lambda e: e.timestamp)
            baseline_ips: set[str] = set()
            sessions_seen = 0
            for event in ordered:
                assert event.source_ip is not None
                if sessions_seen < self.baseline_session_count:
                    baseline_ips.add(event.source_ip)
                    sessions_seen += 1
                    continue
                if event.source_ip in baseline_ips:
                    continue

                evidence_ids = (event.event_id,)
                alerts.append(
                    Alert(
                        alert_id=compute_alert_id(self.rule_id, evidence_ids),
                        rule_id=self.rule_id,
                        severity="medium",
                        confidence=0.55,
                        title=f"VPN source IP deviates from {principal}'s established baseline",
                        explanation=(
                            f"{principal} connected from {event.source_ip}, which is outside "
                            f"the {len(baseline_ips)} source IP(s) previously established as "
                            "this subject's own baseline, rather than an absolute allowlist."
                        ),
                        entities={"principal": principal, "source_ip": event.source_ip},
                        evidence_event_ids=evidence_ids,
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                        recommended_investigation_steps=(
                            "Confirm with the subject whether this connection was expected.",
                            "Check for concurrent sessions from the baseline IPs and this new IP.",
                            "Review subsequent activity performed under this VPN session.",
                        ),
                    )
                )
        return alerts
