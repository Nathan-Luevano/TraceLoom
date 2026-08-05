from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.detection.statistics import shannon_entropy
from tracerloom.events.model import NormalizedEvent


@dataclass(slots=True)
class DnsExfiltrationDetector:
    rule_id: str = "dns.exfiltration.entropy_heuristic"
    min_suspicious_queries: int = 5
    min_label_length: int = 20
    min_entropy_bits_per_char: float = 3.5

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.source_type != "dns" or event.event_type != "dns_query":
                continue
            if event.resource is None or event.source_ip is None:
                continue
            grouped[event.source_ip].append(event)

        alerts: list[Alert] = []
        for source_ip, group in grouped.items():
            suspicious = [e for e in group if self._is_suspicious(e.resource or "")]
            unique_subdomains = len({e.resource for e in suspicious})
            if len(suspicious) < self.min_suspicious_queries:
                continue
            if unique_subdomains < self.min_suspicious_queries:
                continue

            evidence_ids = tuple(sorted(e.event_id for e in suspicious))
            timestamps = [e.timestamp for e in suspicious]
            span_seconds = (max(timestamps) - min(timestamps)).total_seconds()
            frequency = (
                len(suspicious) / span_seconds if span_seconds > 0 else float(len(suspicious))
            )

            alerts.append(
                Alert(
                    alert_id=compute_alert_id(self.rule_id, evidence_ids),
                    rule_id=self.rule_id,
                    severity="high",
                    confidence=min(
                        1.0, 0.5 + unique_subdomains / (self.min_suspicious_queries * 4)
                    ),
                    title=f"Likely DNS exfiltration from {source_ip}",
                    explanation=(
                        f"{len(suspicious)} DNS queries from {source_ip} used high-entropy "
                        f"labels of at least {self.min_label_length} chars across "
                        f"{unique_subdomains} unique subdomains, at roughly {frequency:.2f} "
                        "queries/sec -- consistent with data chunked into DNS labels."
                    ),
                    entities={"source_ip": source_ip},
                    evidence_event_ids=evidence_ids,
                    first_seen=min(timestamps),
                    last_seen=max(timestamps),
                    recommended_investigation_steps=(
                        "Decode the suspicious subdomain labels to check for base32/64 payloads.",
                        "Identify the authoritative nameserver receiving these queries.",
                        "Check the source host for other exfiltration channels in this window.",
                    ),
                )
            )
        return alerts

    def _is_suspicious(self, domain: str) -> bool:
        first_label = domain.split(".")[0]
        if len(first_label) < self.min_label_length:
            return False
        return shannon_entropy(first_label) >= self.min_entropy_bits_per_char
