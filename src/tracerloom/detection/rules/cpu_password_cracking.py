from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.events.model import NormalizedEvent


@dataclass(slots=True)
class CpuPasswordCrackingDetector:
    rule_id: str = "host.cpu.sustained_high_load"
    high_pct_threshold: float = 0.85
    min_consecutive_samples: int = 5

    def detect(self, events: Sequence[NormalizedEvent]) -> list[Alert]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.source_type != "monitoring_cpu" or event.outcome is None:
                continue
            grouped[event.host].append(event)

        alerts: list[Alert] = []
        for host, group in grouped.items():
            ordered = sorted(group, key=lambda e: e.timestamp)
            run: list[NormalizedEvent] = []
            for event in ordered:
                pct = self._pct(event)
                if pct is not None and pct >= self.high_pct_threshold:
                    run.append(event)
                else:
                    if len(run) >= self.min_consecutive_samples:
                        alerts.append(self._build_alert(host, run))
                    run = []
            if len(run) >= self.min_consecutive_samples:
                alerts.append(self._build_alert(host, run))
        return alerts

    def _pct(self, event: NormalizedEvent) -> float | None:
        try:
            return float(event.outcome) if event.outcome is not None else None
        except ValueError:
            return None

    def _build_alert(self, host: str, run: list[NormalizedEvent]) -> Alert:
        evidence_ids = tuple(sorted(e.event_id for e in run))
        timestamps = [e.timestamp for e in run]
        average_pct = sum(self._pct(e) or 0.0 for e in run) / len(run)
        return Alert(
            alert_id=compute_alert_id(self.rule_id, evidence_ids),
            rule_id=self.rule_id,
            severity="medium",
            confidence=min(1.0, 0.4 + len(run) / (self.min_consecutive_samples * 4)),
            title=f"Sustained high CPU load on {host} consistent with offline cracking",
            explanation=(
                f"{len(run)} consecutive CPU samples on {host} averaged {average_pct:.0%} "
                "utilization, a pattern consistent with sustained CPU-bound activity such "
                "as password cracking or hashing rather than typical interactive load."
            ),
            entities={"host": host},
            evidence_event_ids=evidence_ids,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            recommended_investigation_steps=(
                "Identify the process responsible for the CPU load during this window.",
                "Check for recently modified password hash files on this host.",
                "Correlate with authentication failures around the same time range.",
            ),
        )
