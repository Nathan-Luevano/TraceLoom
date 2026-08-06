from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from tracerloom.correlation.stages import RULE_STAGE, STAGE_ORDER
from tracerloom.detection.alert import Alert


def _compute_chain_id(alert_ids: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for alert_id in sorted(alert_ids):
        digest.update(alert_id.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class AttackChainAlert:
    chain_id: str
    correlation_key: str
    stages: tuple[str, ...]
    alerts: tuple[Alert, ...]
    first_seen: datetime
    last_seen: datetime


def _correlation_key(alert: Alert) -> str | None:
    for field_name in ("host", "principal", "source_ip"):
        value = alert.entities.get(field_name)
        if value:
            return value
    return None


@dataclass(slots=True)
class CorrelationEngine:
    window: timedelta = timedelta(hours=6)
    min_distinct_stages: int = 2

    def correlate(self, alerts: Sequence[Alert]) -> list[AttackChainAlert]:
        grouped: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            if alert.rule_id not in RULE_STAGE:
                continue
            key = _correlation_key(alert)
            if key is None:
                continue
            grouped[key].append(alert)

        chains: list[AttackChainAlert] = []
        for key, group in grouped.items():
            ordered = sorted(group, key=lambda a: a.first_seen)
            current_window: list[Alert] = []
            window_start: datetime | None = None
            for alert in ordered:
                if window_start is None or alert.first_seen - window_start <= self.window:
                    current_window.append(alert)
                    if window_start is None:
                        window_start = alert.first_seen
                else:
                    chain = self._build_chain(key, current_window)
                    if chain is not None:
                        chains.append(chain)
                    current_window = [alert]
                    window_start = alert.first_seen
            chain = self._build_chain(key, current_window)
            if chain is not None:
                chains.append(chain)
        return chains

    def _build_chain(self, key: str, group: list[Alert]) -> AttackChainAlert | None:
        if not group:
            return None
        stages_present = {RULE_STAGE[a.rule_id] for a in group}
        if len(stages_present) < self.min_distinct_stages:
            return None
        ordered_stages = tuple(sorted(stages_present, key=lambda s: STAGE_ORDER[s]))
        alert_ids = tuple(sorted(a.alert_id for a in group))
        timestamps_first = [a.first_seen for a in group]
        timestamps_last = [a.last_seen for a in group]
        return AttackChainAlert(
            chain_id=_compute_chain_id(alert_ids),
            correlation_key=key,
            stages=ordered_stages,
            alerts=tuple(sorted(group, key=lambda a: a.first_seen)),
            first_seen=min(timestamps_first),
            last_seen=max(timestamps_last),
        )
