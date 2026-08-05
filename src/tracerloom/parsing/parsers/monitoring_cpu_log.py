from __future__ import annotations

import json
from typing import Any

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_iso8601_timestamp


def _dig(payload: dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


class MonitoringCpuLogParser:
    source_type = "monitoring_cpu"

    def matches(self, relative_path: str) -> bool:
        return "logstash/" in relative_path and relative_path.endswith("-system.cpu.log")

    def parse_line(
        self,
        dataset: str,
        host: str,
        raw_path: str,
        line_number: int,
        content: str,
    ) -> ParseOutcome:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            return ParseOutcome.failed(raw_path, line_number, f"invalid json: {exc}", content)
        if not isinstance(payload, dict):
            return ParseOutcome.failed(
                raw_path, line_number, "top-level json is not an object", content
            )

        ts_raw = payload.get("@timestamp")
        if not isinstance(ts_raw, str):
            return ParseOutcome.failed(raw_path, line_number, "missing @timestamp", content)
        timestamp = parse_iso8601_timestamp(ts_raw)
        if timestamp is None:
            return ParseOutcome.failed(raw_path, line_number, "unparseable @timestamp", content)

        monitored_host = _dig(payload, "host", "name")
        if not isinstance(monitored_host, str):
            monitored_host = host

        cpu_pct = _dig(payload, "system", "cpu", "total", "pct")
        if cpu_pct is None:
            cpu_pct = _dig(payload, "host", "cpu", "pct")

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=monitored_host,
            source_type=self.source_type,
            event_type="cpu_sample",
            principal=None,
            process=None,
            action="cpu_sample",
            resource="system.cpu",
            outcome=str(cpu_pct) if cpu_pct is not None else None,
            source_ip=None,
            source_port=None,
            destination_ip=None,
            destination_port=None,
            protocol=None,
            raw_path=raw_path,
            raw_line=line_number,
            raw_event=content,
        )
        return ParseOutcome.ok(event)
