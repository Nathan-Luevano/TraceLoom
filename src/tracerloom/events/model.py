from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime


def compute_event_id(raw_path: str, raw_line: int, raw_content: str) -> str:
    digest = hashlib.sha256()
    digest.update(raw_path.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(str(raw_line).encode("utf-8"))
    digest.update(b"\x00")
    digest.update(raw_content.encode("utf-8"))
    return digest.hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    dataset: str
    host: str
    source_type: str
    event_type: str
    principal: str | None
    process: str | None
    action: str | None
    resource: str | None
    outcome: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    raw_path: str
    raw_line: int
    raw_event: str

    @staticmethod
    def field_names() -> tuple[str, ...]:
        return (
            "event_id",
            "timestamp",
            "dataset",
            "host",
            "source_type",
            "event_type",
            "principal",
            "process",
            "action",
            "resource",
            "outcome",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "raw_path",
            "raw_line",
            "raw_event",
        )
