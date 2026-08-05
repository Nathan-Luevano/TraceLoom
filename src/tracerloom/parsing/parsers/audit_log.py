from __future__ import annotations

import re

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_epoch_timestamp

_HEADER_PATTERN = re.compile(
    r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<rest>.*)$"
)
_KV_PATTERN = re.compile(r"(?P<key>[\w-]+)=(?P<value>\"[^\"]*\"|'[^']*'|\S+)")


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _extract_pairs(text: str) -> dict[str, str]:
    return {m.group("key"): _strip_quotes(m.group("value")) for m in _KV_PATTERN.finditer(text)}


class AuditLogParser:
    source_type = "audit"

    def matches(self, relative_path: str) -> bool:
        return relative_path.endswith("audit/audit.log")

    def parse_line(
        self,
        dataset: str,
        host: str,
        raw_path: str,
        line_number: int,
        content: str,
    ) -> ParseOutcome:
        header = _HEADER_PATTERN.match(content)
        if header is None:
            return ParseOutcome.failed(
                raw_path, line_number, "unrecognized audit.log header", content
            )
        timestamp = parse_epoch_timestamp(header.group("epoch"))
        if timestamp is None:
            return ParseOutcome.failed(
                raw_path, line_number, "unparseable epoch timestamp", content
            )

        record_type = header.group("type")
        top_level = _extract_pairs(header.group("rest"))
        nested = _extract_pairs(top_level["msg"]) if "msg" in top_level else {}

        principal = nested.get("acct") or nested.get("acct".upper())
        process = nested.get("exe") or top_level.get("exe") or top_level.get("comm")
        resource = nested.get("unit") or top_level.get("exe")
        raw_outcome = nested.get("res") or top_level.get("res") or top_level.get("success")
        outcome = None
        if raw_outcome is not None:
            outcome = "success" if raw_outcome in {"success", "yes", "1"} else "failure"

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=host,
            source_type=self.source_type,
            event_type=record_type.lower(),
            principal=principal,
            process=process,
            action=nested.get("op") or record_type.lower(),
            resource=resource,
            outcome=outcome,
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
