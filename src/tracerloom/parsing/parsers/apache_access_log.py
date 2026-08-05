from __future__ import annotations

import re

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_apache_access_timestamp

_LINE_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"$'
)


class ApacheAccessLogParser:
    source_type = "web_access"

    def matches(self, relative_path: str) -> bool:
        name = relative_path.rsplit("/", 1)[-1]
        return "apache2/" in relative_path and "access.log" in name

    def parse_line(
        self,
        dataset: str,
        host: str,
        raw_path: str,
        line_number: int,
        content: str,
    ) -> ParseOutcome:
        match = _LINE_PATTERN.match(content)
        if match is None:
            return ParseOutcome.failed(
                raw_path, line_number, "unrecognized apache combined-log format", content
            )
        timestamp = parse_apache_access_timestamp(match.group("ts"))
        if timestamp is None:
            return ParseOutcome.failed(raw_path, line_number, "unparseable timestamp", content)

        status = int(match.group("status"))
        user = match.group("user")
        principal = None if user == "-" else user

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=host,
            source_type=self.source_type,
            event_type="http_request",
            principal=principal,
            process="apache2",
            action=match.group("method"),
            resource=match.group("path"),
            outcome=str(status),
            source_ip=match.group("ip"),
            source_port=None,
            destination_ip=None,
            destination_port=None,
            protocol=match.group("proto"),
            raw_path=raw_path,
            raw_line=line_number,
            raw_event=content,
        )
        return ParseOutcome.ok(event)
