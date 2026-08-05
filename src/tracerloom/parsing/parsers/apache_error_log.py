from __future__ import annotations

import re

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_apache_error_timestamp

_LINE_PATTERN = re.compile(
    r"^\[(?P<ts>\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]\s+"
    r"\[(?P<module>[\w:]+)\]\s+\[pid (?P<pid>\d+)\]\s*"
    r"(\[client (?P<ip>[\d.]+):(?P<port>\d+)\]\s*)?"
    r"(?P<message>.*)$"
)


class ApacheErrorLogParser:
    source_type = "web_error"

    def matches(self, relative_path: str) -> bool:
        name = relative_path.rsplit("/", 1)[-1]
        return "apache2/" in relative_path and "error.log" in name

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
                raw_path, line_number, "unrecognized apache error-log format", content
            )
        timestamp = parse_apache_error_timestamp(match.group("ts"))
        if timestamp is None:
            return ParseOutcome.failed(raw_path, line_number, "unparseable timestamp", content)

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=host,
            source_type=self.source_type,
            event_type="http_error",
            principal=None,
            process="apache2",
            action=match.group("module"),
            resource=match.group("message"),
            outcome="error",
            source_ip=match.group("ip"),
            source_port=int(match.group("port")) if match.group("port") else None,
            destination_ip=None,
            destination_port=None,
            protocol=None,
            raw_path=raw_path,
            raw_line=line_number,
            raw_event=content,
        )
        return ParseOutcome.ok(event)
