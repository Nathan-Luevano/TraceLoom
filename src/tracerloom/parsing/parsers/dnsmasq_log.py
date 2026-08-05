from __future__ import annotations

import re

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_syslog_timestamp

_LINE_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"dnsmasq(\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_QUERY = re.compile(r"^query\[(?P<qtype>\w+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)$")
_FORWARDED = re.compile(r"^forwarded\s+(?P<domain>\S+)\s+to\s+(?P<ip>\S+)$")
_REPLY = re.compile(r"^reply\s+(?P<domain>\S+)\s+is\s+(?P<answer>\S+)$")


class DnsmasqLogParser:
    source_type = "dns"

    def __init__(self, reference_year: int) -> None:
        self._reference_year = reference_year

    def matches(self, relative_path: str) -> bool:
        return relative_path.rsplit("/", 1)[-1] == "dnsmasq.log"

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
                raw_path, line_number, "unrecognized dnsmasq format", content
            )
        timestamp = parse_syslog_timestamp(match.group("ts"), self._reference_year)
        if timestamp is None:
            return ParseOutcome.failed(raw_path, line_number, "unparseable timestamp", content)

        message = match.group("message")
        event_type = "dns_other"
        resource: str | None = None
        source_ip: str | None = None
        destination_ip: str | None = None

        query_match = _QUERY.match(message)
        forwarded_match = _FORWARDED.match(message)
        reply_match = _REPLY.match(message)

        if query_match is not None:
            event_type = "dns_query"
            resource = query_match.group("domain")
            source_ip = query_match.group("ip")
        elif forwarded_match is not None:
            event_type = "dns_forwarded"
            resource = forwarded_match.group("domain")
            destination_ip = forwarded_match.group("ip")
        elif reply_match is not None:
            event_type = "dns_reply"
            resource = reply_match.group("domain")
            destination_ip = reply_match.group("answer")
        else:
            return ParseOutcome.failed(
                raw_path, line_number, "unrecognized dnsmasq message", content
            )

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=host,
            source_type=self.source_type,
            event_type=event_type,
            principal=None,
            process="dnsmasq",
            action=event_type,
            resource=resource,
            outcome=None,
            source_ip=source_ip,
            source_port=None,
            destination_ip=destination_ip,
            destination_port=None,
            protocol="dns",
            raw_path=raw_path,
            raw_line=line_number,
            raw_event=content,
        )
        return ParseOutcome.ok(event)
