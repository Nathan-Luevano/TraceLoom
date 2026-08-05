from __future__ import annotations

import re
from datetime import UTC

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_iso8601_timestamp

_LINE_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"((?P<user>[\w.@-]+)/)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)\s+"
    r"(?P<message>.*)$"
)
_VERIFY_IDENTITY = re.compile(r"^VERIFY OK: depth=0, CN=(?P<cn>\S+)$")


class OpenVpnLogParser:
    source_type = "vpn"

    def matches(self, relative_path: str) -> bool:
        return relative_path.rsplit("/", 1)[-1] == "openvpn.log"

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
                raw_path, line_number, "unrecognized openvpn format", content
            )
        timestamp = parse_iso8601_timestamp(match.group("ts").replace(" ", "T"))
        if timestamp is None:
            return ParseOutcome.failed(raw_path, line_number, "unparseable timestamp", content)
        timestamp = timestamp.replace(tzinfo=UTC)

        message = match.group("message")
        principal = match.group("user")
        identity_match = _VERIFY_IDENTITY.match(message)
        if identity_match is not None:
            principal = identity_match.group("cn")
            event_type = "vpn_identity_verified"
        elif message.startswith("TLS: Initial packet"):
            event_type = "vpn_session_start"
        elif "soft reset" in message or "hard reset" in message:
            event_type = "vpn_session_reset"
        else:
            event_type = "vpn_control_message"

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=host,
            source_type=self.source_type,
            event_type=event_type,
            principal=principal,
            process="openvpn",
            action=event_type,
            resource=None,
            outcome=None,
            source_ip=match.group("ip"),
            source_port=int(match.group("port")),
            destination_ip=None,
            destination_port=None,
            protocol="vpn",
            raw_path=raw_path,
            raw_line=line_number,
            raw_event=content,
        )
        return ParseOutcome.ok(event)
