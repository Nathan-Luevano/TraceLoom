from __future__ import annotations

import re

from tracerloom.events.model import NormalizedEvent, compute_event_id
from tracerloom.parsing.base import ParseOutcome
from tracerloom.parsing.timestamps import parse_syslog_timestamp

_LINE_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\[:]+)(\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_SU_SUCCESS = re.compile(r"pam_unix\(su(?::session)?\):\s*session opened for user (?P<target>\S+)")
_SUDO_COMMAND = re.compile(r"(?P<actor>\S+)\s*:.*COMMAND=(?P<command>.+)$")
_FAILED_LOGIN = re.compile(r"authentication failure.*user=(?P<target>\S+)")


class AuthLogParser:
    source_type = "auth"

    def __init__(self, reference_year: int) -> None:
        self._reference_year = reference_year

    def matches(self, relative_path: str) -> bool:
        name = relative_path.rsplit("/", 1)[-1]
        return name == "auth.log" or name.startswith("auth.log.")

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
                raw_path, line_number, "unrecognized auth.log format", content
            )
        timestamp = parse_syslog_timestamp(match.group("ts"), self._reference_year)
        if timestamp is None:
            return ParseOutcome.failed(raw_path, line_number, "unparseable timestamp", content)

        message = match.group("message")
        process = match.group("process").strip()
        principal: str | None = None
        action = "log"
        outcome: str | None = None

        su_match = _SU_SUCCESS.search(message)
        sudo_match = _SUDO_COMMAND.search(message) if process == "sudo" else None
        failed_match = _FAILED_LOGIN.search(message)

        if su_match is not None:
            action = "user_switch"
            principal = su_match.group("target")
            outcome = "success"
        elif sudo_match is not None:
            action = "privileged_command"
            principal = sudo_match.group("actor")
            outcome = "success"
        elif failed_match is not None:
            action = "authentication_failure"
            principal = failed_match.group("target")
            outcome = "failure"

        event_id = compute_event_id(raw_path, line_number, content)
        event = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            dataset=dataset,
            host=host,
            source_type=self.source_type,
            event_type="auth_log_line",
            principal=principal,
            process=process,
            action=action,
            resource=None,
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
