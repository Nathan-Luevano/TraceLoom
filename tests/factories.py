from datetime import UTC, datetime, timedelta

from tracerloom.events.model import NormalizedEvent, compute_event_id

_BASE_TIME = datetime(2031, 6, 1, 8, 0, 0, tzinfo=UTC)


def make_event(
    *,
    line: int = 1,
    raw_path: str = "synthetic.log",
    seconds_offset: int = 0,
    dataset: str = "synthetic",
    host: str = "synthhost",
    source_type: str = "web_access",
    event_type: str = "http_request",
    principal: str | None = None,
    process: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    outcome: str | None = None,
    source_ip: str | None = None,
    source_port: int | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    raw_event: str = "synthetic raw content",
) -> NormalizedEvent:
    timestamp = _BASE_TIME + timedelta(seconds=seconds_offset)
    content = f"{raw_event}#{line}#{seconds_offset}"
    return NormalizedEvent(
        event_id=compute_event_id(raw_path, line, content),
        timestamp=timestamp,
        dataset=dataset,
        host=host,
        source_type=source_type,
        event_type=event_type,
        principal=principal,
        process=process,
        action=action,
        resource=resource,
        outcome=outcome,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        raw_path=raw_path,
        raw_line=line,
        raw_event=content,
    )
