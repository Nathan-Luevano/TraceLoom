from __future__ import annotations

from datetime import UTC, datetime


def parse_syslog_timestamp(text: str, reference_year: int) -> datetime | None:
    try:
        parsed = datetime.strptime(f"{reference_year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def parse_apache_access_timestamp(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse_apache_error_timestamp(text: str) -> datetime | None:
    try:
        parsed = datetime.strptime(text, "%a %b %d %H:%M:%S.%f %Y")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def parse_iso8601_timestamp(text: str) -> datetime | None:
    try:
        normalized = text.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def parse_epoch_timestamp(text: str) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(text), tz=UTC)
    except ValueError:
        return None
