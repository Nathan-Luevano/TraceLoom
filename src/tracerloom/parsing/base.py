from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tracerloom.events.model import NormalizedEvent


@dataclass(frozen=True, slots=True)
class DeadLetter:
    raw_path: str
    line_number: int
    reason: str
    raw_content: str


@dataclass(frozen=True, slots=True)
class ParseOutcome:
    event: NormalizedEvent | None
    dead_letter: DeadLetter | None

    @staticmethod
    def ok(event: NormalizedEvent) -> ParseOutcome:
        return ParseOutcome(event=event, dead_letter=None)

    @staticmethod
    def failed(raw_path: str, line_number: int, reason: str, raw_content: str) -> ParseOutcome:
        return ParseOutcome(
            event=None,
            dead_letter=DeadLetter(
                raw_path=raw_path,
                line_number=line_number,
                reason=reason,
                raw_content=raw_content,
            ),
        )


class LineParser(Protocol):
    source_type: str

    def matches(self, relative_path: str) -> bool: ...

    def parse_line(
        self,
        dataset: str,
        host: str,
        raw_path: str,
        line_number: int,
        content: str,
    ) -> ParseOutcome: ...
