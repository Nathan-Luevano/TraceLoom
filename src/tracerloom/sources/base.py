from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SourceFile:
    host: str
    relative_path: str
    raw_path: str
    label_path: str | None


@dataclass(frozen=True, slots=True)
class RawLine:
    line_number: int
    content: str


class EventSource(Protocol):
    def list_files(self) -> Iterable[SourceFile]: ...

    def read_lines(self, source_file: SourceFile) -> Iterator[RawLine]: ...
