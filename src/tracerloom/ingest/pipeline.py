from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from tracerloom.events.model import NormalizedEvent
from tracerloom.labels.loader import LabelRecord, MalformedLabelLine, load_labels_for_file
from tracerloom.parsing.base import DeadLetter
from tracerloom.parsing.registry import ParserRegistry
from tracerloom.sources.base import EventSource


@dataclass(frozen=True, slots=True)
class GroundTruthEvent:
    raw_path: str
    line_number: int
    event_id: str | None
    labels: tuple[str, ...]
    rules: dict[str, tuple[str, ...]]


@dataclass(slots=True)
class IngestResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    dead_letters: list[DeadLetter] = field(default_factory=list)
    ground_truth: list[GroundTruthEvent] = field(default_factory=list)
    malformed_label_lines: list[MalformedLabelLine] = field(default_factory=list)
    files_seen: int = 0
    files_without_parser: int = 0


def run_ingestion(source: EventSource, registry: ParserRegistry, dataset: str) -> IngestResult:
    result = IngestResult()

    for source_file in source.list_files():
        result.files_seen += 1
        labels_by_line: dict[int, LabelRecord] = {}
        if source_file.label_path is not None:
            records, malformed = load_labels_for_file(
                Path(source_file.label_path), raw_path_key=source_file.raw_path
            )
            for record in records:
                labels_by_line[record.line_number] = record
            result.malformed_label_lines.extend(malformed)

        parser = registry.find(source_file.relative_path)
        if parser is None:
            result.files_without_parser += 1

        seen_line_numbers: set[int] = set()
        for raw_line in source.read_lines(source_file):
            seen_line_numbers.add(raw_line.line_number)
            label_record = labels_by_line.get(raw_line.line_number)
            event_id: str | None = None

            if parser is None:
                result.dead_letters.append(
                    DeadLetter(
                        raw_path=source_file.raw_path,
                        line_number=raw_line.line_number,
                        reason="no parser registered for this source type",
                        raw_content=raw_line.content,
                    )
                )
            else:
                outcome = parser.parse_line(
                    dataset=dataset,
                    host=source_file.host,
                    raw_path=source_file.raw_path,
                    line_number=raw_line.line_number,
                    content=raw_line.content,
                )
                if outcome.event is not None:
                    result.events.append(outcome.event)
                    event_id = outcome.event.event_id
                elif outcome.dead_letter is not None:
                    result.dead_letters.append(outcome.dead_letter)

            if label_record is not None:
                result.ground_truth.append(
                    GroundTruthEvent(
                        raw_path=source_file.raw_path,
                        line_number=raw_line.line_number,
                        event_id=event_id,
                        labels=label_record.labels,
                        rules=label_record.rules,
                    )
                )

        for orphaned_line_number in sorted(set(labels_by_line) - seen_line_numbers):
            orphaned_record = labels_by_line[orphaned_line_number]
            result.ground_truth.append(
                GroundTruthEvent(
                    raw_path=source_file.raw_path,
                    line_number=orphaned_line_number,
                    event_id=None,
                    labels=orphaned_record.labels,
                    rules=orphaned_record.rules,
                )
            )

    return result
