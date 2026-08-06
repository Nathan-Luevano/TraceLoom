from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from tracerloom.detection.registry import default_detectors
from tracerloom.ingest.pipeline import run_ingestion
from tracerloom.parsing.registry import default_registry
from tracerloom.sources.base import RawLine, SourceFile


@dataclass(slots=True)
class InMemoryEventSource:
    files: dict[SourceFile, list[str]] = field(default_factory=dict)

    def list_files(self) -> Iterable[SourceFile]:
        return list(self.files.keys())

    def read_lines(self, source_file: SourceFile) -> Iterator[RawLine]:
        for line_number, content in enumerate(self.files[source_file], start=1):
            yield RawLine(line_number=line_number, content=content)


def test_ingestion_and_detection_work_against_a_non_file_event_source() -> None:
    source_file = SourceFile(
        host="webhost",
        relative_path="apache2/site-access.log",
        raw_path="memory://webhost/apache2/site-access.log",
        label_path=None,
    )
    request_line = (
        '203.0.113.9 - - [01/Jun/2031:08:00:02 +0000] "GET /uploads/x.php?cmd=id '
        'HTTP/1.1" 200 12 "-" "curl/7.68.0"'
    )
    source = InMemoryEventSource(files={source_file: [request_line]})
    registry = default_registry(reference_year=2031)
    result = run_ingestion(source, registry, dataset="in-memory-synthetic")
    assert len(result.events) == 1

    alerts = []
    for detector in default_detectors():
        alerts.extend(detector.detect(result.events))
    assert any(alert.rule_id == "web.webshell.command_heuristic" for alert in alerts)
