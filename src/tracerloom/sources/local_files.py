from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from tracerloom.discovery.scan import DatasetDiscovery, discover_dataset
from tracerloom.sources.base import RawLine, SourceFile


@dataclass(slots=True)
class LocalFileEventSource:
    dataset_root: Path
    _discovery: DatasetDiscovery | None = None

    def discovery(self) -> DatasetDiscovery:
        if self._discovery is None:
            self._discovery = discover_dataset(self.dataset_root)
        return self._discovery

    def list_files(self) -> Iterable[SourceFile]:
        discovery = self.discovery()
        for host in discovery.hosts:
            for log_file in host.log_files:
                yield SourceFile(
                    host=host.name,
                    relative_path=log_file.relative_path,
                    raw_path=str(log_file.raw_path),
                    label_path=str(log_file.label_path) if log_file.label_path else None,
                )

    def read_lines(self, source_file: SourceFile) -> Iterator[RawLine]:
        path = Path(source_file.raw_path)
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_number, raw in enumerate(handle, start=1):
                yield RawLine(line_number=line_number, content=raw.rstrip("\n"))
