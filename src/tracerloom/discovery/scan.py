from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class DatasetValidationError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class DiscoveredLogFile:
    host: str
    raw_path: Path
    relative_path: str
    has_labels: bool
    label_path: Path | None


@dataclass(frozen=True, slots=True)
class DiscoveredHost:
    name: str
    log_files: tuple[DiscoveredLogFile, ...]


@dataclass(frozen=True, slots=True)
class DatasetDiscovery:
    dataset_root: Path
    dataset_name: str
    simulation_start: str
    simulation_end: str
    hosts: tuple[DiscoveredHost, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total_log_files(self) -> int:
        return sum(len(host.log_files) for host in self.hosts)

    @property
    def total_labeled_files(self) -> int:
        return sum(1 for host in self.hosts for f in host.log_files if f.has_labels)


def _load_dataset_yaml(dataset_root: Path) -> dict[str, str]:
    dataset_yaml_path = dataset_root / "dataset.yaml"
    if not dataset_yaml_path.is_file():
        raise DatasetValidationError(f"missing dataset.yaml at {dataset_yaml_path}")
    raw = yaml.safe_load(dataset_yaml_path.read_text())
    if not isinstance(raw, dict) or "start" not in raw or "end" not in raw:
        raise DatasetValidationError("dataset.yaml missing required start/end keys")
    return {
        "start": str(raw["start"]),
        "end": str(raw["end"]),
        "name": str(raw.get("name", dataset_root.name)),
    }


def discover_dataset(dataset_root: Path) -> DatasetDiscovery:
    if not dataset_root.is_dir():
        raise DatasetValidationError(f"dataset root does not exist: {dataset_root}")
    gather_root = dataset_root / "gather"
    if not gather_root.is_dir():
        raise DatasetValidationError(f"missing gather/ under {dataset_root}")
    labels_root = dataset_root / "labels"

    window = _load_dataset_yaml(dataset_root)
    warnings: list[str] = []
    hosts: list[DiscoveredHost] = []

    for host_dir in sorted(p for p in gather_root.iterdir() if p.is_dir()):
        logs_dir = host_dir / "logs"
        if not logs_dir.is_dir():
            warnings.append(f"host {host_dir.name} has no logs/ directory")
            continue
        log_files: list[DiscoveredLogFile] = []
        for raw_path in sorted(p for p in logs_dir.rglob("*") if p.is_file()):
            relative_path = str(raw_path.relative_to(logs_dir))
            candidate_label_path = labels_root / host_dir.name / "logs" / relative_path
            has_labels = candidate_label_path.is_file()
            with_jsonl = candidate_label_path.with_suffix(candidate_label_path.suffix + ".jsonl")
            if not has_labels and with_jsonl.is_file():
                candidate_label_path = with_jsonl
                has_labels = True
            log_files.append(
                DiscoveredLogFile(
                    host=host_dir.name,
                    raw_path=raw_path,
                    relative_path=relative_path,
                    has_labels=has_labels,
                    label_path=candidate_label_path if has_labels else None,
                )
            )
        hosts.append(DiscoveredHost(name=host_dir.name, log_files=tuple(log_files)))

    if labels_root.is_dir():
        for labeled_host_dir in sorted(p for p in labels_root.iterdir() if p.is_dir()):
            if labeled_host_dir.name not in {h.name for h in hosts}:
                warnings.append(f"labels reference unknown host {labeled_host_dir.name}")

    return DatasetDiscovery(
        dataset_root=dataset_root,
        dataset_name=window["name"],
        simulation_start=window["start"],
        simulation_end=window["end"],
        hosts=tuple(hosts),
        warnings=tuple(warnings),
    )
