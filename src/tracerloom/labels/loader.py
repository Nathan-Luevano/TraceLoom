from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class LabelRecord:
    raw_path: str
    line_number: int
    labels: tuple[str, ...]
    rules: dict[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class MalformedLabelLine:
    label_path: str
    line_number: int
    reason: str


def load_labels_for_file(
    label_path: Path, raw_path_key: str
) -> tuple[list[LabelRecord], list[MalformedLabelLine]]:
    records: list[LabelRecord] = []
    malformed: list[MalformedLabelLine] = []
    with label_path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                malformed.append(
                    MalformedLabelLine(
                        label_path=str(label_path),
                        line_number=line_number,
                        reason=f"invalid json: {exc}",
                    )
                )
                continue
            if not isinstance(payload, dict) or "line" not in payload or "labels" not in payload:
                malformed.append(
                    MalformedLabelLine(
                        label_path=str(label_path),
                        line_number=line_number,
                        reason="missing required keys 'line'/'labels'",
                    )
                )
                continue
            raw_labels = payload.get("labels")
            raw_rules = payload.get("rules", {})
            if not isinstance(raw_labels, list) or not isinstance(raw_rules, dict):
                malformed.append(
                    MalformedLabelLine(
                        label_path=str(label_path),
                        line_number=line_number,
                        reason="'labels' must be a list and 'rules' must be an object",
                    )
                )
                continue
            rules: dict[str, tuple[str, ...]] = {
                str(key): tuple(str(v) for v in value)
                for key, value in raw_rules.items()
                if isinstance(value, list)
            }
            records.append(
                LabelRecord(
                    raw_path=raw_path_key,
                    line_number=int(payload["line"]),
                    labels=tuple(str(label) for label in raw_labels),
                    rules=rules,
                )
            )
    return records, malformed
