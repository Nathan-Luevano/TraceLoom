from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class TracerloomConfig:
    dataset_root: Path
    output_root: Path
    parquet_dir: Path
    dead_letter_dir: Path
    reports_dir: Path

    @staticmethod
    def default() -> TracerloomConfig:
        return TracerloomConfig(
            dataset_root=Path("russellmitchell_no-pcaps"),
            output_root=Path(".tracerloom-output"),
            parquet_dir=Path(".tracerloom-output/parquet"),
            dead_letter_dir=Path(".tracerloom-output/dead-letter"),
            reports_dir=Path(".tracerloom-output/reports"),
        )

    def with_overrides(
        self,
        dataset_root: Path | None = None,
        output_root: Path | None = None,
    ) -> TracerloomConfig:
        resolved_output = output_root if output_root is not None else self.output_root
        return TracerloomConfig(
            dataset_root=dataset_root if dataset_root is not None else self.dataset_root,
            output_root=resolved_output,
            parquet_dir=resolved_output / "parquet",
            dead_letter_dir=resolved_output / "dead-letter",
            reports_dir=resolved_output / "reports",
        )


def load_config(path: Path | None) -> TracerloomConfig:
    if path is None or not path.exists():
        return TracerloomConfig.default()
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    base = TracerloomConfig.default()
    dataset_root = Path(raw["dataset_root"]) if "dataset_root" in raw else base.dataset_root
    output_root = Path(raw["output_root"]) if "output_root" in raw else base.output_root
    return base.with_overrides(dataset_root=dataset_root, output_root=output_root)
