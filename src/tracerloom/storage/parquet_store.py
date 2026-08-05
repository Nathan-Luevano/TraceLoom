from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.dataset as ds

from tracerloom.events.model import NormalizedEvent

_STRING_FIELDS = (
    "event_id",
    "dataset",
    "host",
    "source_type",
    "event_type",
    "principal",
    "process",
    "action",
    "resource",
    "outcome",
    "source_ip",
    "destination_ip",
    "protocol",
    "raw_path",
    "raw_event",
)


def _events_to_table(events: list[NormalizedEvent]) -> pa.Table:
    columns: dict[str, list[object]] = {name: [] for name in NormalizedEvent.field_names()}
    columns["date"] = []
    for event in events:
        for name in NormalizedEvent.field_names():
            columns[name].append(getattr(event, name))
        columns["date"].append(event.timestamp.date().isoformat())
    return pa.table(columns)


def write_events(events: list[NormalizedEvent], parquet_dir: Path) -> None:
    if parquet_dir.exists():
        shutil.rmtree(parquet_dir)
    parquet_dir.mkdir(parents=True, exist_ok=True)
    if not events:
        return
    table = _events_to_table(events)
    ds.write_dataset(
        table,
        base_dir=str(parquet_dir),
        format="parquet",
        partitioning=["dataset", "source_type", "date"],
        partitioning_flavor="hive",
        existing_data_behavior="overwrite_or_ignore",
    )


def read_events(parquet_dir: Path) -> list[NormalizedEvent]:
    if not parquet_dir.exists() or not any(parquet_dir.iterdir()):
        return []
    dataset = ds.dataset(str(parquet_dir), format="parquet", partitioning="hive")
    table = dataset.to_table()
    events: list[NormalizedEvent] = []
    columns = {name: table.column(name).to_pylist() for name in NormalizedEvent.field_names()}
    row_count = table.num_rows
    for index in range(row_count):
        timestamp_value = columns["timestamp"][index]
        if isinstance(timestamp_value, datetime):
            timestamp = timestamp_value
        else:
            timestamp = datetime.fromisoformat(str(timestamp_value))
        events.append(
            NormalizedEvent(
                event_id=columns["event_id"][index],
                timestamp=timestamp,
                dataset=columns["dataset"][index],
                host=columns["host"][index],
                source_type=columns["source_type"][index],
                event_type=columns["event_type"][index],
                principal=columns["principal"][index],
                process=columns["process"][index],
                action=columns["action"][index],
                resource=columns["resource"][index],
                outcome=columns["outcome"][index],
                source_ip=columns["source_ip"][index],
                source_port=columns["source_port"][index],
                destination_ip=columns["destination_ip"][index],
                destination_port=columns["destination_port"][index],
                protocol=columns["protocol"][index],
                raw_path=columns["raw_path"][index],
                raw_line=columns["raw_line"][index],
                raw_event=columns["raw_event"][index],
            )
        )
    return events
