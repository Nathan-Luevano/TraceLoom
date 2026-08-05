from pathlib import Path

from tracerloom.ingest.pipeline import run_ingestion
from tracerloom.parsing.registry import default_registry
from tracerloom.sources.local_files import LocalFileEventSource
from tracerloom.storage.parquet_store import read_events, write_events


def test_write_then_read_round_trips_events(fixture_dataset_root: Path, tmp_path: Path) -> None:
    source = LocalFileEventSource(dataset_root=fixture_dataset_root)
    registry = default_registry(reference_year=2031)
    result = run_ingestion(source, registry, dataset="synthetic_fixture_scenario")

    parquet_dir = tmp_path / "parquet"
    write_events(result.events, parquet_dir)
    read_back = read_events(parquet_dir)

    original_ids = sorted(e.event_id for e in result.events)
    read_ids = sorted(e.event_id for e in read_back)
    assert original_ids == read_ids


def test_rerun_write_is_idempotent(fixture_dataset_root: Path, tmp_path: Path) -> None:
    source = LocalFileEventSource(dataset_root=fixture_dataset_root)
    registry = default_registry(reference_year=2031)
    result = run_ingestion(source, registry, dataset="synthetic_fixture_scenario")

    parquet_dir = tmp_path / "parquet"
    write_events(result.events, parquet_dir)
    first_count = len(read_events(parquet_dir))
    write_events(result.events, parquet_dir)
    second_count = len(read_events(parquet_dir))
    assert first_count == second_count
