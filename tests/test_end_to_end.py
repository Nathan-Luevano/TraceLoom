from pathlib import Path

from tracerloom.config import TracerloomConfig
from tracerloom.orchestration import run_full_pipeline


def test_full_pipeline_runs_against_synthetic_fixture(
    fixture_dataset_root: Path, tmp_path: Path
) -> None:
    output_root = tmp_path / "out"
    config = TracerloomConfig.default().with_overrides(
        dataset_root=fixture_dataset_root, output_root=output_root
    )

    artifacts = run_full_pipeline(config)

    assert artifacts.dataset_name == "synthetic_fixture_scenario"
    assert len(artifacts.ingest_result.events) > 0
    assert len(artifacts.ingest_result.dead_letters) > 0
    assert artifacts.report.total_events == len(artifacts.ingest_result.events)
    assert (config.parquet_dir).exists()


def test_alert_evidence_event_ids_map_back_to_ingested_raw_lines(
    fixture_dataset_root: Path, tmp_path: Path
) -> None:
    output_root = tmp_path / "out"
    config = TracerloomConfig.default().with_overrides(
        dataset_root=fixture_dataset_root, output_root=output_root
    )
    artifacts = run_full_pipeline(config)

    event_index = {e.event_id: (e.raw_path, e.raw_line) for e in artifacts.ingest_result.events}
    assert artifacts.alerts, "expected at least one alert from the synthetic fixture"
    for alert in artifacts.alerts:
        for evidence_id in alert.evidence_event_ids:
            assert evidence_id in event_index
            raw_path, raw_line = event_index[evidence_id]
            assert raw_path
            assert raw_line >= 1
