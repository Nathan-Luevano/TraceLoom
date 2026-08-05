from pathlib import Path

from tracerloom.ingest.pipeline import IngestResult, run_ingestion
from tracerloom.parsing.registry import default_registry
from tracerloom.sources.local_files import LocalFileEventSource


def _run(fixture_dataset_root: Path) -> IngestResult:
    source = LocalFileEventSource(dataset_root=fixture_dataset_root)
    registry = default_registry(reference_year=2031)
    return run_ingestion(source, registry, dataset="synthetic_fixture_scenario")


def test_labels_join_to_correct_raw_lines(fixture_dataset_root: Path) -> None:
    result = _run(fixture_dataset_root)
    auth_ground_truth = [g for g in result.ground_truth if g.raw_path.endswith("auth.log")]
    matched = {g.line_number: g for g in auth_ground_truth}
    assert matched[3].event_id is not None
    matching_event = next(e for e in result.events if e.event_id == matched[3].event_id)
    assert matching_event.raw_line == 3
    assert matching_event.action == "user_switch"


def test_orphaned_out_of_range_label_does_not_crash_and_has_no_event(
    fixture_dataset_root: Path,
) -> None:
    result = _run(fixture_dataset_root)
    auth_ground_truth = [g for g in result.ground_truth if g.raw_path.endswith("auth.log")]
    orphan = next(g for g in auth_ground_truth if g.line_number == 42)
    assert orphan.event_id is None


def test_malformed_lines_produce_dead_letters_not_crashes(fixture_dataset_root: Path) -> None:
    result = _run(fixture_dataset_root)
    assert len(result.dead_letters) > 0
    reasons = {dl.reason for dl in result.dead_letters}
    assert any(reasons)


def test_ingestion_produces_events_for_every_supported_source_type(
    fixture_dataset_root: Path,
) -> None:
    result = _run(fixture_dataset_root)
    source_types = {event.source_type for event in result.events}
    assert source_types == {"auth", "dns", "vpn", "web_access", "audit", "monitoring_cpu"}


def test_event_ids_are_stable_across_reruns(fixture_dataset_root: Path) -> None:
    first = _run(fixture_dataset_root)
    second = _run(fixture_dataset_root)
    first_ids = sorted(e.event_id for e in first.events)
    second_ids = sorted(e.event_id for e in second.events)
    assert first_ids == second_ids


def test_evidence_event_ids_map_back_to_raw_path_and_line(fixture_dataset_root: Path) -> None:
    result = _run(fixture_dataset_root)
    index = {e.event_id: (e.raw_path, e.raw_line) for e in result.events}
    for ground_truth in result.ground_truth:
        if ground_truth.event_id is not None:
            raw_path, raw_line = index[ground_truth.event_id]
            assert raw_path == ground_truth.raw_path
            assert raw_line == ground_truth.line_number
