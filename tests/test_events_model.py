from tracerloom.events.model import NormalizedEvent, compute_event_id


def test_compute_event_id_is_deterministic() -> None:
    first = compute_event_id("path/a.log", 3, "some content")
    second = compute_event_id("path/a.log", 3, "some content")
    assert first == second


def test_compute_event_id_differs_on_content_change() -> None:
    first = compute_event_id("path/a.log", 3, "some content")
    second = compute_event_id("path/a.log", 3, "different content")
    assert first != second


def test_compute_event_id_differs_on_line_number_change() -> None:
    first = compute_event_id("path/a.log", 3, "some content")
    second = compute_event_id("path/a.log", 4, "some content")
    assert first != second


def test_normalized_event_field_names_match_required_schema() -> None:
    expected = {
        "event_id",
        "timestamp",
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
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "raw_path",
        "raw_line",
        "raw_event",
    }
    assert set(NormalizedEvent.field_names()) == expected


def test_normalized_event_schema_has_no_label_fields() -> None:
    forbidden_substrings = ("label", "ground_truth", "rule_id", "attack")
    for name in NormalizedEvent.field_names():
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden_substrings)
