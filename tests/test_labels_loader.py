from pathlib import Path

from tracerloom.labels.loader import load_labels_for_file


def test_loads_records_and_preserves_line_numbers(fixture_dataset_root: Path) -> None:
    label_path = fixture_dataset_root / "labels" / "authhost" / "logs" / "auth.log"
    records, malformed = load_labels_for_file(label_path, raw_path_key="synthetic-raw-key")
    line_numbers = {record.line_number for record in records}
    assert line_numbers == {3, 4, 5, 42}
    assert len(malformed) == 1
    assert "invalid json" in malformed[0].reason


def test_preserves_multiple_hierarchical_labels_and_rules(fixture_dataset_root: Path) -> None:
    label_path = fixture_dataset_root / "labels" / "authhost" / "logs" / "auth.log"
    records, _ = load_labels_for_file(label_path, raw_path_key="synthetic-raw-key")
    line_three = next(r for r in records if r.line_number == 3)
    assert set(line_three.labels) == {"synthetic_change_user", "escalate"}
    assert line_three.rules["escalate"] == ("synthetic.escalate.su.login",)


def test_malformed_jsonl_lines_are_skipped_not_raised(tmp_path: Path) -> None:
    label_path = tmp_path / "broken.jsonl"
    label_path.write_text(
        '{"line": 1, "labels": ["a"], "rules": {}}\nnot-json\n{"missing_line": true}\n'
    )
    records, malformed = load_labels_for_file(label_path, raw_path_key="key")
    assert len(records) == 1
    assert len(malformed) == 2


def test_off_by_one_line_numbers_are_preserved_exactly(tmp_path: Path) -> None:
    label_path = tmp_path / "labels.jsonl"
    label_path.write_text('{"line": 1, "labels": ["first_line"], "rules": {}}\n')
    records, _ = load_labels_for_file(label_path, raw_path_key="key")
    assert records[0].line_number == 1
    assert records[0].line_number != 0
    assert records[0].line_number != 2
