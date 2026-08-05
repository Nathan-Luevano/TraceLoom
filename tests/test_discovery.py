from pathlib import Path

import pytest

from tracerloom.discovery.scan import DatasetValidationError, discover_dataset


def test_discovers_hosts_and_labeled_files(fixture_dataset_root: Path) -> None:
    discovery = discover_dataset(fixture_dataset_root)
    host_names = {host.name for host in discovery.hosts}
    assert host_names == {"authhost", "webhost", "vpnhost", "dnshost", "monhost", "sharehost"}
    assert discovery.total_log_files >= 6
    assert discovery.total_labeled_files == 2


def test_reports_simulation_window(fixture_dataset_root: Path) -> None:
    discovery = discover_dataset(fixture_dataset_root)
    assert discovery.simulation_start == "2031-06-01T00:00:00"
    assert discovery.simulation_end == "2031-06-03T00:00:00"


def test_missing_dataset_root_raises(tmp_path: Path) -> None:
    with pytest.raises(DatasetValidationError):
        discover_dataset(tmp_path / "does-not-exist")


def test_missing_gather_dir_raises(tmp_path: Path) -> None:
    (tmp_path / "dataset.yaml").write_text(
        "start: '2031-01-01T00:00:00'\nend: '2031-01-02T00:00:00'\n"
    )
    with pytest.raises(DatasetValidationError):
        discover_dataset(tmp_path)


def test_missing_dataset_yaml_raises(tmp_path: Path) -> None:
    (tmp_path / "gather").mkdir()
    with pytest.raises(DatasetValidationError):
        discover_dataset(tmp_path)


def test_labeled_files_carry_label_path(fixture_dataset_root: Path) -> None:
    discovery = discover_dataset(fixture_dataset_root)
    auth_host = next(host for host in discovery.hosts if host.name == "authhost")
    auth_log = next(f for f in auth_host.log_files if f.relative_path == "auth.log")
    assert auth_log.has_labels
    assert auth_log.label_path is not None
    assert auth_log.label_path.name == "auth.log"
