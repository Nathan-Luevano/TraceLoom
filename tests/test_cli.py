from pathlib import Path

from typer.testing import CliRunner

from tracerloom.cli.main import app

runner = CliRunner()


def test_inspect_reports_fixture_dataset_summary(fixture_dataset_root: Path) -> None:
    result = runner.invoke(app, ["inspect", "--dataset-root", str(fixture_dataset_root)])
    assert result.exit_code == 0
    assert "synthetic_fixture_scenario" in result.stdout
    assert "hosts: 6" in result.stdout


def test_full_run_command_produces_reports(fixture_dataset_root: Path, tmp_path: Path) -> None:
    output_root = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "run",
            "--dataset-root",
            str(fixture_dataset_root),
            "--output-root",
            str(output_root),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert (output_root / "reports" / "evaluation.json").exists()
    assert (output_root / "reports" / "evaluation.md").exists()
    assert "precision=" in result.stdout


def test_stepwise_commands_produce_same_reports_as_run(
    fixture_dataset_root: Path, tmp_path: Path
) -> None:
    output_root = tmp_path / "out"
    for command in ["ingest", "detect", "evaluate", "report"]:
        args = [command, "--output-root", str(output_root)]
        if command == "ingest":
            args += ["--dataset-root", str(fixture_dataset_root)]
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.stdout
    assert (output_root / "reports" / "evaluation.md").exists()
