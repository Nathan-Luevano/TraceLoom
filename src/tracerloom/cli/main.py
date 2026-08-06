from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from tracerloom.config import TracerloomConfig, load_config
from tracerloom.discovery.scan import discover_dataset
from tracerloom.logging_setup import configure_logging
from tracerloom.orchestration import (
    load_events_from_parquet,
    run_correlate_phase,
    run_detect_phase,
    run_evaluate_phase,
    run_ingest_phase,
)
from tracerloom.reporting.json_report import render_json_report
from tracerloom.reporting.markdown_report import render_markdown_report
from tracerloom.serialization import (
    alert_from_dict,
    alert_to_dict,
    chain_from_dict,
    chain_to_dict,
    ground_truth_from_dict,
    ground_truth_to_dict,
    report_from_dict,
)

app = typer.Typer(add_completion=False, help="TracerLoom: log-native detection pipeline")
logger = logging.getLogger("tracerloom.cli")


def _resolve_config(
    config_path: Path | None, dataset_root: Path | None, output_root: Path | None
) -> TracerloomConfig:
    config = load_config(config_path)
    return config.with_overrides(dataset_root=dataset_root, output_root=output_root)


def _ingest_meta_path(config: TracerloomConfig) -> Path:
    return config.output_root / "ingest_meta.json"


def _ground_truth_path(config: TracerloomConfig) -> Path:
    return config.output_root / "ground_truth.json"


def _alerts_path(config: TracerloomConfig) -> Path:
    return config.output_root / "alerts.json"


def _chains_path(config: TracerloomConfig) -> Path:
    return config.output_root / "chains.json"


def _evaluation_json_path(config: TracerloomConfig) -> Path:
    return config.reports_dir / "evaluation.json"


def _evaluation_md_path(config: TracerloomConfig) -> Path:
    return config.reports_dir / "evaluation.md"


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    configure_logging(level=logging.DEBUG if verbose else logging.INFO)


@app.command()
def inspect(
    dataset_root: Path = typer.Option(Path("russellmitchell_no-pcaps"), "--dataset-root"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    resolved = _resolve_config(config, dataset_root, None)
    discovery = discover_dataset(resolved.dataset_root)
    typer.echo(f"dataset: {discovery.dataset_name}")
    typer.echo(f"simulation window: {discovery.simulation_start} .. {discovery.simulation_end}")
    typer.echo(f"hosts: {len(discovery.hosts)}")
    typer.echo(f"log files: {discovery.total_log_files}")
    typer.echo(f"labeled log files: {discovery.total_labeled_files}")
    for warning in discovery.warnings:
        typer.echo(f"warning: {warning}")


@app.command()
def ingest(
    dataset_root: Path = typer.Option(Path("russellmitchell_no-pcaps"), "--dataset-root"),
    output_root: Path | None = typer.Option(None, "--output-root"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    resolved = _resolve_config(config, dataset_root, output_root)
    resolved.output_root.mkdir(parents=True, exist_ok=True)
    dataset_name, result = run_ingest_phase(resolved)

    _ingest_meta_path(resolved).write_text(
        json.dumps(
            {
                "dataset_name": dataset_name,
                "dead_letter_count": len(result.dead_letters),
                "files_seen": result.files_seen,
                "files_without_parser": result.files_without_parser,
            },
            indent=2,
        )
    )
    _ground_truth_path(resolved).write_text(
        json.dumps([ground_truth_to_dict(g) for g in result.ground_truth], indent=2)
    )
    resolved.dead_letter_dir.mkdir(parents=True, exist_ok=True)
    (resolved.dead_letter_dir / "dead_letters.jsonl").write_text(
        "\n".join(
            json.dumps(
                {
                    "raw_path": d.raw_path,
                    "line_number": d.line_number,
                    "reason": d.reason,
                }
            )
            for d in result.dead_letters
        )
    )
    typer.echo(f"ingested {len(result.events)} events, {len(result.dead_letters)} dead-lettered")


@app.command()
def detect(
    output_root: Path | None = typer.Option(None, "--output-root"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    resolved = _resolve_config(config, None, output_root)
    events = load_events_from_parquet(resolved)
    alerts = run_detect_phase(events)
    chains = run_correlate_phase(alerts)

    _alerts_path(resolved).write_text(json.dumps([alert_to_dict(a) for a in alerts], indent=2))
    _chains_path(resolved).write_text(json.dumps([chain_to_dict(c) for c in chains], indent=2))
    typer.echo(f"produced {len(alerts)} alerts, {len(chains)} attack chains")


@app.command()
def evaluate(
    output_root: Path | None = typer.Option(None, "--output-root"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    resolved = _resolve_config(config, None, output_root)
    events = load_events_from_parquet(resolved)
    meta = json.loads(_ingest_meta_path(resolved).read_text())
    ground_truth = [
        ground_truth_from_dict(item)
        for item in json.loads(_ground_truth_path(resolved).read_text())
    ]
    alerts = [alert_from_dict(item) for item in json.loads(_alerts_path(resolved).read_text())]
    chains = [chain_from_dict(item) for item in json.loads(_chains_path(resolved).read_text())]

    report = run_evaluate_phase(events, meta["dead_letter_count"], ground_truth, alerts, chains)

    resolved.reports_dir.mkdir(parents=True, exist_ok=True)
    _evaluation_json_path(resolved).write_text(render_json_report(report))
    typer.echo(
        f"precision={report.precision:.2f} attack_step_recall={report.attack_step_recall:.2f}"
    )


@app.command()
def report(
    output_root: Path | None = typer.Option(None, "--output-root"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    resolved = _resolve_config(config, None, output_root)
    meta = json.loads(_ingest_meta_path(resolved).read_text())
    data = json.loads(_evaluation_json_path(resolved).read_text())
    evaluation_report = report_from_dict(data)
    markdown = render_markdown_report(evaluation_report, dataset_name=meta["dataset_name"])
    _evaluation_md_path(resolved).write_text(markdown)
    typer.echo(markdown)


@app.command()
def run(
    dataset_root: Path = typer.Option(Path("russellmitchell_no-pcaps"), "--dataset-root"),
    output_root: Path | None = typer.Option(None, "--output-root"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    resolved = _resolve_config(config, dataset_root, output_root)
    resolved.output_root.mkdir(parents=True, exist_ok=True)
    resolved.reports_dir.mkdir(parents=True, exist_ok=True)

    dataset_name, ingest_result = run_ingest_phase(resolved)
    alerts = run_detect_phase(ingest_result.events)
    chains = run_correlate_phase(alerts)
    evaluation_report = run_evaluate_phase(
        ingest_result.events,
        len(ingest_result.dead_letters),
        ingest_result.ground_truth,
        alerts,
        chains,
    )

    _evaluation_json_path(resolved).write_text(render_json_report(evaluation_report))
    markdown = render_markdown_report(evaluation_report, dataset_name=dataset_name)
    _evaluation_md_path(resolved).write_text(markdown)

    typer.echo(f"dataset: {dataset_name}")
    typer.echo(
        f"events: {len(ingest_result.events)}, dead-lettered: {len(ingest_result.dead_letters)}"
    )
    typer.echo(f"alerts: {len(alerts)}, attack chains: {len(chains)}")
    typer.echo(
        f"precision={evaluation_report.precision:.2f} "
        f"attack_step_recall={evaluation_report.attack_step_recall:.2f}"
    )
    typer.echo(f"reports written to {resolved.reports_dir}")


if __name__ == "__main__":
    app()
