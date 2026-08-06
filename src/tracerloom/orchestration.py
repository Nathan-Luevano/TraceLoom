from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tracerloom.config import TracerloomConfig
from tracerloom.correlation.engine import AttackChainAlert, CorrelationEngine
from tracerloom.detection.alert import Alert
from tracerloom.detection.registry import default_detectors
from tracerloom.discovery.scan import discover_dataset
from tracerloom.evaluation.metrics import EvaluationReport, compute_evaluation_report
from tracerloom.events.model import NormalizedEvent
from tracerloom.ingest.pipeline import GroundTruthEvent, IngestResult, run_ingestion
from tracerloom.parsing.registry import default_registry
from tracerloom.sources.local_files import LocalFileEventSource
from tracerloom.storage.parquet_store import read_events, write_events


def _reference_year(discovery_start: str) -> int:
    return datetime.fromisoformat(discovery_start).year


@dataclass(slots=True)
class PipelineArtifacts:
    dataset_name: str
    ingest_result: IngestResult
    alerts: list[Alert]
    chains: list[AttackChainAlert]
    report: EvaluationReport


def run_ingest_phase(config: TracerloomConfig) -> tuple[str, IngestResult]:
    discovery = discover_dataset(config.dataset_root)
    source = LocalFileEventSource(dataset_root=config.dataset_root)
    registry = default_registry(reference_year=_reference_year(discovery.simulation_start))
    result = run_ingestion(source, registry, dataset=discovery.dataset_name)
    write_events(result.events, config.parquet_dir)
    return discovery.dataset_name, result


def run_detect_phase(events: list[NormalizedEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for detector in default_detectors():
        alerts.extend(detector.detect(events))
    return alerts


def run_correlate_phase(alerts: list[Alert]) -> list[AttackChainAlert]:
    engine = CorrelationEngine()
    return engine.correlate(alerts)


def run_evaluate_phase(
    events: list[NormalizedEvent],
    dead_letter_count: int,
    ground_truth: list[GroundTruthEvent],
    alerts: list[Alert],
    chains: list[AttackChainAlert],
) -> EvaluationReport:
    return compute_evaluation_report(events, dead_letter_count, ground_truth, alerts, chains)


def run_full_pipeline(config: TracerloomConfig) -> PipelineArtifacts:
    dataset_name, ingest_result = run_ingest_phase(config)
    alerts = run_detect_phase(ingest_result.events)
    chains = run_correlate_phase(alerts)
    report = run_evaluate_phase(
        ingest_result.events,
        len(ingest_result.dead_letters),
        ingest_result.ground_truth,
        alerts,
        chains,
    )
    return PipelineArtifacts(
        dataset_name=dataset_name,
        ingest_result=ingest_result,
        alerts=alerts,
        chains=chains,
        report=report,
    )


def load_events_from_parquet(config: TracerloomConfig) -> list[NormalizedEvent]:
    return read_events(config.parquet_dir)
