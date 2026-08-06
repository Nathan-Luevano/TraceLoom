from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from tracerloom.correlation.engine import AttackChainAlert
from tracerloom.detection.alert import Alert
from tracerloom.events.model import NormalizedEvent
from tracerloom.ingest.pipeline import GroundTruthEvent

PRECISION_CAVEAT = (
    "Ground-truth labels in this dataset are sparse and cover only a subset of true "
    "attack-related lines. Precision here is a LOWER BOUND: alerts with no labeled "
    "evidence may still be genuine true positives that simply were not labeled, so this "
    "number should not be read as a strict false-positive rate."
)

SCOPE_CAVEAT = (
    "All metrics in this report are specific to a single simulated dataset "
    "(AIT-LDSv2, russellmitchell scenario) and must not be interpreted as general "
    "detection efficacy claims for other environments or attack styles."
)


@dataclass(frozen=True, slots=True)
class SourceBreakdown:
    source_type: str
    event_count: int
    dead_letter_count: int
    alert_count: int


@dataclass(frozen=True, slots=True)
class LabelBreakdown:
    label: str
    occurrence_count: int
    matched_by_alert_count: int


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    total_events: int
    total_dead_letters: int
    parser_success_rate: float
    total_ground_truth_records: int
    event_level_label_coverage: float
    distinct_labels: int
    attack_step_recall: float
    total_alerts: int
    matched_alerts: int
    unmatched_alerts: int
    precision: float
    precision_caveat: str
    mean_detection_latency_seconds: float | None
    unmatched_alerts_per_10k_events: float
    total_chains: int
    attack_chain_coverage: float
    alert_aggregation_ratio: float
    source_breakdown: tuple[SourceBreakdown, ...]
    label_breakdown: tuple[LabelBreakdown, ...]
    scope_caveat: str = SCOPE_CAVEAT


def compute_evaluation_report(
    events: Sequence[NormalizedEvent],
    dead_letter_count: int,
    ground_truth: Sequence[GroundTruthEvent],
    alerts: Sequence[Alert],
    chains: Sequence[AttackChainAlert],
) -> EvaluationReport:
    event_by_id = {event.event_id: event for event in events}

    labeled_records_with_event = [g for g in ground_truth if g.event_id is not None]
    event_level_label_coverage = (
        len(labeled_records_with_event) / len(ground_truth) if ground_truth else 0.0
    )

    label_to_event_ids: dict[str, set[str]] = defaultdict(set)
    for record in labeled_records_with_event:
        assert record.event_id is not None
        for label in record.labels:
            label_to_event_ids[label].add(record.event_id)

    labeled_event_ids: set[str] = {eid for ids in label_to_event_ids.values() for eid in ids}

    matched_alerts: list[Alert] = []
    unmatched_alerts: list[Alert] = []
    for alert in alerts:
        if labeled_event_ids.intersection(alert.evidence_event_ids):
            matched_alerts.append(alert)
        else:
            unmatched_alerts.append(alert)

    precision = len(matched_alerts) / len(alerts) if alerts else 0.0

    covered_labels = 0
    for _label, event_ids in label_to_event_ids.items():
        if any(event_ids.intersection(alert.evidence_event_ids) for alert in alerts):
            covered_labels += 1
    attack_step_recall = covered_labels / len(label_to_event_ids) if label_to_event_ids else 0.0

    latencies: list[float] = []
    for alert in matched_alerts:
        matched_event_ids = labeled_event_ids.intersection(alert.evidence_event_ids)
        matched_timestamps = [
            event_by_id[eid].timestamp for eid in matched_event_ids if eid in event_by_id
        ]
        if matched_timestamps:
            earliest = min(matched_timestamps)
            latencies.append((alert.first_seen - earliest).total_seconds())
    mean_latency = sum(latencies) / len(latencies) if latencies else None

    total_events = len(events)
    unmatched_per_10k = (len(unmatched_alerts) / total_events) * 10_000 if total_events else 0.0

    chains_with_match = sum(
        1 for chain in chains if any(alert in matched_alerts for alert in chain.alerts)
    )
    attack_chain_coverage = chains_with_match / len(chains) if chains else 0.0

    total_evidence = sum(len(alert.evidence_event_ids) for alert in alerts)
    alert_aggregation_ratio = total_evidence / len(alerts) if alerts else 0.0

    parser_success_rate = (
        total_events / (total_events + dead_letter_count)
        if (total_events + dead_letter_count) > 0
        else 0.0
    )

    source_event_counts: dict[str, int] = defaultdict(int)
    for event in events:
        source_event_counts[event.source_type] += 1
    source_alert_counts: dict[str, int] = defaultdict(int)
    for alert in alerts:
        for event_id in alert.evidence_event_ids:
            evidence_event = event_by_id.get(event_id)
            if evidence_event is not None:
                source_alert_counts[evidence_event.source_type] += 1
                break
    source_breakdown = tuple(
        SourceBreakdown(
            source_type=source_type,
            event_count=count,
            dead_letter_count=0,
            alert_count=source_alert_counts.get(source_type, 0),
        )
        for source_type, count in sorted(source_event_counts.items())
    )

    label_breakdown = tuple(
        LabelBreakdown(
            label=label,
            occurrence_count=len(event_ids),
            matched_by_alert_count=sum(
                1 for alert in alerts if event_ids.intersection(alert.evidence_event_ids)
            ),
        )
        for label, event_ids in sorted(label_to_event_ids.items())
    )

    return EvaluationReport(
        total_events=total_events,
        total_dead_letters=dead_letter_count,
        parser_success_rate=parser_success_rate,
        total_ground_truth_records=len(ground_truth),
        event_level_label_coverage=event_level_label_coverage,
        distinct_labels=len(label_to_event_ids),
        attack_step_recall=attack_step_recall,
        total_alerts=len(alerts),
        matched_alerts=len(matched_alerts),
        unmatched_alerts=len(unmatched_alerts),
        precision=precision,
        precision_caveat=PRECISION_CAVEAT,
        mean_detection_latency_seconds=mean_latency,
        unmatched_alerts_per_10k_events=unmatched_per_10k,
        total_chains=len(chains),
        attack_chain_coverage=attack_chain_coverage,
        alert_aggregation_ratio=alert_aggregation_ratio,
        source_breakdown=source_breakdown,
        label_breakdown=label_breakdown,
    )
