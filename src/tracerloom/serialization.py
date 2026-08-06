from __future__ import annotations

from datetime import datetime
from typing import Any

from tracerloom.correlation.engine import AttackChainAlert
from tracerloom.detection.alert import Alert
from tracerloom.evaluation.metrics import EvaluationReport, LabelBreakdown, SourceBreakdown
from tracerloom.ingest.pipeline import GroundTruthEvent


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "title": alert.title,
        "explanation": alert.explanation,
        "entities": alert.entities,
        "evidence_event_ids": list(alert.evidence_event_ids),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "recommended_investigation_steps": list(alert.recommended_investigation_steps),
    }


def alert_from_dict(data: dict[str, Any]) -> Alert:
    return Alert(
        alert_id=data["alert_id"],
        rule_id=data["rule_id"],
        severity=data["severity"],
        confidence=data["confidence"],
        title=data["title"],
        explanation=data["explanation"],
        entities=data["entities"],
        evidence_event_ids=tuple(data["evidence_event_ids"]),
        first_seen=datetime.fromisoformat(data["first_seen"]),
        last_seen=datetime.fromisoformat(data["last_seen"]),
        recommended_investigation_steps=tuple(data["recommended_investigation_steps"]),
    )


def chain_to_dict(chain: AttackChainAlert) -> dict[str, Any]:
    return {
        "chain_id": chain.chain_id,
        "correlation_key": chain.correlation_key,
        "stages": list(chain.stages),
        "alerts": [alert_to_dict(a) for a in chain.alerts],
        "first_seen": chain.first_seen.isoformat(),
        "last_seen": chain.last_seen.isoformat(),
    }


def chain_from_dict(data: dict[str, Any]) -> AttackChainAlert:
    return AttackChainAlert(
        chain_id=data["chain_id"],
        correlation_key=data["correlation_key"],
        stages=tuple(data["stages"]),
        alerts=tuple(alert_from_dict(a) for a in data["alerts"]),
        first_seen=datetime.fromisoformat(data["first_seen"]),
        last_seen=datetime.fromisoformat(data["last_seen"]),
    )


def ground_truth_to_dict(record: GroundTruthEvent) -> dict[str, Any]:
    return {
        "raw_path": record.raw_path,
        "line_number": record.line_number,
        "event_id": record.event_id,
        "labels": list(record.labels),
        "rules": {key: list(value) for key, value in record.rules.items()},
    }


def ground_truth_from_dict(data: dict[str, Any]) -> GroundTruthEvent:
    return GroundTruthEvent(
        raw_path=data["raw_path"],
        line_number=data["line_number"],
        event_id=data["event_id"],
        labels=tuple(data["labels"]),
        rules={key: tuple(value) for key, value in data["rules"].items()},
    )


def report_from_dict(data: dict[str, Any]) -> EvaluationReport:
    return EvaluationReport(
        total_events=data["total_events"],
        total_dead_letters=data["total_dead_letters"],
        parser_success_rate=data["parser_success_rate"],
        total_ground_truth_records=data["total_ground_truth_records"],
        event_level_label_coverage=data["event_level_label_coverage"],
        distinct_labels=data["distinct_labels"],
        attack_step_recall=data["attack_step_recall"],
        total_alerts=data["total_alerts"],
        matched_alerts=data["matched_alerts"],
        unmatched_alerts=data["unmatched_alerts"],
        precision=data["precision"],
        precision_caveat=data["precision_caveat"],
        mean_detection_latency_seconds=data["mean_detection_latency_seconds"],
        unmatched_alerts_per_10k_events=data["unmatched_alerts_per_10k_events"],
        total_chains=data["total_chains"],
        attack_chain_coverage=data["attack_chain_coverage"],
        alert_aggregation_ratio=data["alert_aggregation_ratio"],
        source_breakdown=tuple(SourceBreakdown(**entry) for entry in data["source_breakdown"]),
        label_breakdown=tuple(LabelBreakdown(**entry) for entry in data["label_breakdown"]),
        scope_caveat=data["scope_caveat"],
    )
