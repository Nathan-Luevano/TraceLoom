from datetime import UTC, datetime

from tracerloom.correlation.engine import AttackChainAlert
from tracerloom.detection.alert import Alert
from tracerloom.ingest.pipeline import GroundTruthEvent
from tracerloom.serialization import (
    alert_from_dict,
    alert_to_dict,
    chain_from_dict,
    chain_to_dict,
    ground_truth_from_dict,
    ground_truth_to_dict,
)

_TS = datetime(2031, 6, 1, 8, 0, 0, tzinfo=UTC)


def _sample_alert() -> Alert:
    return Alert(
        alert_id="abc123",
        rule_id="web.scanning.high_rate",
        severity="high",
        confidence=0.8,
        title="title",
        explanation="explanation",
        entities={"host": "webhost"},
        evidence_event_ids=("e1", "e2"),
        first_seen=_TS,
        last_seen=_TS,
        recommended_investigation_steps=("step one", "step two"),
    )


def test_alert_round_trips_through_dict() -> None:
    alert = _sample_alert()
    restored = alert_from_dict(alert_to_dict(alert))
    assert restored == alert


def test_chain_round_trips_through_dict() -> None:
    chain = AttackChainAlert(
        chain_id="chain-1",
        correlation_key="webhost",
        stages=("reconnaissance", "initial_access"),
        alerts=(_sample_alert(),),
        first_seen=_TS,
        last_seen=_TS,
    )
    restored = chain_from_dict(chain_to_dict(chain))
    assert restored == chain


def test_ground_truth_round_trips_through_dict() -> None:
    record = GroundTruthEvent(
        raw_path="auth.log",
        line_number=42,
        event_id="event-42",
        labels=("a", "b"),
        rules={"a": ("rule.a",), "b": ("rule.b1", "rule.b2")},
    )
    restored = ground_truth_from_dict(ground_truth_to_dict(record))
    assert restored == record
