from datetime import UTC, datetime, timedelta

from tracerloom.correlation.engine import CorrelationEngine
from tracerloom.detection.alert import Alert, compute_alert_id

_BASE_TIME = datetime(2031, 6, 1, 8, 0, 0, tzinfo=UTC)


def _make_alert(rule_id: str, entities: dict[str, str], minutes_offset: int) -> Alert:
    timestamp = _BASE_TIME + timedelta(minutes=minutes_offset)
    evidence = (f"evidence-{rule_id}-{minutes_offset}",)
    return Alert(
        alert_id=compute_alert_id(rule_id, evidence),
        rule_id=rule_id,
        severity="medium",
        confidence=0.6,
        title="synthetic",
        explanation="synthetic",
        entities=entities,
        evidence_event_ids=evidence,
        first_seen=timestamp,
        last_seen=timestamp,
        recommended_investigation_steps=(),
    )


def test_correlates_multi_stage_chain_on_same_host() -> None:
    engine = CorrelationEngine(window=timedelta(hours=6), min_distinct_stages=2)
    alerts = [
        _make_alert("web.scanning.high_rate", {"host": "webhost"}, 0),
        _make_alert("auth.escalation.user_switch_from_web_context", {"host": "webhost"}, 30),
        _make_alert("privilege.sensitive_access.command_or_file", {"host": "webhost"}, 45),
    ]
    chains = engine.correlate(alerts)
    assert len(chains) == 1
    assert chains[0].stages == ("reconnaissance", "privilege_escalation", "command_execution")
    assert len(chains[0].alerts) == 3


def test_does_not_correlate_single_stage_or_different_hosts() -> None:
    engine = CorrelationEngine(window=timedelta(hours=6), min_distinct_stages=2)
    alerts = [
        _make_alert("web.scanning.high_rate", {"host": "webhost-a"}, 0),
        _make_alert("web.scanning.high_rate", {"host": "webhost-a"}, 5),
        _make_alert("auth.escalation.user_switch_from_web_context", {"host": "webhost-b"}, 10),
    ]
    chains = engine.correlate(alerts)
    assert chains == []


def test_does_not_correlate_alerts_outside_time_window() -> None:
    engine = CorrelationEngine(window=timedelta(minutes=10), min_distinct_stages=2)
    alerts = [
        _make_alert("web.scanning.high_rate", {"host": "webhost"}, 0),
        _make_alert("auth.escalation.user_switch_from_web_context", {"host": "webhost"}, 120),
    ]
    chains = engine.correlate(alerts)
    assert chains == []
