from datetime import UTC, datetime, timedelta

from tests.factories import make_event
from tracerloom.correlation.engine import AttackChainAlert
from tracerloom.detection.alert import Alert, compute_alert_id
from tracerloom.evaluation.metrics import compute_evaluation_report
from tracerloom.ingest.pipeline import GroundTruthEvent

_BASE_TIME = datetime(2031, 6, 1, 8, 0, 0, tzinfo=UTC)


def _alert(rule_id: str, evidence_event_ids: tuple[str, ...], seconds_offset: int = 0) -> Alert:
    timestamp = _BASE_TIME + timedelta(seconds=seconds_offset)
    return Alert(
        alert_id=compute_alert_id(rule_id, evidence_event_ids),
        rule_id=rule_id,
        severity="medium",
        confidence=0.5,
        title="synthetic",
        explanation="synthetic",
        entities={},
        evidence_event_ids=evidence_event_ids,
        first_seen=timestamp,
        last_seen=timestamp,
        recommended_investigation_steps=(),
    )


def test_parser_success_rate_and_total_events() -> None:
    events = [make_event(line=1), make_event(line=2)]
    report = compute_evaluation_report(
        events, dead_letter_count=2, ground_truth=[], alerts=[], chains=[]
    )
    assert report.total_events == 2
    assert report.total_dead_letters == 2
    assert report.parser_success_rate == 0.5


def test_event_level_label_coverage() -> None:
    event = make_event(line=1)
    ground_truth = [
        GroundTruthEvent(
            raw_path="x.log", line_number=1, event_id=event.event_id, labels=("a",), rules={}
        ),
        GroundTruthEvent(raw_path="x.log", line_number=99, event_id=None, labels=("b",), rules={}),
    ]
    report = compute_evaluation_report([event], 0, ground_truth, [], [])
    assert report.total_ground_truth_records == 2
    assert report.event_level_label_coverage == 0.5


def test_attack_step_recall_and_precision_with_matched_alert() -> None:
    event = make_event(line=1)
    ground_truth = [
        GroundTruthEvent(
            raw_path="x.log", line_number=1, event_id=event.event_id, labels=("recon",), rules={}
        )
    ]
    matching_alert = _alert("web.scanning.high_rate", (event.event_id,))
    unrelated_event = make_event(line=2)
    unmatched_alert = _alert("web.webshell.command_heuristic", (unrelated_event.event_id,))

    report = compute_evaluation_report(
        [event, unrelated_event], 0, ground_truth, [matching_alert, unmatched_alert], []
    )
    assert report.attack_step_recall == 1.0
    assert report.matched_alerts == 1
    assert report.unmatched_alerts == 1
    assert report.precision == 0.5
    assert "lower bound" in report.precision_caveat.lower()


def test_detection_latency_is_computed_for_matched_alerts() -> None:
    event = make_event(line=1)
    ground_truth = [
        GroundTruthEvent(
            raw_path="x.log", line_number=1, event_id=event.event_id, labels=("recon",), rules={}
        )
    ]
    alert = _alert("web.scanning.high_rate", (event.event_id,), seconds_offset=120)
    report = compute_evaluation_report([event], 0, ground_truth, [alert], [])
    assert report.mean_detection_latency_seconds == 120.0


def test_unmatched_alerts_per_10k_events() -> None:
    events = [make_event(line=i) for i in range(1, 101)]
    unmatched_alert = _alert("web.scanning.high_rate", (events[0].event_id,))
    report = compute_evaluation_report(events, 0, [], [unmatched_alert], [])
    assert report.unmatched_alerts == 1
    assert report.unmatched_alerts_per_10k_events == 100.0


def test_attack_chain_coverage() -> None:
    event = make_event(line=1)
    ground_truth = [
        GroundTruthEvent(
            raw_path="x.log", line_number=1, event_id=event.event_id, labels=("recon",), rules={}
        )
    ]
    matched_alert = _alert("web.scanning.high_rate", (event.event_id,))
    other_event = make_event(line=2)
    other_alert = _alert("web.webshell.command_heuristic", (other_event.event_id,))
    chain_with_match = AttackChainAlert(
        chain_id="chain-1",
        correlation_key="host-a",
        stages=("reconnaissance", "initial_access"),
        alerts=(matched_alert, other_alert),
        first_seen=_BASE_TIME,
        last_seen=_BASE_TIME,
    )
    chain_without_match = AttackChainAlert(
        chain_id="chain-2",
        correlation_key="host-b",
        stages=("reconnaissance", "initial_access"),
        alerts=(other_alert,),
        first_seen=_BASE_TIME,
        last_seen=_BASE_TIME,
    )
    report = compute_evaluation_report(
        [event, other_event],
        0,
        ground_truth,
        [matched_alert, other_alert],
        [chain_with_match, chain_without_match],
    )
    assert report.total_chains == 2
    assert report.attack_chain_coverage == 0.5


def test_alert_aggregation_ratio() -> None:
    events = [make_event(line=i) for i in range(1, 5)]
    alert_with_four_events = _alert("web.scanning.high_rate", tuple(e.event_id for e in events))
    report = compute_evaluation_report(events, 0, [], [alert_with_four_events], [])
    assert report.alert_aggregation_ratio == 4.0


def test_source_and_label_breakdowns() -> None:
    web_event = make_event(line=1, source_type="web_access")
    dns_event = make_event(line=2, source_type="dns")
    ground_truth = [
        GroundTruthEvent(
            raw_path="x.log",
            line_number=1,
            event_id=web_event.event_id,
            labels=("recon",),
            rules={},
        )
    ]
    matching_alert = _alert("web.scanning.high_rate", (web_event.event_id,))
    report = compute_evaluation_report(
        [web_event, dns_event], 0, ground_truth, [matching_alert], []
    )
    source_types = {b.source_type for b in report.source_breakdown}
    assert source_types == {"web_access", "dns"}
    assert report.label_breakdown[0].label == "recon"
    assert report.label_breakdown[0].matched_by_alert_count == 1
