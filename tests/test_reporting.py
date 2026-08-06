import json

from tests.factories import make_event
from tracerloom.evaluation.metrics import EvaluationReport, compute_evaluation_report
from tracerloom.reporting.json_report import render_json_report
from tracerloom.reporting.markdown_report import render_markdown_report


def _sample_report() -> EvaluationReport:
    events = [make_event(line=1)]
    return compute_evaluation_report(
        events, dead_letter_count=1, ground_truth=[], alerts=[], chains=[]
    )


def test_json_report_is_valid_json_with_expected_keys() -> None:
    report = _sample_report()
    rendered = render_json_report(report)
    payload = json.loads(rendered)
    assert payload["total_events"] == 1
    assert payload["total_dead_letters"] == 1
    assert "precision_caveat" in payload
    assert "scope_caveat" in payload


def test_markdown_report_includes_caveats_and_dataset_name() -> None:
    report = _sample_report()
    rendered = render_markdown_report(report, dataset_name="synthetic_fixture_scenario")
    assert "synthetic_fixture_scenario" in rendered
    assert report.precision_caveat in rendered
    assert report.scope_caveat in rendered
    assert "Parser success rate" in rendered
