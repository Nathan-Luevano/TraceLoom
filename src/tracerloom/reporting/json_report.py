from __future__ import annotations

import json
from dataclasses import asdict

from tracerloom.evaluation.metrics import EvaluationReport


def render_json_report(report: EvaluationReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
