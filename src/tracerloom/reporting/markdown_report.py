from __future__ import annotations

from tracerloom.evaluation.metrics import EvaluationReport


def render_markdown_report(report: EvaluationReport, dataset_name: str) -> str:
    latency = (
        f"{report.mean_detection_latency_seconds:.1f}s"
        if report.mean_detection_latency_seconds is not None
        else "n/a (no matched alerts)"
    )
    lines: list[str] = [
        f"# TracerLoom Evaluation Report -- {dataset_name}",
        "",
        f"> {report.scope_caveat}",
        "",
        "## Ingestion",
        "",
        f"- Total normalized events: {report.total_events}",
        f"- Total dead-lettered lines: {report.total_dead_letters}",
        f"- Parser success rate: {report.parser_success_rate:.1%}",
        f"- Total ground-truth label records: {report.total_ground_truth_records}",
        f"- Event-level label coverage: {report.event_level_label_coverage:.1%}",
        f"- Distinct labels observed: {report.distinct_labels}",
        "",
        "## Detection",
        "",
        f"- Total alerts: {report.total_alerts}",
        f"- Alerts matched to ground truth: {report.matched_alerts}",
        f"- Unmatched alerts: {report.unmatched_alerts}",
        f"- Precision (matched / total): {report.precision:.1%}",
        f"- Attack-step recall: {report.attack_step_recall:.1%}",
        f"- Mean detection latency: {latency}",
        f"- Unmatched alerts per 10,000 events: {report.unmatched_alerts_per_10k_events:.2f}",
        f"- Alert aggregation ratio (evidence / alert): {report.alert_aggregation_ratio:.2f}",
        "",
        f"> {report.precision_caveat}",
        "",
        "## Correlation",
        "",
        f"- Attack chains produced: {report.total_chains}",
        f"- Attack-chain coverage (chains w/ matched evidence): {report.attack_chain_coverage:.1%}",
        "",
        "## Breakdown by source type",
        "",
        "| Source type | Events | Alerts |",
        "| --- | ---: | ---: |",
    ]
    for entry in report.source_breakdown:
        lines.append(f"| {entry.source_type} | {entry.event_count} | {entry.alert_count} |")

    lines += [
        "",
        "## Breakdown by label",
        "",
        "| Label | Occurrences | Matched by alert |",
        "| --- | ---: | ---: |",
    ]
    for label_entry in report.label_breakdown:
        lines.append(
            f"| {label_entry.label} | {label_entry.occurrence_count} | "
            f"{label_entry.matched_by_alert_count} |"
        )

    lines.append("")
    return "\n".join(lines)
