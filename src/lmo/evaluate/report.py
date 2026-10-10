"""Human-readable and JSON rendering of an evaluation."""

from __future__ import annotations

import json
from pathlib import Path


def render_eval(report: dict) -> str:
    kind = report.get("metric_kind", "stage")
    lines = [
        f"evaluate  world={report['world']}  kind={report['world_kind']}"
        f"  metric={kind}  seed={report.get('seed')!s}  days={report['n_days']}",
        f"  labelled events: {report['n_labelled_events']:,}    "
        f"layered alerts: {report['n_layered_alerts']:,}    "
        f"naive first-contact units: {report['n_naive_alerts']:,}",
        "",
    ]
    if kind == "event":
        lines += [
            f"{'budget/day':>10}  {'detector':<10}{'hit':>8}{'ev rec':>8}"
            f"{'TTD s':>10}{'prec':>8}{'alerts/d':>10}",
            "-" * 72,
        ]
        for row in report["budgets"]:
            ttd = row["time_to_detection_sec"]
            ttd_s = "-" if ttd is None else f"{ttd:,.0f}"
            lines.append(
                f"{row['budget_per_day']:>10}  {row['detector']:<10}"
                f"{row.get('n_labelled_hit', 0):>8}"
                f"{row.get('event_recall', 0):>8.2f}"
                f"{ttd_s:>10}{row['precision']:>8.3f}"
                f"{row['alerts_per_day']:>10.2f}"
            )
    else:
        lines += [
            f"{'budget/day':>10}  {'detector':<10}{'stages':>8}{'recall':>8}"
            f"{'TTD s':>10}{'prec':>8}{'alerts/d':>10}  stages hit",
            "-" * 88,
        ]
        for row in report["budgets"]:
            ttd = row["time_to_detection_sec"]
            ttd_s = "-" if ttd is None else f"{ttd:,.0f}"
            stages = ",".join(str(s) for s in row["stages_hit"]) or "-"
            lines.append(
                f"{row['budget_per_day']:>10}  {row['detector']:<10}"
                f"{len(row['stages_hit']):>3}/{4:<3}"
                f"{row['stage_recall']:>8.2f}"
                f"{ttd_s:>10}{row['precision']:>8.3f}"
                f"{row['alerts_per_day']:>10.2f}  {stages}"
            )

    vol = report.get("clean_volume_per_day")
    if vol:
        lines += [
            "",
            "clean-world volume at the configured score bands "
            "(every alert here is a false positive):",
            f"  high    {vol.get('high', 0):8.2f} / day",
            f"  medium  {vol.get('medium', 0):8.2f} / day",
            f"  low     {vol.get('low', 0):8.2f} / day",
            f"  any     {vol.get('any', 0):8.2f} / day",
        ]
    return "\n".join(lines)


def write_report(report: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def curve_table(report: dict, detector: str = "layered") -> str:
    """Markdown table of recall against alerts-per-day, for the README."""
    kind = report.get("metric_kind", "stage")
    if kind == "event":
        lines = [
            "| Alert budget (per day) | Event recall | Time to first true alert | Precision |",
            "|---|---|---|---|",
        ]
        for row in report["budgets"]:
            if row["detector"] != detector:
                continue
            ttd = row["time_to_detection_sec"]
            ttd_s = "-" if ttd is None else f"{ttd:,.0f} s"
            lines.append(
                f"| {row['budget_per_day']} "
                f"| {row.get('n_labelled_hit', 0)}/"
                f"{report['n_labelled_events']} "
                f"({row.get('event_recall', 0):.2f}) "
                f"| {ttd_s} "
                f"| {row['precision']:.3f} |"
            )
        return "\n".join(lines)
    lines = [
        "| Alert budget (per day) | Stage recall | Time to first true alert | Precision |",
        "|---|---|---|---|",
    ]
    for row in report["budgets"]:
        if row["detector"] != detector:
            continue
        ttd = row["time_to_detection_sec"]
        ttd_s = "-" if ttd is None else f"{ttd:,.0f} s"
        lines.append(
            f"| {row['budget_per_day']} "
            f"| {len(row['stages_hit'])}/4 ({row['stage_recall']:.2f}) "
            f"| {ttd_s} "
            f"| {row['precision']:.3f} |"
        )
    return "\n".join(lines)
