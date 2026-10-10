"""Orchestration: events → units → signals → scored alerts.

The pipeline is a sequence of SQL passes with one Python scoring loop at the
end. Scoring is a weighted sum of named numbers; doing it in Python keeps the
weights in one dataclass and makes "same input, same score" a trivial test
rather than a property of JSON-object key order in SQL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from lmo.detect.baseline import (
    apply_baseline_signals,
    build_bucket_dsts,
    build_detect_auth,
    build_trailing,
    resolve_day_range,
)
from lmo.detect.graph_signals import apply_graph_signals
from lmo.detect.rules import aggregate_rules_onto_units, emit_rule_signals
from lmo.detect.schema import (
    BUCKET_SECONDS,
    DETECT_SCHEMA_VERSION,
    create_detect_tables,
    reset_detect_outputs,
)
from lmo.detect.score import SQL_NORMALIZERS, ScoreConfig
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse, timer
from lmo.ontology.build import graph_is_stale, require_fresh_graph


@dataclass
class DetectReport:
    run_id: str
    graph_id: str
    start_day: int
    end_day: int
    n_units: int = 0
    n_signals: int = 0
    n_alerts: int = 0
    n_high: int = 0
    n_medium: int = 0
    n_low: int = 0
    seconds: float = 0.0
    weights: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "graph_id": self.graph_id,
            "start_day": self.start_day,
            "end_day": self.end_day,
            "n_units": self.n_units,
            "n_signals": self.n_signals,
            "n_alerts": self.n_alerts,
            "bands": {
                "high": self.n_high,
                "medium": self.n_medium,
                "low": self.n_low,
            },
            "seconds": round(self.seconds, 3),
            "weights": self.weights,
        }

    def render(self) -> str:
        lines = [
            f"detect {self.run_id}   graph={self.graph_id}",
            f"days {self.start_day}-{self.end_day}   "
            f"{self.n_units:,} units   {self.n_signals:,} event signals",
            "",
            f"{'band':<10}{'alerts':>10}",
            "-" * 20,
            f"{'high':<10}{self.n_high:>10,}",
            f"{'medium':<10}{self.n_medium:>10,}",
            f"{'low':<10}{self.n_low:>10,}",
            "-" * 20,
            f"{'total':<10}{self.n_alerts:>10,}   {self.seconds:.2f}s",
        ]
        return "\n".join(lines)


def _build_units(wh: Warehouse, start_day: int, end_day: int) -> int:
    wh.con.execute(
        f"""
        INSERT INTO detect_units (
            user_uid, src_host, bucket_start_sec, bucket_end_sec, day_index,
            n_events, n_distinct_dst, n_fail, event_uids
        )
        SELECT src_user_uid,
               src_endpoint,
               (time_sec // {BUCKET_SECONDS}) * {BUCKET_SECONDS},
               (time_sec // {BUCKET_SECONDS}) * {BUCKET_SECONDS} + {BUCKET_SECONDS},
               min(day_index),
               count(*),
               count(DISTINCT dst_endpoint),
               count(*) FILTER (status_id = 2),
               list(event_uid ORDER BY time_sec, event_uid)
        FROM detect_auth
        WHERE src_endpoint IS NOT NULL
          AND day_index BETWEEN ? AND ?
        GROUP BY 1, 2, 3, 4
        """,
        [start_day, end_day],
    )
    return wh.count("detect_units")


def _score_units(wh: Warehouse, run_id: str, config: ScoreConfig) -> tuple[int, int, int, int]:
    """One INSERT SELECT. Per-row Python inserts were ~40ms each in DuckDB."""
    norm_select = []
    contrib_terms = []
    json_fields = []
    for name, weight in config.weights.items():
        n_expr = SQL_NORMALIZERS[name]
        n_col = f"n_{name}"
        norm_select.append(f"{n_expr} AS {n_col}")
        contrib_terms.append(f"{n_col} * {float(weight)}")
        json_fields.append(
            f"'{name}', round({n_col} * {float(weight)}, 6)"
        )
    score_expr = " + ".join(contrib_terms) if contrib_terms else "0"
    json_expr = "json_object(" + ", ".join(json_fields) + ")"
    now = datetime.now(timezone.utc)
    wh.con.execute(
        f"""
        INSERT INTO alerts
        SELECT
            md5(? || '|' || user_uid || '|' || src_host || '|'
                || bucket_start_sec::VARCHAR),
            ?,
            user_uid, src_host, bucket_start_sec, bucket_end_sec,
            score,
            CASE
                WHEN score >= ? THEN 'high'
                WHEN score >= ? THEN 'medium'
                ELSE 'low'
            END,
            n_events, n_distinct_dst, n_fail,
            signals_json,
            event_uids,
            ?
        FROM (
            SELECT u.*,
                   round({score_expr}, 6) AS score,
                   {json_expr}::VARCHAR AS signals_json
            FROM (
                SELECT *, {", ".join(norm_select)}
                FROM detect_units
            ) u
        )
        WHERE score > ?
        """,
        [
            run_id,
            run_id,
            config.high_threshold,
            config.medium_threshold,
            now,
            config.low_threshold,
        ],
    )
    n_alerts = wh.count("alerts")
    counts = dict(
        wh.con.execute(
            "SELECT band, count(*) FROM alerts GROUP BY 1"
        ).fetchall()
    )
    return (
        n_alerts,
        int(counts.get("high", 0)),
        int(counts.get("medium", 0)),
        int(counts.get("low", 0)),
    )


def run_detect(
    wh: Warehouse,
    *,
    start_day: int | None = None,
    end_day: int | None = None,
    config: ScoreConfig | None = None,
) -> DetectReport:
    """Rebuild every detect table from the current events and graph."""
    graph_id = require_fresh_graph(wh)
    config = config or ScoreConfig()
    start_day, end_day = resolve_day_range(wh, start_day, end_day)

    create_detect_tables(wh)
    reset_detect_outputs(wh)

    run_id = f"detect_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}"
    report = DetectReport(
        run_id=run_id,
        graph_id=graph_id,
        start_day=start_day,
        end_day=end_day,
        weights=dict(config.weights),
    )
    t0 = timer()

    build_detect_auth(wh)
    build_trailing(wh)
    report.n_units = _build_units(wh, start_day, end_day)
    if report.n_units == 0:
        raise LmoError(
            "no authentication buckets in that day range",
            "Check --start-day/--end-day against 'lmo profile', or ingest first.",
        )

    build_bucket_dsts(wh)
    report.n_signals = emit_rule_signals(wh, run_id)
    aggregate_rules_onto_units(wh)
    apply_graph_signals(wh)
    apply_baseline_signals(wh)

    n_alerts, n_high, n_medium, n_low = _score_units(wh, run_id, config)
    report.n_alerts = n_alerts
    report.n_high = n_high
    report.n_medium = n_medium
    report.n_low = n_low
    report.seconds = timer() - t0

    stale, _ = graph_is_stale(wh)
    if stale:
        # Scoring read graph tables; if ingest happened mid-run we would
        # rather refuse than emit a mixture of two worlds.
        raise LmoError(
            "the ontology went out of date while detection was running",
            "Run 'lmo build-graph' and then 'lmo detect' again.",
        )

    wh.con.execute(
        """
        INSERT OR REPLACE INTO detect_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        [
            run_id,
            datetime.now(timezone.utc),
            DETECT_SCHEMA_VERSION,
            graph_id,
            start_day,
            end_day,
            report.n_units,
            report.n_alerts,
            report.n_signals,
            report.seconds,
            json.dumps(config.weights, sort_keys=True),
            json.dumps(
                {"high": n_high, "medium": n_medium, "low": n_low},
                sort_keys=True,
            ),
        ],
    )
    return report


def latest_detect_run(wh: Warehouse) -> str:
    try:
        row = wh.con.execute(
            "SELECT run_id FROM detect_runs ORDER BY built_at DESC LIMIT 1"
        ).fetchone()
    except Exception:
        row = None
    if row is None:
        raise LmoError(
            "no detect run has been recorded yet",
            "Run 'lmo detect' first -- alerts are produced by that step.",
        )
    return row[0]


def require_alerts(wh: Warehouse) -> str:
    return latest_detect_run(wh)


def list_alerts(
    wh: Warehouse,
    *,
    band: str | None = None,
    day: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    require_fresh_graph(wh)
    require_alerts(wh)
    if limit < 1:
        raise LmoError("limit must be at least 1", "Pass a positive --limit.")
    if offset < 0:
        raise LmoError("offset cannot be negative", "Pass offset >= 0.")
    clauses = ["1=1"]
    params: list = []
    if band is not None:
        clauses.append("band = ?")
        params.append(band)
    if day is not None:
        clauses.append(
            f"bucket_start_sec >= ? * 86400 AND bucket_start_sec < (? + 1) * 86400"
        )
        params += [day, day]
    rows = wh.con.execute(
        f"""
        SELECT alert_uid, user_uid, src_host, bucket_start_sec, bucket_end_sec,
               score, band, n_events, n_distinct_dst, n_fail, signals_json,
               event_uids
        FROM alerts
        WHERE {' AND '.join(clauses)}
        ORDER BY score DESC, bucket_start_sec, user_uid, src_host
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def get_alert(wh: Warehouse, alert_uid: str) -> dict:
    require_fresh_graph(wh)
    require_alerts(wh)
    row = wh.con.execute(
        """
        SELECT alert_uid, run_id, user_uid, src_host,
               bucket_start_sec, bucket_end_sec,
               score, band, n_events, n_distinct_dst, n_fail,
               signals_json, event_uids, created_at
        FROM alerts WHERE alert_uid = ?
        """,
        [alert_uid],
    ).fetchone()
    if row is None:
        raise LmoError(
            f"no alert with uid {alert_uid!r}",
            "Copy the id from 'lmo alerts'. It is the md5 printed in the first column.",
        )
    cols = [d[0] for d in wh.con.description]
    return dict(zip(cols, row, strict=True))


def explain_alert(wh: Warehouse, alert_uid: str) -> dict:
    """Signals, contributing events, and enough lineage to open the raw line."""
    alert = get_alert(wh, alert_uid)
    event_uids = list(alert["event_uids"] or [])
    events: list[dict] = []
    if event_uids:
        placeholders = ",".join("?" * len(event_uids))
        rows = wh.con.execute(
            f"""
            SELECT event_uid, event_time, time_sec, src_user_uid, dst_user_uid,
                   src_endpoint, dst_endpoint, auth_protocol, logon_type,
                   activity_name, status, src_dataset, src_file, src_line_no,
                   src_line_hash, run_id
            FROM events
            WHERE event_uid IN ({placeholders})
            ORDER BY time_sec, event_uid
            """,
            event_uids,
        ).fetchall()
        cols = [d[0] for d in wh.con.description]
        events = [dict(zip(cols, r, strict=True)) for r in rows]
    try:
        raw = alert["signals_json"] or "{}"
        signals = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (json.JSONDecodeError, TypeError):
        signals = {}
    return {"alert": alert, "signals": signals, "events": events}


def render_explain(payload: dict) -> str:
    alert = payload["alert"]
    lines = [
        f"alert     {alert['alert_uid']}",
        f"  who     {alert['user_uid']} from {alert['src_host']}",
        f"  when    {alert['bucket_start_sec']}–{alert['bucket_end_sec']} "
        f"(dataset seconds)",
        f"  score   {alert['score']:.3f}   band={alert['band']}",
        f"  size    {alert['n_events']} events, "
        f"{alert['n_distinct_dst']} destinations, {alert['n_fail']} failures",
        "",
        "  why (contribution = weight × normalised signal):",
    ]
    signals = sorted(
        ((k, v) for k, v in payload["signals"].items() if v),
        key=lambda kv: (-kv[1], kv[0]),
    )
    if not signals:
        lines.append("    (no non-zero contributions — this should not happen)")
    for name, value in signals:
        lines.append(f"    {name:<20}{value:>10.3f}")
    lines += ["", "  contributing events:"]
    if not payload["events"]:
        lines.append("    (none resolvable — the lineage link is broken)")
    for e in payload["events"]:
        lines.append(
            f"    {e['time_sec']:<12} {e['src_user_uid'] or '':<16} "
            f"{e['src_endpoint'] or ''} -> {e['dst_endpoint'] or ''}  "
            f"{e['logon_type'] or ''} {e['activity_name'] or ''} {e['status'] or ''}"
        )
        lines.append(
            f"               {e['src_dataset']} / {e['src_file']} "
            f"line {e['src_line_no']}  uid={e['event_uid']}"
        )
    return "\n".join(lines)


def render_alert_table(rows: list[dict]) -> str:
    if not rows:
        return "no alerts match"
    lines = [
        f"{'score':>7}  {'band':<7}{'account':<16}{'from':<10}"
        f"{'start':>12}{'dsts':>6}  top signals",
        "-" * 96,
    ]
    for r in rows:
        try:
            raw = r["signals_json"] or "{}"
            sigs = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (json.JSONDecodeError, TypeError):
            sigs = {}
        top = ", ".join(
            f"{k}={v:.2f}"
            for k, v in sorted(sigs.items(), key=lambda kv: -kv[1])[:3]
        )
        lines.append(
            f"{r['score']:7.3f}  {r['band']:<7}{r['user_uid']:<16}"
            f"{r['src_host']:<10}{r['bucket_start_sec']:>12}"
            f"{r['n_distinct_dst']:>6}  {top}"
        )
        lines.append(f"         {r['alert_uid']}")
    lines.append(f"\n{len(rows)} alert(s)")
    return "\n".join(lines)
