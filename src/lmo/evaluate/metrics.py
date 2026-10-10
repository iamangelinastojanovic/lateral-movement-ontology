"""Recall at a fixed alert budget, and the supporting measurements.

Accuracy, AUC and F1 are the wrong numbers here. At one attacker event in
~10,000 a detector that alerts on nothing is 99.99% accurate, and AUC is
dominated by the negative class. A SOC lives by: given that we can triage N
alerts a day, how much of the campaign do we catch, and how soon?

Stage recall, not event recall: an alert covering 12 of 30 labelled events is
one campaign detected, not 40% recall. Time to detection is seconds from the
campaign's first event to the first true-positive alert that made the budget
cut -- a detector that only fires on the objective has found the intrusion
after it succeeded.

False positives are measured on a clean world (generated with no intrusion).
Every alert there is a false positive, which is a more honest cost than
precision on the attacked world, where the campaign itself dilutes the
denominator.

This module is the only place under ``evaluate/`` that reads ground truth.
Nothing in ``detect/`` may. Synthetic campaigns report stage recall (four
phases). LANL ``redteam.txt.gz`` is a list of authentications without those
phases; that world reports event recall instead. Do not mix the two tables.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from lmo.detect.baseline import resolve_day_range
from lmo.detect.rules import naive_first_contact_units
from lmo.detect.schema import AUTH
from lmo.detect.run import require_alerts
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ontology.build import require_fresh_graph

DEFAULT_BUDGETS = (10, 25, 50, 100)
N_STAGES = 4


@dataclass
class SliceMetrics:
    detector: str
    n_days: int
    n_alerts: int
    n_true: int
    precision: float
    stages_hit: list[int]
    stage_recall: float
    campaign_detected: bool
    time_to_detection_sec: float | None
    alerts_per_day: float
    budget_per_day: int | None = None
    threshold: float | None = None
    event_recall: float = 0.0
    n_labelled_hit: int = 0

    def as_dict(self) -> dict:
        d = asdict(self)
        if d["time_to_detection_sec"] is not None:
            d["time_to_detection_sec"] = round(d["time_to_detection_sec"], 1)
        d["precision"] = round(d["precision"], 4)
        d["stage_recall"] = round(d["stage_recall"], 4)
        d["event_recall"] = round(d["event_recall"], 4)
        d["alerts_per_day"] = round(d["alerts_per_day"], 3)
        return d


def load_scenario(source: Path) -> dict | None:
    path = Path(source) / "scenario.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def warehouse_n_days(wh: Warehouse) -> int:
    row = wh.con.execute(
        f"SELECT min(day_index), max(day_index) FROM events WHERE {AUTH}"
    ).fetchone()
    if row[0] is None:
        return 0
    return int(row[1]) - int(row[0]) + 1


def labelled_events(wh: Warehouse, ground_truth: dict | None) -> list[dict]:
    """Join labels onto events and assign each to a campaign stage.

    Stage windows in ``scenario.json`` are not used as the primary key: the
    generator records stage 4's start as the *last* objective event, and stage
    3's start as the same second as stage 2. Mapping by those timestamps
    silently files the objective hop under lateral movement. Identity is more
    stable than those clocks -- victim recon, the NewCredentials switch, the
    stolen admin, then anything on the objective host.
    """
    rows = wh.con.execute(
        f"""
        SELECT e.event_uid, e.time_sec, e.src_user_uid, e.dst_user_uid,
               e.src_endpoint, e.dst_endpoint, e.logon_type, e.activity_name
        FROM events e
        INNER JOIN redteam_labels l
          ON l.time_sec = e.time_sec
         AND l.user_uid = e.src_user_uid
         AND l.src_endpoint = e.src_endpoint
         AND l.dst_endpoint = e.dst_endpoint
        WHERE {AUTH}
        ORDER BY e.time_sec, e.event_uid
        """
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    out = [dict(zip(cols, r, strict=True)) for r in rows]
    if ground_truth is None:
        for rec in out:
            rec["stage"] = None
        return out
    for rec in out:
        rec["stage"] = stage_of_labelled_event(rec, ground_truth)
    return out


def stage_of_labelled_event(row: dict, ground_truth: dict) -> int:
    """Map one labelled authentication onto stages 1–4.

    A synthetic alert whose event_uids contain a known labelled event must
    land on the same stage this function returns; that is the evaluation's
    join key, so it is tested directly.
    """
    objective = ground_truth.get("objective") or ""
    if row["src_endpoint"] == objective or row["dst_endpoint"] == objective:
        return 4
    src_u, dst_u = row.get("src_user_uid"), row.get("dst_user_uid")
    if row.get("logon_type") == "NewCredentials" and src_u and dst_u and src_u != dst_u:
        return 2
    if src_u == ground_truth.get("stolen_admin"):
        return 3
    return 1


def _labelled_map(rows: list[dict]) -> dict[str, dict]:
    return {r["event_uid"]: r for r in rows}


def _slice_metrics(
    alerts: list[dict],
    labelled: dict[str, dict],
    *,
    detector: str,
    n_days: int,
    campaign_start: int | None,
    budget_per_day: int | None = None,
    threshold: float | None = None,
) -> SliceMetrics:
    stages: set[int] = set()
    labelled_hit: set[str] = set()
    n_true = 0
    first_tp_time: int | None = None
    for alert in alerts:
        uids = alert.get("event_uids") or []
        hit_times: list[int] = []
        hit_stages: set[int] = set()
        hit_any = False
        for uid in uids:
            lab = labelled.get(uid)
            if lab is None:
                continue
            hit_any = True
            labelled_hit.add(uid)
            if lab.get("stage") is not None:
                hit_stages.add(int(lab["stage"]))
            hit_times.append(int(lab["time_sec"]))
        if not hit_any:
            continue
        n_true += 1
        stages |= hit_stages
        t = min(hit_times)
        if first_tp_time is None or t < first_tp_time:
            first_tp_time = t

    n_alerts = len(alerts)
    precision = (n_true / n_alerts) if n_alerts else 0.0
    ttd: float | None
    if first_tp_time is None or campaign_start is None:
        ttd = None
    else:
        ttd = float(max(0, first_tp_time - campaign_start))

    stages_hit = sorted(stages)
    n_lab = len(labelled)
    event_recall = (len(labelled_hit) / n_lab) if n_lab else 0.0
    has_stages = any(r.get("stage") is not None for r in labelled.values())
    stage_recall = (len(stages_hit) / N_STAGES) if has_stages else 0.0
    return SliceMetrics(
        detector=detector,
        n_days=n_days,
        n_alerts=n_alerts,
        n_true=n_true,
        precision=precision,
        stages_hit=stages_hit,
        stage_recall=stage_recall,
        campaign_detected=n_true > 0,
        time_to_detection_sec=ttd,
        alerts_per_day=(n_alerts / n_days) if n_days else 0.0,
        budget_per_day=budget_per_day,
        threshold=threshold,
        event_recall=event_recall,
        n_labelled_hit=len(labelled_hit),
    )


def _ranked_layered(wh: Warehouse) -> list[dict]:
    rows = wh.con.execute(
        """
        SELECT alert_uid, user_uid, src_host, bucket_start_sec, bucket_end_sec,
               score, band, n_events, n_distinct_dst, n_fail, event_uids
        FROM alerts
        ORDER BY score DESC, bucket_start_sec, user_uid, src_host
        """
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    out = []
    for r in rows:
        rec = dict(zip(cols, r, strict=True))
        rec["event_uids"] = list(rec["event_uids"] or [])
        out.append(rec)
    return out


def _cap(rows: list[dict], n: int) -> list[dict]:
    if n <= 0:
        return []
    return rows[:n]


def band_volumes(wh: Warehouse, n_days: int) -> dict[str, float]:
    """Alerts per day at the configured score bands. Used on the clean world.

    Budget ranking on a world with no attack always fills the budget, which
    is not a measurement. Volume at a *fixed score cut* is.
    """
    rows = wh.con.execute(
        "SELECT band, count(*) FROM alerts GROUP BY 1"
    ).fetchall()
    counts = {band: 0 for band in ("high", "medium", "low")}
    for band, n in rows:
        counts[str(band)] = int(n)
    per_day = {
        band: (n / n_days) if n_days else 0.0 for band, n in counts.items()
    }
    per_day["any"] = (sum(counts.values()) / n_days) if n_days else 0.0
    per_day["counts"] = counts
    return per_day


def evaluate(
    wh: Warehouse,
    source: Path | None = None,
    *,
    budgets: tuple[int, ...] | list[int] = DEFAULT_BUDGETS,
) -> dict:
    """Score the current alerts against the world in ``source``.

    ``source`` may be a generator directory (``scenario.json``) or a LANL
    download (labels only). Labels come from the warehouse, never from detect
    tables. A clean world (no ground truth, no labels) yields zero true
    positives by construction. LANL has no four-stage campaign; that world
    reports event recall, not stage recall.
    """
    require_fresh_graph(wh)
    require_alerts(wh)

    scenario = load_scenario(source) if source is not None else None
    gt = (scenario or {}).get("ground_truth") if scenario else None
    n_days = warehouse_n_days(wh)
    if n_days == 0:
        raise LmoError(
            "the warehouse holds no authentication events",
            "Ingest the world you want to evaluate before running this.",
        )

    labelled_rows = labelled_events(wh, gt)
    labelled = _labelled_map(labelled_rows)
    campaign_start = None if gt is None else int(gt["start_time"])
    if campaign_start is None and labelled_rows:
        campaign_start = min(int(r["time_sec"]) for r in labelled_rows)

    layered = _ranked_layered(wh)
    start_day, end_day = resolve_day_range(wh, None, None)
    naive = naive_first_contact_units(wh, start_day, end_day)

    budget_rows: list[dict] = []
    for budget in budgets:
        cap = int(budget) * n_days
        for detector, ranked in (("layered", layered), ("naive", naive)):
            m = _slice_metrics(
                _cap(ranked, cap),
                labelled,
                detector=detector,
                n_days=n_days,
                campaign_start=campaign_start,
                budget_per_day=int(budget),
            )
            budget_rows.append(m.as_dict())

    if gt:
        world_kind = "attacked"
        metric_kind = "stage"
    elif labelled_rows:
        world_kind = "labelled"
        metric_kind = "event"
    else:
        world_kind = "clean"
        metric_kind = "none"
    if source is not None:
        world_name = Path(source).name
    else:
        world_name = world_kind

    seed = None
    if scenario and isinstance(scenario.get("config"), dict):
        seed = scenario["config"].get("seed")

    return {
        "world": world_name,
        "world_kind": world_kind,
        "metric_kind": metric_kind,
        "seed": seed,
        "n_days": n_days,
        "n_labelled_events": len(labelled_rows),
        "n_layered_alerts": len(layered),
        "n_naive_alerts": len(naive),
        "budgets": budget_rows,
        "clean_volume_per_day": (
            band_volumes(wh, n_days) if world_kind == "clean" else None
        ),
        "source": str(source) if source is not None else None,
    }


def sweep(
    wh: Warehouse,
    source: Path | None = None,
    *,
    budgets: tuple[int, ...] | list[int] = DEFAULT_BUDGETS,
) -> dict:
    """Recall against alerts-per-day, layered vs naive. Same work as evaluate."""
    return evaluate(wh, source, budgets=budgets)
