"""Group hourly alerts into incidents for one account.

The detector's grain is (account, source host, hour) on purpose: that is what
a person triages. A campaign is still several of those rows. This module
stitches them when the same account keeps firing within a gap, without
changing scores and without reading evaluation labels.
"""

from __future__ import annotations

import hashlib

from lmo.detect.run import require_alerts
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ontology.build import require_fresh_graph

DEFAULT_GAP_SEC = 4 * 3600
BAND_RANK = {"high": 3, "medium": 2, "low": 1}


def _uid(user_uid: str, alert_uids: list[str]) -> str:
    payload = user_uid + "|" + "|".join(alert_uids)
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


def _best_band(bands: list[str]) -> str:
    return max(bands, key=lambda b: BAND_RANK.get(b, 0)) if bands else "low"


def cluster_alerts(
    alerts: list[dict],
    *,
    gap_sec: int = DEFAULT_GAP_SEC,
) -> list[dict]:
    """Greedy clusters: same account, next hour starts within ``gap_sec`` of the last end."""
    if gap_sec < 0:
        raise LmoError(
            f"gap must be >= 0 seconds (got {gap_sec})",
            "Pass --gap-hours 0 to split every hour, or 4 for the default merge.",
        )
    ordered = sorted(
        alerts,
        key=lambda a: (
            str(a.get("user_uid") or ""),
            int(a.get("bucket_start_sec") or 0),
            str(a.get("alert_uid") or ""),
        ),
    )
    groups: list[list[dict]] = []
    current: list[dict] = []
    for row in ordered:
        if not current:
            current = [row]
            continue
        prev = current[-1]
        same_user = row.get("user_uid") == prev.get("user_uid")
        start = int(row.get("bucket_start_sec") or 0)
        prev_end = int(prev.get("bucket_end_sec") or 0)
        if same_user and start <= prev_end + gap_sec:
            current.append(row)
        else:
            groups.append(current)
            current = [row]
    if current:
        groups.append(current)

    incidents: list[dict] = []
    for members in groups:
        uids = [str(m["alert_uid"]) for m in members]
        user = str(members[0].get("user_uid") or "")
        hosts = []
        seen: set[str] = set()
        for m in members:
            h = str(m.get("src_host") or "")
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
        scores = [float(m.get("score") or 0.0) for m in members]
        bands = [str(m.get("band") or "low") for m in members]
        starts = [int(m.get("bucket_start_sec") or 0) for m in members]
        ends = [int(m.get("bucket_end_sec") or 0) for m in members]
        dsts = [int(m.get("n_distinct_dst") or 0) for m in members]
        incidents.append(
            {
                "incident_uid": _uid(user, uids),
                "user_uid": user,
                "n_alerts": len(members),
                "n_hosts": len(hosts),
                "src_hosts": hosts,
                "score_max": max(scores) if scores else 0.0,
                "band": _best_band(bands),
                "start_sec": min(starts) if starts else 0,
                "end_sec": max(ends) if ends else 0,
                "n_distinct_dst_max": max(dsts) if dsts else 0,
                "alert_uids": uids,
            }
        )
    incidents.sort(
        key=lambda i: (-float(i["score_max"]), -int(i["n_alerts"]), i["user_uid"]),
    )
    return incidents


def _load_alerts(wh: Warehouse) -> list[dict]:
    require_fresh_graph(wh)
    require_alerts(wh)
    rows = wh.con.execute(
        """
        SELECT alert_uid, user_uid, src_host, bucket_start_sec, bucket_end_sec,
               score, band, n_events, n_distinct_dst, n_fail
        FROM alerts
        ORDER BY user_uid, bucket_start_sec, alert_uid
        """
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def list_incidents(
    wh: Warehouse,
    *,
    gap_sec: int = DEFAULT_GAP_SEC,
    limit: int = 50,
) -> list[dict]:
    if limit < 1:
        raise LmoError("limit must be at least 1", "Pass a positive --limit.")
    return cluster_alerts(_load_alerts(wh), gap_sec=gap_sec)[:limit]


def get_incident(
    wh: Warehouse,
    incident_uid: str,
    *,
    gap_sec: int = DEFAULT_GAP_SEC,
) -> dict:
    for row in cluster_alerts(_load_alerts(wh), gap_sec=gap_sec):
        if row["incident_uid"] == incident_uid:
            return row
    raise LmoError(
        f"no incident with uid {incident_uid!r}",
        "Copy the id from 'lmo incidents'. Gap hours must match the list you used.",
    )


def render_incident_table(rows: list[dict]) -> str:
    if not rows:
        return "no incidents"
    lines = [
        f"{'score':>7}  {'band':<7}{'alerts':>7}{'hosts':>7}  {'account':<16}  window",
        "-" * 88,
    ]
    for r in rows:
        lines.append(
            f"{r['score_max']:7.3f}  {r['band']:<7}{r['n_alerts']:>7}"
            f"{r['n_hosts']:>7}  {r['user_uid']:<16}  "
            f"{r['start_sec']}–{r['end_sec']}"
        )
        lines.append(f"         {r['incident_uid']}")
    lines.append(f"\n{len(rows)} incident(s)")
    return "\n".join(lines)


def render_incident(row: dict) -> str:
    hosts = ", ".join(row.get("src_hosts") or []) or "-"
    lines = [
        f"incident  {row['incident_uid']}",
        f"  who     {row['user_uid']}",
        f"  when    {row['start_sec']}–{row['end_sec']}",
        f"  score   {row['score_max']:.3f}   band={row['band']}",
        f"  size    {row['n_alerts']} alerts, {row['n_hosts']} source hosts, "
        f"max {row['n_distinct_dst_max']} destinations in one hour",
        f"  hosts   {hosts}",
        "",
        "  member alerts:",
    ]
    for uid in row.get("alert_uids") or []:
        lines.append(f"    {uid}")
    return "\n".join(lines)
