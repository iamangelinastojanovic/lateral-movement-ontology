"""Record and retrieve analyst decisions; resolve a raw line by hash."""

from __future__ import annotations

import gzip
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from lmo.detect.run import get_alert, require_alerts, require_fresh_graph
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.writeback.schema import ACTIONS, ensure_decision_tables

VIEWS = ("open", "all", "confirmed", "dismissed")


def _has_table(wh: Warehouse, name: str) -> bool:
    row = wh.con.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'main' AND table_name = ?
        """,
        [name],
    ).fetchone()
    return row is not None


def _row(wh: Warehouse, decision_id: str) -> dict:
    row = wh.con.execute(
        """
        SELECT decision_id, alert_uid, event_uid, action, note, analyst,
               created_at, supersedes
        FROM decisions WHERE decision_id = ?
        """,
        [decision_id],
    ).fetchone()
    cols = [d[0] for d in wh.con.description]
    return dict(zip(cols, row, strict=True))


def latest_for_alert(wh: Warehouse, alert_uid: str) -> dict | None:
    if not _has_table(wh, "decisions"):
        return None
    row = wh.con.execute(
        """
        SELECT decision_id, alert_uid, event_uid, action, note, analyst,
               created_at, supersedes
        FROM decisions
        WHERE alert_uid = ?
        ORDER BY created_at DESC, decision_id DESC
        LIMIT 1
        """,
        [alert_uid],
    ).fetchone()
    if row is None:
        return None
    cols = [d[0] for d in wh.con.description]
    return dict(zip(cols, row, strict=True))


def record_decision(
    wh: Warehouse,
    *,
    alert_uid: str,
    action: str,
    note: str = "",
    analyst: str = "local",
    event_uid: str | None = None,
) -> dict:
    ensure_decision_tables(wh.con)
    if action not in ACTIONS:
        raise LmoError(
            f"unknown action {action!r}",
            "Use true_positive, false_positive, or inconclusive.",
        )
    get_alert(wh, alert_uid)
    if event_uid:
        found = wh.con.execute(
            "SELECT 1 FROM events WHERE event_uid = ?", [event_uid]
        ).fetchone()
        if found is None:
            raise LmoError(
                f"no event with uid {event_uid!r}",
                "Copy an event_uid from the contributing events on the alert.",
            )
    prev = latest_for_alert(wh, alert_uid)
    decision_id = uuid.uuid4().hex
    wh.con.execute(
        """
        INSERT INTO decisions
        (decision_id, alert_uid, event_uid, action, note, analyst,
         created_at, supersedes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            decision_id,
            alert_uid,
            event_uid,
            action,
            note,
            analyst or "local",
            datetime.now(timezone.utc),
            None if prev is None else prev["decision_id"],
        ],
    )
    return _row(wh, decision_id)


def list_history(wh: Warehouse, alert_uid: str) -> list[dict]:
    get_alert(wh, alert_uid)
    if not _has_table(wh, "decisions"):
        return []
    rows = wh.con.execute(
        """
        SELECT decision_id, alert_uid, event_uid, action, note, analyst,
               created_at, supersedes
        FROM decisions
        WHERE alert_uid = ?
        ORDER BY created_at DESC, decision_id DESC
        """,
        [alert_uid],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def list_audit(wh: Warehouse, *, limit: int = 50) -> list[dict]:
    if limit < 1:
        raise LmoError("limit must be at least 1", "Pass a positive --limit.")
    if not _has_table(wh, "decisions"):
        return []
    rows = wh.con.execute(
        """
        SELECT decision_id, alert_uid, event_uid, action, note, analyst,
               created_at, supersedes
        FROM decisions
        ORDER BY created_at DESC, decision_id DESC
        LIMIT ?
        """,
        [limit],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def list_queue(
    wh: Warehouse,
    *,
    band: str | None = None,
    day: int | None = None,
    limit: int = 50,
    offset: int = 0,
    view: str = "open",
) -> list[dict]:
    """Scored alerts with the latest judgement attached.

    ``view=open`` hides false positives. Scores are unchanged.
    """
    if view not in VIEWS:
        raise LmoError(
            f"unknown view {view!r}",
            "Use open, all, confirmed, or dismissed.",
        )
    require_fresh_graph(wh)
    require_alerts(wh)
    if limit < 1:
        raise LmoError("limit must be at least 1", "Pass a positive --limit.")
    if offset < 0:
        raise LmoError("offset cannot be negative", "Pass offset >= 0.")

    clauses = ["1=1"]
    params: list = []
    if band is not None:
        clauses.append("a.band = ?")
        params.append(band)
    if day is not None:
        clauses.append(
            "a.bucket_start_sec >= ? * 86400 AND a.bucket_start_sec < (? + 1) * 86400"
        )
        params += [day, day]

    has_dec = _has_table(wh, "decisions")
    if has_dec:
        if view == "open":
            clauses.append(
                "(d.action IS NULL OR d.action IS DISTINCT FROM 'false_positive')"
            )
        elif view == "confirmed":
            clauses.append("d.action = 'true_positive'")
        elif view == "dismissed":
            clauses.append("d.action = 'false_positive'")
        join = """
        LEFT JOIN (
            SELECT * EXCLUDE (rn) FROM (
                SELECT *, row_number() OVER (
                    PARTITION BY alert_uid
                    ORDER BY created_at DESC, decision_id DESC
                ) AS rn
                FROM decisions
            ) ranked WHERE rn = 1
        ) d ON d.alert_uid = a.alert_uid
        """
        dec_cols = """,
               d.decision_id, d.event_uid AS decision_event_uid, d.action,
               d.note, d.analyst, d.created_at AS decision_at, d.supersedes
        """
    else:
        join = ""
        dec_cols = """,
               NULL AS decision_id, NULL AS decision_event_uid, NULL AS action,
               NULL AS note, NULL AS analyst, NULL AS decision_at,
               NULL AS supersedes
        """

    rows = wh.con.execute(
        f"""
        SELECT a.alert_uid, a.user_uid, a.src_host, a.bucket_start_sec,
               a.bucket_end_sec, a.score, a.band, a.n_events, a.n_distinct_dst,
               a.n_fail, a.signals_json, a.event_uids
               {dec_cols}
        FROM alerts a
        {join}
        WHERE {' AND '.join(clauses)}
        ORDER BY a.score DESC, a.bucket_start_sec, a.user_uid, a.src_host
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    out = []
    for r in rows:
        item = dict(zip(cols, r, strict=True))
        if item.get("decision_id"):
            item["decision"] = {
                "decision_id": item.pop("decision_id"),
                "alert_uid": item["alert_uid"],
                "event_uid": item.pop("decision_event_uid"),
                "action": item.pop("action"),
                "note": item.pop("note"),
                "analyst": item.pop("analyst"),
                "created_at": item.pop("decision_at"),
                "supersedes": item.pop("supersedes"),
            }
        else:
            for k in (
                "decision_id", "decision_event_uid", "action", "note",
                "analyst", "decision_at", "supersedes",
            ):
                item.pop(k, None)
            item["decision"] = None
        out.append(item)
    return out


def decisions_for_entity(wh: Warehouse, key: str, *, limit: int = 20) -> list[dict]:
    require_fresh_graph(wh)
    require_alerts(wh)
    if not _has_table(wh, "decisions"):
        return []
    if "@" in key:
        clause = "a.user_uid = ?"
    else:
        clause = "a.src_host = ?"
    rows = wh.con.execute(
        f"""
        SELECT d.decision_id, d.alert_uid, d.event_uid, d.action, d.note,
               d.analyst, d.created_at, d.supersedes
        FROM decisions d
        JOIN alerts a ON a.alert_uid = d.alert_uid
        WHERE {clause}
          AND d.decision_id = (
              SELECT d2.decision_id FROM decisions d2
              WHERE d2.alert_uid = d.alert_uid
              ORDER BY d2.created_at DESC, d2.decision_id DESC
              LIMIT 1
          )
        ORDER BY d.created_at DESC
        LIMIT ?
        """,
        [key, limit],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def resolve_raw_line(
    wh: Warehouse, event_uid: str, source_dir: Path | str
) -> dict:
    """Return the raw line, checking the hash stored at ingest."""
    row = wh.con.execute(
        """
        SELECT event_uid, src_dataset, src_file, src_line_no, src_line_hash
        FROM events WHERE event_uid = ?
        """,
        [event_uid],
    ).fetchone()
    if row is None:
        raise LmoError(
            f"no event with uid {event_uid!r}",
            "Copy the id from an alert's contributing events.",
        )
    event_uid, dataset, filename, line_no, expected = row
    source = Path(source_dir)
    path = source / filename
    if not path.exists():
        raise LmoError(
            f"no raw file {filename} under {source}",
            "Pass --source pointing at the directory that was ingested.",
        )

    locator_raw = None
    locator_hash = None
    hash_at: int | None = None
    hash_raw = None
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            raw = line.rstrip("\n")
            digest = hashlib.md5(raw.encode("utf-8")).hexdigest()
            if i == line_no:
                locator_raw = raw
                locator_hash = digest
            if digest == expected and hash_at is None:
                hash_at = i
                hash_raw = raw
            if locator_raw is not None and hash_at is not None and i >= line_no:
                break

    if locator_hash == expected:
        return {
            "event_uid": event_uid,
            "src_dataset": dataset,
            "src_file": filename,
            "src_line_no": line_no,
            "src_line_hash": expected,
            "raw": locator_raw,
            "locator_ok": True,
        }
    if hash_raw is not None:
        return {
            "event_uid": event_uid,
            "src_dataset": dataset,
            "src_file": filename,
            "src_line_no": hash_at,
            "src_line_hash": expected,
            "raw": hash_raw,
            "locator_ok": False,
        }
    raise LmoError(
        f"raw line hash {expected} was not found in {filename}",
        "The file on disk is not the one this event was ingested from.",
    )
