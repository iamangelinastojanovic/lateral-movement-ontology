"""Handoff artifacts: a case file an analyst can pass on, and Parquet layout.

Neither of these reads the evaluation label table. A case is the alert, its
contributing events, and the writeback history -- the same objects the UI
already shows. Parquet is the on-disk layout ``docs/scale-out.md`` describes
(``day_index`` partitions), written with DuckDB ``COPY`` rather than a cluster
engine.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from lmo.api.serialize import jsonable
from lmo.detect.run import explain_alert
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.schemas.normalized import EVENT_COLUMNS
from lmo.writeback.store import list_history

CASE_SCHEMA_VERSION = "1"


def pack_case(wh: Warehouse, alert_uid: str) -> dict:
    """Build a JSON-serialisable case for one alert.

    Ground-truth labels are not in this object. A recipient who wants recall
    numbers runs ``lmo evaluate``, which is the only path allowed to join them.
    """
    payload = explain_alert(wh, alert_uid)
    history = list_history(wh, alert_uid)
    return jsonable(
        {
            "kind": "lmo_case",
            "schema_version": CASE_SCHEMA_VERSION,
            "packed_at": datetime.now(timezone.utc).isoformat(),
            "alert_uid": alert_uid,
            "alert": payload["alert"],
            "signals": payload["signals"],
            "events": payload["events"],
            "history": history,
        }
    )


def write_case(case: dict, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(case, indent=2, default=str), encoding="utf-8")
    return path


def _sql_path(path: Path) -> str:
    text = path.resolve().as_posix()
    if "'" in text:
        raise LmoError(
            f"refusing a path that contains a quote: {path}",
            "Choose an output directory without apostrophes in the name.",
        )
    return text


def export_parquet(wh: Warehouse, out_dir: Path | str) -> dict:
    """Write Hive-style ``events/day_index=N/*.parquet`` plus ``alerts.parquet``.

    Host-bucket sub-partitioning from the scale-out note is intentionally
    omitted: on one node it adds directories without changing I/O. Day
    partitions are what a later job would prune.
    """
    out_dir = Path(out_dir)
    n_events = wh.count("events")
    if n_events == 0:
        raise LmoError(
            "the warehouse holds no events to export",
            "Run 'lmo ingest' first.",
        )
    events_dir = out_dir / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    target = _sql_path(events_dir)
    wh.con.execute(
        f"COPY (SELECT * FROM events) TO '{target}' "
        "(FORMAT PARQUET, PARTITION_BY (day_index), OVERWRITE_OR_IGNORE)"
    )
    n_alerts = 0
    tables = {
        r[0]
        for r in wh.con.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
    }
    if "alerts" in tables:
        n_alerts = wh.count("alerts")
        if n_alerts:
            alerts_path = _sql_path(out_dir / "alerts.parquet")
            (out_dir / "alerts.parquet").parent.mkdir(parents=True, exist_ok=True)
            wh.con.execute(
                f"COPY (SELECT * FROM alerts) TO '{alerts_path}' "
                "(FORMAT PARQUET, OVERWRITE_OR_IGNORE)"
            )
    n_parts = sum(1 for p in events_dir.rglob("*.parquet"))
    return {
        "out": str(out_dir),
        "n_events": n_events,
        "n_alerts": n_alerts,
        "n_parquet_files": n_parts,
    }


def import_parquet(wh: Warehouse, src_dir: Path | str) -> dict:
    """Load Hive-partitioned events from ``export_parquet``. Skip known hashes.

    Alerts are not imported. They are a detect product; loading them here would
    make the warehouse look detected when the graph is stale.
    """
    src_dir = Path(src_dir)
    events_dir = src_dir / "events" if (src_dir / "events").is_dir() else src_dir
    files = list(events_dir.rglob("*.parquet"))
    if not files:
        raise LmoError(
            f"no parquet files under {events_dir}",
            "Point --source at a directory 'lmo export-parquet --out' wrote.",
        )
    glob = _sql_path(events_dir) + "/**/*.parquet"
    cols = ", ".join(f"p.{c.name}" for c in EVENT_COLUMNS)
    n_src = wh.con.execute(
        f"SELECT count(*) FROM read_parquet('{glob}', hive_partitioning=true)"
    ).fetchone()[0]
    before = wh.count("events")
    wh.con.execute(
        f"""
        INSERT INTO events
        SELECT {cols}
        FROM read_parquet('{glob}', hive_partitioning=true) p
        WHERE NOT EXISTS (
            SELECT 1 FROM events e
            WHERE e.src_dataset = p.src_dataset
              AND e.src_file = p.src_file
              AND e.src_line_hash = p.src_line_hash
        )
        """
    )
    inserted = wh.count("events") - before
    return {
        "source": str(src_dir),
        "n_parquet_rows": int(n_src),
        "n_inserted": inserted,
        "n_duplicate": int(n_src) - inserted,
    }


def load_case(path: Path | str) -> dict:
    path = Path(path)
    if not path.is_file():
        raise LmoError(
            f"no case file at {path}",
            "Pass the JSON path 'lmo pack --out' wrote.",
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LmoError(
            f"{path} is not valid JSON",
            "Re-run 'lmo pack' and point --in at that file.",
        ) from exc
    if not isinstance(data, dict) or data.get("kind") != "lmo_case":
        raise LmoError(
            f"{path} is not an lmo_case file",
            "The top-level object needs kind=lmo_case.",
        )
    return data


def verify_pack(wh: Warehouse, case: dict) -> dict:
    """Check each packed event's line hash against the warehouse.

    Does not read evaluation labels. A mismatch means the case and the warehouse
    no longer describe the same raw line.
    """
    events = case.get("events") or []
    missing: list[str] = []
    hash_mismatch: list[str] = []
    n_ok = 0
    for ev in events:
        uid = ev.get("event_uid")
        expected = ev.get("src_line_hash")
        if not uid:
            missing.append("(missing event_uid)")
            continue
        row = wh.con.execute(
            "SELECT src_line_hash FROM events WHERE event_uid = ?",
            [uid],
        ).fetchone()
        if row is None:
            missing.append(str(uid))
            continue
        if expected is not None and row[0] != expected:
            hash_mismatch.append(str(uid))
            continue
        n_ok += 1
    return {
        "ok": not missing and not hash_mismatch,
        "alert_uid": case.get("alert_uid"),
        "n_events": len(events),
        "n_ok": n_ok,
        "missing": missing,
        "hash_mismatch": hash_mismatch,
    }
