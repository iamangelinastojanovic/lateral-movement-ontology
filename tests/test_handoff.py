"""Case pack and partitioned Parquet export -- no labels in the artifact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lmo.cli import main
from lmo.detect.run import run_detect
from lmo.errors import LmoError
from lmo.handoff import export_parquet, pack_case, write_case
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph
from lmo.writeback.store import record_decision

HANDOFF = Path(__file__).resolve().parents[1] / "src" / "lmo" / "handoff.py"


@pytest.fixture(scope="module")
def detected_path(tiny_dataset, tmp_path_factory):
    db = tmp_path_factory.mktemp("hand") / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
    return db


def test_handoff_never_mentions_labels():
    assert "redteam" not in HANDOFF.read_text(encoding="utf-8")


def test_pack_case_has_events_and_no_labels(detected_path):
    with Warehouse(detected_path, read_only=True) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1")[0][0]
        case = pack_case(wh, uid)
    blob = json.dumps(case)
    assert "redteam" not in blob
    assert case["kind"] == "lmo_case"
    assert case["schema_version"] == "1"
    assert case["alert_uid"] == uid
    assert case["events"]
    assert case["alert"]["alert_uid"] == uid
    hashes = {e["src_line_hash"] for e in case["events"]}
    assert hashes and all(h for h in hashes)


def test_pack_includes_writeback_history(detected_path):
    with Warehouse(detected_path) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1")[0][0]
        record_decision(wh, alert_uid=uid, action="inconclusive", note="pack test")
        case = pack_case(wh, uid)
    assert case["history"]
    assert case["history"][0]["action"] == "inconclusive"
    assert case["history"][0]["note"] == "pack test"


def test_pack_missing_alert_is_a_user_error(detected_path):
    with Warehouse(detected_path, read_only=True) as wh:
        with pytest.raises(LmoError) as exc:
            pack_case(wh, "not-a-real-uid")
    assert "no alert" in exc.value.problem.lower()


def test_write_case_roundtrip(detected_path, tmp_path):
    with Warehouse(detected_path, read_only=True) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts LIMIT 1")[0][0]
        path = write_case(pack_case(wh, uid), tmp_path / "case.json")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["kind"] == "lmo_case"
    assert "redteam" not in path.read_text(encoding="utf-8")


def test_export_parquet_roundtrip_counts(detected_path, tmp_path):
    out = tmp_path / "pq"
    with Warehouse(detected_path, read_only=True) as wh:
        n_events = wh.count("events")
        n_alerts = wh.count("alerts")
        info = export_parquet(wh, out)
    assert info["n_events"] == n_events
    assert info["n_alerts"] == n_alerts
    assert info["n_parquet_files"] > 0
    assert list(out.joinpath("events").rglob("*.parquet"))
    with Warehouse(":memory:") as chk:
        glob = (out / "events").resolve().as_posix() + "/**/*.parquet"
        n = chk.con.execute(
            f"SELECT count(*) FROM read_parquet('{glob}')"
        ).fetchone()[0]
        assert n == n_events
        n_al = chk.con.execute(
            f"SELECT count(*) FROM read_parquet('{(out / 'alerts.parquet').resolve().as_posix()}')"
        ).fetchone()[0]
        assert n_al == n_alerts
    assert any("day_index=" in str(p) for p in (out / "events").rglob("*"))


def test_export_parquet_empty_warehouse_explains_itself(warehouse, tmp_path):
    with pytest.raises(LmoError) as exc:
        export_parquet(warehouse, tmp_path / "empty-pq")
    assert "no events" in exc.value.problem.lower()


def test_cli_pack(detected_path, tmp_path):
    with Warehouse(detected_path, read_only=True) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts LIMIT 1")[0][0]
    dest = tmp_path / "c.json"
    rc = main([
        "--db", str(detected_path),
        "pack",
        "--alert-uid", uid,
        "--out", str(dest),
    ])
    assert rc == 0
    assert dest.exists()
