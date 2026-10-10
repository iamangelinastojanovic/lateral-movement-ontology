"""Analyst writeback: append-only judgements, hash-checked raw lines."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lmo.api.app import create_app
from lmo.cli import main
from lmo.detect.run import run_detect
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph
from lmo.writeback.store import (
    list_audit,
    list_history,
    list_queue,
    record_decision,
    resolve_raw_line,
)

DETECT_ROOT = Path(__file__).resolve().parents[1] / "src" / "lmo" / "detect"
WRITEBACK_ROOT = Path(__file__).resolve().parents[1] / "src" / "lmo" / "writeback"


@pytest.fixture(scope="module")
def detected_path(tiny_dataset, tmp_path_factory):
    db = tmp_path_factory.mktemp("wb") / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
    return db


@pytest.fixture
def client(detected_path, tiny_dataset):
    app = create_app(detected_path, source=tiny_dataset)
    with TestClient(app) as c:
        yield c


def test_detect_does_not_import_writeback():
    for path in DETECT_ROOT.rglob("*.py"):
        assert "writeback" not in path.read_text(encoding="utf-8")


def test_writeback_never_mentions_labels():
    blob = "\n".join(
        p.read_text(encoding="utf-8")
        for p in WRITEBACK_ROOT.rglob("*.py")
    )
    assert "redteam" not in blob


def test_append_only_latest_wins(detected_path):
    with Warehouse(detected_path) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1")[0][0]
        first = record_decision(
            wh, alert_uid=uid, action="inconclusive", note="looks odd",
            analyst="a",
        )
        second = record_decision(
            wh, alert_uid=uid, action="false_positive", note="benign drift",
            analyst="b",
        )
        hist = list_history(wh, uid)
        assert len(hist) >= 2
        assert hist[0]["decision_id"] == second["decision_id"]
        assert hist[1]["decision_id"] == first["decision_id"]
        assert second["supersedes"] == first["decision_id"]
        n = wh.count("decisions")
        assert n >= 2


def test_false_positive_leaves_open_queue(detected_path):
    with Warehouse(detected_path) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1")[0][0]
        record_decision(wh, alert_uid=uid, action="false_positive", analyst="a")
        open_ids = {r["alert_uid"] for r in list_queue(wh, limit=200, view="open")}
        all_ids = {r["alert_uid"] for r in list_queue(wh, limit=200, view="all")}
        dismissed = {r["alert_uid"] for r in list_queue(wh, limit=200, view="dismissed")}
        assert uid not in open_ids
        assert uid in all_ids
        assert uid in dismissed


def test_true_positive_stays_on_open_queue(detected_path):
    with Warehouse(detected_path) as wh:
        uid = wh.sql(
            "SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1 OFFSET 1"
        )[0][0]
        record_decision(wh, alert_uid=uid, action="true_positive", analyst="a")
        open_ids = {r["alert_uid"] for r in list_queue(wh, limit=200, view="open")}
        confirmed = {r["alert_uid"] for r in list_queue(wh, limit=200, view="confirmed")}
        assert uid in open_ids
        assert uid in confirmed
        row = next(r for r in list_queue(wh, limit=200, view="open") if r["alert_uid"] == uid)
        assert row["decision"]["action"] == "true_positive"


def test_missing_alert_is_404(client):
    r = client.post(
        "/api/alerts/not-a-real-uid/decisions",
        json={"action": "false_positive"},
    )
    assert r.status_code == 404
    assert r.json()["fix"]


def test_unknown_action_is_400(client):
    uid = client.get("/api/alerts", params={"limit": 1, "view": "all"}).json()[0][
        "alert_uid"
    ]
    r = client.post(f"/api/alerts/{uid}/decisions", json={"action": "ignore"})
    assert r.status_code == 400
    assert "true_positive" in r.json()["fix"]


def test_decision_json_has_no_forbidden_keys(client):
    uid = client.get("/api/alerts", params={"limit": 1, "view": "all"}).json()[0][
        "alert_uid"
    ]
    r = client.post(
        f"/api/alerts/{uid}/decisions",
        json={"action": "inconclusive", "note": "needs a second look", "analyst": "x"},
    )
    assert r.status_code == 200
    body = r.json()
    for k in body:
        kl = str(k).lower()
        assert kl not in {"redteam", "label", "malicious"}
        assert "redteam" not in kl


def test_raw_line_matches_gzip_and_hash(client, tiny_dataset):
    uid = client.get("/api/alerts", params={"limit": 1, "view": "all"}).json()[0][
        "alert_uid"
    ]
    events = client.get(f"/api/alerts/{uid}").json()["events"]
    assert events
    event_uid = events[0]["event_uid"]
    got = client.get(f"/api/events/{event_uid}/raw")
    assert got.status_code == 200
    body = got.json()
    assert body["locator_ok"] is True
    path = tiny_dataset / body["src_file"]
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        lines = [ln.rstrip("\n") for ln in fh]
    raw = lines[body["src_line_no"] - 1]
    assert body["raw"] == raw
    assert hashlib.md5(raw.encode("utf-8")).hexdigest() == body["src_line_hash"]


def test_hash_mismatch_without_match_is_error(tiny_dataset, tmp_path):
    db = tmp_path / "h.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
        event_uid, filename, line_no, expected = wh.sql(
            """
            SELECT event_uid, src_file, src_line_no, src_line_hash
            FROM events WHERE src_dataset = 'auth' LIMIT 1
            """
        )[0]
    other = tmp_path / "other"
    other.mkdir()
    with gzip.open(other / filename, "wt", encoding="utf-8", newline="\n") as fh:
        fh.write("0,U00000@DOM1,U00000@DOM1,C0,C1,Kerberos,Network,LogOn,Success\n")
    with Warehouse(db, read_only=True) as wh:
        with pytest.raises(LmoError, match="was not found"):
            resolve_raw_line(wh, event_uid, other)


def test_cli_decide_then_audit(detected_path, capsys):
    with Warehouse(detected_path, read_only=True) as wh:
        uid = wh.sql("SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1")[0][0]
    assert main([
        "--db", str(detected_path), "decide",
        "--alert-uid", uid, "--action", "inconclusive",
        "--note", "cli round trip", "--analyst", "cli",
    ]) == 0
    capsys.readouterr()
    assert main(["--db", str(detected_path), "audit", "--limit", "5"]) == 0
    out = capsys.readouterr().out
    assert "inconclusive" in out
    assert uid in out
    with Warehouse(detected_path, read_only=True) as wh:
        assert list_audit(wh, limit=5)


def test_api_fp_hides_then_all_shows(client):
    uid = client.get("/api/alerts", params={"limit": 1, "view": "all"}).json()[0][
        "alert_uid"
    ]
    assert client.post(
        f"/api/alerts/{uid}/decisions",
        json={"action": "false_positive", "analyst": "ui"},
    ).status_code == 200
    open_ids = [
        r["alert_uid"]
        for r in client.get("/api/alerts", params={"view": "open", "limit": 100}).json()
    ]
    all_ids = [
        r["alert_uid"]
        for r in client.get("/api/alerts", params={"view": "all", "limit": 100}).json()
    ]
    assert uid not in open_ids
    assert uid in all_ids
    audit = client.get("/api/audit").json()
    assert any(d["alert_uid"] == uid for d in audit)
