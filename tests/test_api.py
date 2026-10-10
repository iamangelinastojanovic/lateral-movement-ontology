"""API and static UI: wrap existing investigation functions, never labels."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import with_extra_auth
from lmo.api.app import STATIC_DIR, create_app
from lmo.cli import main
from lmo.detect.run import explain_alert, list_alerts, run_detect
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph

API_ROOT = Path(__file__).resolve().parents[1] / "src" / "lmo" / "api"
WEB_ROOT = Path(__file__).resolve().parents[1] / "src" / "lmo" / "web"
WRITEBACK_ROOT = Path(__file__).resolve().parents[1] / "src" / "lmo" / "writeback"


@pytest.fixture(scope="module")
def detected_path(tiny_dataset, tmp_path_factory):
    db = tmp_path_factory.mktemp("api") / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
    return db


@pytest.fixture
def client(detected_path):
    app = create_app(detected_path)
    with TestClient(app) as c:
        yield c


def _walk_source(root: Path) -> str:
    parts = []
    for path in root.rglob("*"):
        if path.suffix in {".py", ".js", ".html", ".css"} and path.is_file():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def test_api_and_web_never_mention_labels():
    blob = _walk_source(API_ROOT) + "\n" + _walk_source(WEB_ROOT) + "\n" + _walk_source(WRITEBACK_ROOT)
    assert "redteam" not in blob


def test_health_ok_on_detected_warehouse(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["graph_stale"] is False
    assert body["n_alerts"] > 0


def test_queue_grain_matches_cli(client):
    r = client.get("/api/alerts", params={"limit": 10})
    assert r.status_code == 200
    rows = r.json()
    assert rows
    with client.app.state.lock:
        expected = list_alerts(client.app.state.wh, limit=10)
    assert rows[0]["user_uid"] == expected[0]["user_uid"]
    assert rows[0]["src_host"] == expected[0]["src_host"]
    assert rows[0]["bucket_start_sec"] == expected[0]["bucket_start_sec"]
    assert rows[0]["score"] == pytest.approx(expected[0]["score"])


def test_incidents_endpoint_has_no_labels(client):
    r = client.get("/api/incidents", params={"limit": 10, "gap_hours": 4})
    assert r.status_code == 200
    rows = r.json()
    assert rows
    assert "incident_uid" in rows[0]
    assert "redteam" not in json.dumps(rows)
    uid = rows[0]["incident_uid"]
    d = client.get(f"/api/incidents/{uid}", params={"gap_hours": 4})
    assert d.status_code == 200
    assert d.json()["incident_uid"] == uid


def test_explain_matches_explain_alert(client):
    uid = client.get("/api/alerts", params={"limit": 1}).json()[0]["alert_uid"]
    r = client.get(f"/api/alerts/{uid}")
    assert r.status_code == 200
    body = r.json()
    with client.app.state.lock:
        expected = explain_alert(client.app.state.wh, uid)
    api_uids = [e["event_uid"] for e in body["events"]]
    cli_uids = [e["event_uid"] for e in expected["events"]]
    assert api_uids == cli_uids
    assert any(v for v in body["signals"].values())


def test_missing_alert_is_404_with_fix(client):
    r = client.get("/api/alerts/not-a-real-uid")
    assert r.status_code == 404
    body = r.json()
    assert "problem" in body
    assert body["fix"]


def test_stale_graph_is_409(tiny_dataset, tmp_path):
    db = tmp_path / "stale.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
        run_ingest(wh, with_extra_auth(tiny_dataset, tmp_path / "more"))
    app = create_app(db)
    with TestClient(app) as c:
        r = c.get("/api/alerts")
    assert r.status_code == 409
    assert "fix" in r.json()


def test_timeline_without_user_or_host_is_400(client):
    r = client.get("/api/timeline", params={"start": 0, "end": 100})
    assert r.status_code == 400
    assert r.json()["problem"]
    assert r.json()["fix"]


def test_ui_index_is_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert 'id="app"' in r.text
    assert STATIC_DIR.joinpath("index.html").is_file()
    css = client.get("/static/app.css")
    js = client.get("/static/app.js")
    assert css.status_code == 200
    assert js.status_code == 200


def _forbidden_keys(obj) -> list[str]:
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in {"redteam", "label", "malicious"} or "redteam" in kl:
                hits.append(str(k))
            hits.extend(_forbidden_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            hits.extend(_forbidden_keys(item))
    return hits


def test_alert_json_has_no_label_fields(client):
    uid = client.get("/api/alerts", params={"limit": 1}).json()[0]["alert_uid"]
    body = client.get(f"/api/alerts/{uid}").json()
    assert _forbidden_keys(body) == []
    dump = json.dumps(body).lower()
    assert "redteam" not in dump
    assert "malicious" not in dump


def test_lock_does_not_deadlock_a_second_request(client):
    a = client.get("/api/health")
    b = client.get("/api/alerts", params={"limit": 5})
    assert a.status_code == 200
    assert b.status_code == 200


def test_pack_endpoint_matches_kind_and_omits_labels(client):
    uid = client.get("/api/alerts", params={"limit": 1}).json()[0]["alert_uid"]
    r = client.get(f"/api/alerts/{uid}/pack")
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "lmo_case"
    assert body["alert_uid"] == uid
    assert "redteam" not in json.dumps(body)


def test_serve_missing_db_exits_2(tmp_path, capsys):
    missing = tmp_path / "none.duckdb"
    code = main(["--db", str(missing), "serve"])
    assert code == 2
    err = capsys.readouterr().err
    assert "no warehouse" in err
    assert "Traceback" not in err
