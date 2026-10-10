"""Hourly alerts grouped into incidents without touching scores or labels."""

from __future__ import annotations

from pathlib import Path

import pytest

from lmo.cli import main
from lmo.detect.run import run_detect
from lmo.errors import LmoError
from lmo.incidents import cluster_alerts, list_incidents
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph

INCIDENTS = Path(__file__).resolve().parents[1] / "src" / "lmo" / "incidents.py"


def _alert(**kwargs) -> dict:
    row = {
        "alert_uid": "a",
        "user_uid": "U1@DOM1",
        "src_host": "C1",
        "bucket_start_sec": 0,
        "bucket_end_sec": 3600,
        "score": 1.0,
        "band": "low",
        "n_distinct_dst": 1,
    }
    row.update(kwargs)
    return row


def test_incidents_module_never_mentions_labels():
    assert "redteam" not in INCIDENTS.read_text(encoding="utf-8")


def test_same_account_close_hours_merge():
    rows = cluster_alerts(
        [
            _alert(alert_uid="a1", bucket_start_sec=0, bucket_end_sec=3600),
            _alert(
                alert_uid="a2",
                bucket_start_sec=3600,
                bucket_end_sec=7200,
                src_host="C2",
            ),
        ],
        gap_sec=4 * 3600,
    )
    assert len(rows) == 1
    assert rows[0]["n_alerts"] == 2
    assert rows[0]["n_hosts"] == 2
    assert rows[0]["src_hosts"] == ["C1", "C2"]


def test_wide_gap_splits_the_account():
    rows = cluster_alerts(
        [
            _alert(alert_uid="a1", bucket_start_sec=0, bucket_end_sec=3600),
            _alert(
                alert_uid="a2",
                bucket_start_sec=86400,
                bucket_end_sec=90000,
            ),
        ],
        gap_sec=4 * 3600,
    )
    assert len(rows) == 2


def test_two_accounts_same_hour_are_two_incidents():
    rows = cluster_alerts(
        [
            _alert(alert_uid="a1", user_uid="U1@DOM1"),
            _alert(alert_uid="a2", user_uid="U2@DOM1"),
        ],
        gap_sec=4 * 3600,
    )
    assert len(rows) == 2


def test_negative_gap_is_a_user_error():
    with pytest.raises(LmoError) as exc:
        cluster_alerts([_alert()], gap_sec=-1)
    assert "gap" in exc.value.problem


def test_list_incidents_on_tiny_world(tiny_dataset, tmp_path):
    db = tmp_path / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
        rows = list_incidents(wh, limit=20)
    assert rows
    assert rows[0]["n_alerts"] >= 1
    assert rows[0]["incident_uid"]


def test_cli_rejects_negative_gap_hours(tiny_dataset, tmp_path):
    db = tmp_path / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
    rc = main([
        "--db", str(db),
        "incidents",
        "--gap-hours", "-1",
    ])
    assert rc == 2
