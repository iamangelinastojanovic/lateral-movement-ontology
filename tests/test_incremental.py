"""Idempotent ingest, parquet round-trip, and case hash checks."""

from __future__ import annotations

import pytest

from lmo.cli import main
from lmo.detect.run import run_detect
from lmo.errors import LmoError
from lmo.handoff import (
    export_parquet,
    import_parquet,
    load_case,
    pack_case,
    verify_pack,
    write_case,
)
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph, graph_is_stale


def test_parquet_roundtrip_then_idempotent_import(warehouse, tiny_dataset, tmp_path):
    run_ingest(warehouse, tiny_dataset)
    n = warehouse.count("events")
    pq = tmp_path / "pq"
    export_parquet(warehouse, pq)
    with Warehouse(tmp_path / "copy.duckdb") as dest:
        info = import_parquet(dest, pq)
        assert info["n_inserted"] == n
        assert dest.count("events") == n
        again = import_parquet(dest, pq)
        assert again["n_inserted"] == 0
        assert again["n_duplicate"] == n
        stale, _ = graph_is_stale(dest)
        assert stale


def test_verify_pack_accepts_matching_hashes(tiny_dataset, tmp_path):
    db = tmp_path / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
        uid = wh.sql("SELECT alert_uid FROM alerts LIMIT 1")[0][0]
        case_path = write_case(pack_case(wh, uid), tmp_path / "case.json")
        report = verify_pack(wh, load_case(case_path))
        assert report["ok"]
        assert report["n_ok"] == report["n_events"] > 0


def test_verify_pack_detects_tampered_hash(tiny_dataset, tmp_path):
    db = tmp_path / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
        uid = wh.sql("SELECT alert_uid FROM alerts LIMIT 1")[0][0]
        case = pack_case(wh, uid)
        case["events"][0]["src_line_hash"] = "0" * 32
        report = verify_pack(wh, case)
        assert report["ok"] is False
        assert report["hash_mismatch"]


def test_verify_pack_missing_file_is_a_user_error(tmp_path):
    with pytest.raises(LmoError) as exc:
        load_case(tmp_path / "nope.json")
    assert "no case file" in exc.value.problem


def test_cli_verify_pack(tiny_dataset, tmp_path):
    db = tmp_path / "w.duckdb"
    case_path = tmp_path / "c.json"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
        uid = wh.sql("SELECT alert_uid FROM alerts LIMIT 1")[0][0]
        write_case(pack_case(wh, uid), case_path)
    rc = main([
        "--db", str(db),
        "verify-pack",
        "--in", str(case_path),
    ])
    assert rc == 0
