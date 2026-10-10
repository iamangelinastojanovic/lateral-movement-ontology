"""Day-capped ingest and evaluation without generator scenario.json."""

from __future__ import annotations

import shutil

import pytest

from lmo.cli import main
from lmo.detect.run import run_detect
from lmo.errors import LmoError
from lmo.evaluate.metrics import evaluate
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import profile, run_ingest
from lmo.ontology.build import build_graph


def test_max_day_reconciles_and_preserves_label_join(warehouse, tiny_dataset):
    """Labels outside the window must not sit in redteam_labels unmatched.

    Otherwise profile.label_join_rate would drop below 1.0 and look like a
    broken join, when the real issue was an ingest slice.
    """
    sliced = run_ingest(warehouse, tiny_dataset, max_day=0)
    assert sliced.ok
    for s in sliced.stats:
        assert s.reconciled, f"{s.dataset} lost rows"
    assert sliced.total_beyond > 0
    lo, hi = warehouse.sql(
        "SELECT min(day_index), max(day_index) FROM events"
    )[0]
    assert lo == 0 and hi == 0
    prof = profile(warehouse)
    assert prof["labels"] >= 0
    if prof["labels"]:
        assert prof["label_join_rate"] == 1.0

    n_slice = warehouse.sql("SELECT count(*) FROM events")[0][0]
    with Warehouse(":memory:") as full_wh:
        run_ingest(full_wh, tiny_dataset)
        n_full = full_wh.sql("SELECT count(*) FROM events")[0][0]
    assert n_slice < n_full


def test_negative_max_day_is_a_user_error(warehouse, tiny_dataset):
    with pytest.raises(LmoError) as exc:
        run_ingest(warehouse, tiny_dataset, max_day=-1)
    assert "max-day" in exc.value.problem
    assert "0" in (exc.value.fix or "")


def test_cli_rejects_negative_max_day(tiny_dataset, tmp_path):
    rc = main([
        "--db", str(tmp_path / "w.duckdb"),
        "ingest",
        "--source", str(tiny_dataset),
        "--max-day=-1",
    ])
    assert rc == 2


def test_evaluate_lanl_style_directory_uses_event_recall(
    warehouse, tiny_dataset, tmp_path,
):
    """Real LANL has redteam.txt.gz and no scenario.json / four stages."""
    src = tmp_path / "lanl_like"
    shutil.copytree(tiny_dataset, src)
    (src / "scenario.json").unlink()
    run_ingest(warehouse, src)
    build_graph(warehouse)
    run_detect(warehouse)
    report = evaluate(warehouse, src, budgets=(100,))
    assert report["world_kind"] == "labelled"
    assert report["metric_kind"] == "event"
    assert report["n_labelled_events"] > 0
    assert report["seed"] is None
    assert report["clean_volume_per_day"] is None
    for row in report["budgets"]:
        assert "event_recall" in row
        assert 0.0 <= row["event_recall"] <= 1.0
        assert row["stage_recall"] == 0
        assert row["stages_hit"] == []
