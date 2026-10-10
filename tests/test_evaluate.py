"""Evaluation: stage mapping, clean-world FPs, naive comparison, budget curve."""

from __future__ import annotations

import json

import pytest

from lmo.detect.run import run_detect
from lmo.errors import LmoError
from lmo.evaluate.metrics import (
    evaluate,
    labelled_events,
    stage_of_labelled_event,
)
from lmo.evaluate.report import render_eval
from lmo.generate.synth import GeneratorConfig, generate
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph


@pytest.fixture(scope="module")
def detected_path(tiny_dataset, tmp_path_factory):
    db = tmp_path_factory.mktemp("eval") / "w.duckdb"
    with Warehouse(db) as wh:
        run_ingest(wh, tiny_dataset)
        build_graph(wh)
        run_detect(wh)
    return db


@pytest.fixture
def detected(detected_path):
    wh = Warehouse(detected_path, read_only=True)
    yield wh
    wh.close()


@pytest.fixture
def graph(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    build_graph(warehouse)
    return warehouse


def _scenario(tiny_dataset):
    return json.loads(
        (tiny_dataset / "scenario.json").read_text(encoding="utf-8")
    )


# ---------------------------------------------------------------------------
# Stage mapping
# ---------------------------------------------------------------------------


def test_identity_switch_label_maps_to_credential_theft(graph, tiny_dataset):
    """If this is wrong, stage recall credits the wrong phase of the campaign."""
    gt = _scenario(tiny_dataset)["ground_truth"]
    row = graph.sql(
        """
        SELECT e.event_uid, e.time_sec, e.src_user_uid, e.dst_user_uid,
               e.src_endpoint, e.dst_endpoint, e.logon_type, e.activity_name
        FROM events e
        JOIN redteam_labels l
          ON l.time_sec = e.time_sec
         AND l.user_uid = e.src_user_uid
         AND l.src_endpoint = e.src_endpoint
         AND l.dst_endpoint = e.dst_endpoint
        WHERE e.src_dataset = 'auth'
          AND e.logon_type = 'NewCredentials'
          AND e.src_user_uid <> e.dst_user_uid
        LIMIT 1
        """
    )
    assert row, "tiny world has no credential-theft event"
    cols = [
        "event_uid", "time_sec", "src_user_uid", "dst_user_uid",
        "src_endpoint", "dst_endpoint", "logon_type", "activity_name",
    ]
    rec = dict(zip(cols, row[0], strict=True))
    assert stage_of_labelled_event(rec, gt) == 2


def test_objective_host_label_maps_to_stage_four(graph, tiny_dataset):
    gt = _scenario(tiny_dataset)["ground_truth"]
    row = graph.sql(
        """
        SELECT e.event_uid, e.time_sec, e.src_user_uid, e.dst_user_uid,
               e.src_endpoint, e.dst_endpoint, e.logon_type, e.activity_name
        FROM events e
        JOIN redteam_labels l
          ON l.time_sec = e.time_sec
         AND l.user_uid = e.src_user_uid
         AND l.src_endpoint = e.src_endpoint
         AND l.dst_endpoint = e.dst_endpoint
        WHERE e.src_dataset = 'auth'
          AND (e.src_endpoint = ? OR e.dst_endpoint = ?)
        LIMIT 1
        """,
        [gt["objective"], gt["objective"]],
    )
    assert row, "tiny world has no objective-host event"
    cols = [
        "event_uid", "time_sec", "src_user_uid", "dst_user_uid",
        "src_endpoint", "dst_endpoint", "logon_type", "activity_name",
    ]
    rec = dict(zip(cols, row[0], strict=True))
    assert stage_of_labelled_event(rec, gt) == 4


def test_victim_recon_maps_to_stage_one(graph, tiny_dataset):
    gt = _scenario(tiny_dataset)["ground_truth"]
    rows = labelled_events(graph, gt)
    recon = [r for r in rows if r["stage"] == 1]
    assert recon
    assert all(r["src_user_uid"] == gt["victim_user"] for r in recon)


def test_every_labelled_event_gets_a_stage(graph, tiny_dataset):
    gt = _scenario(tiny_dataset)["ground_truth"]
    rows = labelled_events(graph, gt)
    assert rows
    assert {r["stage"] for r in rows} <= {1, 2, 3, 4}
    assert all(r["stage"] in {1, 2, 3, 4} for r in rows)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_evaluation_includes_the_naive_baseline(detected, tiny_dataset):
    report = evaluate(detected, tiny_dataset, budgets=(25,))
    detectors = {row["detector"] for row in report["budgets"]}
    assert detectors == {"layered", "naive"}
    assert report["n_naive_alerts"] > 0
    text = render_eval(report)
    assert "naive" in text
    assert "layered" in text


def test_stage_recall_is_between_zero_and_one(detected, tiny_dataset):
    report = evaluate(detected, tiny_dataset, budgets=(10, 25, 50, 100))
    for row in report["budgets"]:
        assert 0.0 <= row["stage_recall"] <= 1.0
        assert 0.0 <= row["event_recall"] <= 1.0
        assert 0 <= len(row["stages_hit"]) <= 4
        assert row["campaign_detected"] == (row["n_true"] > 0)
        if row["time_to_detection_sec"] is not None:
            assert row["time_to_detection_sec"] >= 0


def test_higher_budget_cannot_reduce_stage_recall(detected, tiny_dataset):
    """Top-K is a prefix of the same ranking, so recall is weakly increasing.

    If this fails, evaluate is not taking a prefix -- it is sampling, and the
    budget table is not a curve.
    """
    report = evaluate(detected, tiny_dataset, budgets=(10, 25, 50, 100))
    for detector in ("layered", "naive"):
        recalls = [
            row["stage_recall"]
            for row in report["budgets"]
            if row["detector"] == detector
        ]
        assert recalls == sorted(recalls)


def test_sweep_emits_every_requested_budget(detected, tiny_dataset):
    report = evaluate(detected, tiny_dataset, budgets=(10, 25, 50, 100))
    budgets = {
        row["budget_per_day"]
        for row in report["budgets"]
        if row["detector"] == "layered"
    }
    assert budgets == {10, 25, 50, 100}


def test_clean_world_produces_no_true_positives(warehouse, tmp_path):
    """A world with no intrusion cannot yield a true positive, by construction.

    If this fires, evaluation is crediting alerts that did not hit a label --
    usually a join that matched on the wrong key, or a detector that read the
    labels.
    """
    cfg = GeneratorConfig.preset("tiny", seed=7)
    cfg.inject_redteam = False
    generate(cfg, tmp_path)
    run_ingest(warehouse, tmp_path)
    build_graph(warehouse)
    run_detect(warehouse)
    report = evaluate(warehouse, tmp_path, budgets=(10, 25, 50, 100))
    assert report["world_kind"] == "clean"
    assert report["metric_kind"] == "none"
    assert report["n_labelled_events"] == 0
    assert all(row["n_true"] == 0 for row in report["budgets"])
    assert all(row["stage_recall"] == 0 for row in report["budgets"])
    assert all(row["campaign_detected"] is False for row in report["budgets"])
    assert report["clean_volume_per_day"] is not None
    assert report["clean_volume_per_day"]["any"] >= 0


def test_evaluate_refuses_before_detect(graph, tiny_dataset):
    with pytest.raises(LmoError) as exc:
        evaluate(graph, tiny_dataset, budgets=(25,))
    assert "detect" in exc.value.problem.lower() or "detect" in (exc.value.fix or "")


def test_attacked_world_is_marked_as_attacked(detected, tiny_dataset):
    report = evaluate(detected, tiny_dataset, budgets=(100,))
    assert report["world_kind"] == "attacked"
    assert report["metric_kind"] == "stage"
    assert report["n_labelled_events"] > 0
    assert report["seed"] == 1234
