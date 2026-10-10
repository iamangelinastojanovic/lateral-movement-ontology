"""Detection: trailing-only signals, evidence on every alert, no label leakage."""

from __future__ import annotations

from pathlib import Path

import pytest

from helpers import with_extra_auth
from lmo.detect.baseline import (
    dst_users_as_of,
    host_count_mean_as_of,
    hour_percentiles_as_of,
    kerberos_share_as_of,
    pair_count_as_of,
    protocol_count_as_of,
)
from lmo.detect.rules import naive_first_contact_units
from lmo.detect.run import explain_alert, list_alerts, run_detect
from lmo.detect.score import DEFAULT_WEIGHTS, SQL_NORMALIZERS, ScoreConfig, WEIGHT_REASONS, combine
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest
from lmo.ontology.build import build_graph

DETECT_ROOT = Path(__file__).resolve().parents[1] / "src" / "lmo" / "detect"


@pytest.fixture(scope="module")
def detected_path(tiny_dataset, tmp_path_factory):
    """One detect run for the module. Rebuilding it per test was the suite's
    slowest step by a wide margin, and none of the read-side tests mutate it.
    """
    db = tmp_path_factory.mktemp("detect") / "w.duckdb"
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


# ---------------------------------------------------------------------------
# Label leakage
# ---------------------------------------------------------------------------


def test_detect_package_never_mentions_ground_truth_table():
    """Anything detect can read, it will eventually use.

    The word the labels live under is the one that must not appear here. A
    feature pipeline that can see the answer will learn it, and every number
    downstream is then fiction. Blunt, and that is the point.
    """
    offenders = []
    for path in sorted(DETECT_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "redteam" in text.lower():
            offenders.append(path.name)
    assert not offenders, f"detect package mentions labels: {offenders}"


def test_every_weight_has_a_reason():
    """A weight without a sentence is a number nobody can argue with."""
    assert set(DEFAULT_WEIGHTS) == set(WEIGHT_REASONS) == set(SQL_NORMALIZERS)
    assert all(DEFAULT_WEIGHTS.values())
    assert all(WEIGHT_REASONS.values())


# ---------------------------------------------------------------------------
# Lookahead
# ---------------------------------------------------------------------------


def test_pair_rarity_ignores_everything_after_as_of(graph):
    """Copy of the host_rarity_as_of shape, for the signal Part 3 actually scores.

    Counting the pair over the whole table and scoring a day-3 event with it
    lets the model see the future. The metrics improve, the code reads fine,
    and nothing in the output looks wrong.
    """
    row = graph.sql(
        """
        SELECT src_user_uid, dst_endpoint, min(time_sec) FROM events
        WHERE src_dataset = 'auth' AND src_user_uid IS NOT NULL
        GROUP BY 1, 2
        HAVING count(*) > 3
        ORDER BY min(time_sec)
        LIMIT 1
        """
    )
    assert row, "need a repeating account-host pair to test trailing counts"
    user, host, first_sec = row[0]
    last_sec = graph.sql("SELECT max(time_sec) + 1 FROM events WHERE src_dataset='auth'")[0][0]
    at_start = pair_count_as_of(graph, user, host, first_sec)
    at_end = pair_count_as_of(graph, user, host, last_sec)
    assert at_start == 0
    assert at_end > at_start


def test_protocol_rarity_ignores_everything_after_as_of(graph):
    row = graph.sql(
        """
        SELECT src_user_uid, auth_protocol, logon_type, min(time_sec) FROM events
        WHERE src_dataset = 'auth' AND src_user_uid IS NOT NULL
        GROUP BY 1, 2, 3
        HAVING count(*) > 3
        ORDER BY min(time_sec)
        LIMIT 1
        """
    )
    assert row
    user, proto, logon, first_sec = row[0]
    last_sec = graph.sql("SELECT max(time_sec) + 1 FROM events WHERE src_dataset='auth'")[0][0]
    at_start = protocol_count_as_of(graph, user, proto, logon, first_sec)
    at_end = protocol_count_as_of(graph, user, proto, logon, last_sec)
    assert at_start == 0
    assert at_end > at_start


def test_dst_popularity_ignores_everything_after_as_of(graph):
    row = graph.sql(
        """
        SELECT dst_endpoint, min(time_sec) FROM events
        WHERE src_dataset = 'auth' AND dst_endpoint IS NOT NULL
        GROUP BY 1
        HAVING count(DISTINCT src_user_uid) > 2
        ORDER BY min(time_sec)
        LIMIT 1
        """
    )
    assert row
    host, first_sec = row[0]
    last_sec = graph.sql("SELECT max(time_sec) + 1 FROM events WHERE src_dataset='auth'")[0][0]
    at_start = dst_users_as_of(graph, host, first_sec)
    at_end = dst_users_as_of(graph, host, last_sec)
    assert at_start == 0
    assert at_end > at_start


def test_host_count_mean_grows_as_as_of_moves(graph):
    user, first_sec = graph.sql(
        """
        SELECT src_user_uid, time_sec FROM events
        WHERE src_dataset = 'auth' AND src_user_uid IS NOT NULL
        ORDER BY time_sec LIMIT 1
        """
    )[0]
    early = host_count_mean_as_of(graph, user, first_sec)
    late = host_count_mean_as_of(graph, user, 10**9)
    assert early is None
    assert late is not None and late > 0


def test_kerberos_share_at_start_cannot_see_later_traffic(graph):
    host, first_sec = graph.sql(
        """
        SELECT dst_endpoint, time_sec FROM events
        WHERE src_dataset = 'auth' AND dst_endpoint IS NOT NULL
          AND auth_protocol = 'Kerberos'
        ORDER BY time_sec LIMIT 1
        """
    )[0]
    at_start = kerberos_share_as_of(graph, host, first_sec)
    at_end = kerberos_share_as_of(graph, host, 10**9)
    assert at_start is None
    assert at_end is not None


def test_hour_percentiles_need_history(graph):
    user, first_sec = graph.sql(
        """
        SELECT src_user_uid, time_sec FROM events
        WHERE src_dataset = 'auth' AND src_user_uid IS NOT NULL
        ORDER BY time_sec LIMIT 1
        """
    )[0]
    assert hour_percentiles_as_of(graph, user, first_sec) is None
    late = hour_percentiles_as_of(graph, user, 10**9)
    assert late is not None
    lo, hi = late
    assert 0 <= lo <= hi <= 23


def test_materialised_pair_baseline_matches_strict_past(detected):
    """The production path, not just the as_of helper, has to be trailing.

    A helper that looks backwards while the table used for scoring looks at
    everything would pass the tests above and still inflate every metric.
    """
    mismatches = detected.sql(
        """
        SELECT count(*) FROM trailing_pair t
        WHERE t.n_trailing <> (
            SELECT count(*) FROM events e
            WHERE e.src_dataset = 'auth' AND e.class_uid = 3002
              AND e.src_user_uid = t.user_uid
              AND e.dst_endpoint = t.dst_host
              AND e.day_index < t.day_index
              AND e.day_index >= t.day_index - 30
        )
        """
    )[0][0]
    assert mismatches == 0


def test_materialised_protocol_baseline_matches_strict_past(detected):
    mismatches = detected.sql(
        """
        SELECT count(*) FROM trailing_protocol t
        WHERE t.n_trailing <> (
            SELECT count(*) FROM events e
            WHERE e.src_dataset = 'auth' AND e.class_uid = 3002
              AND e.src_user_uid = t.user_uid
              AND e.auth_protocol IS NOT DISTINCT FROM t.auth_protocol
              AND e.logon_type IS NOT DISTINCT FROM t.logon_type
              AND e.day_index < t.day_index
              AND e.day_index >= t.day_index - 30
        )
        """
    )[0][0]
    assert mismatches == 0


# ---------------------------------------------------------------------------
# Alert unit invariants
# ---------------------------------------------------------------------------


def test_every_alert_carries_resolvable_evidence(detected):
    """An alert a person cannot open is an alert they learn to ignore."""
    empty = detected.sql(
        "SELECT count(*) FROM alerts WHERE len(event_uids) < 1"
    )[0][0]
    assert empty == 0
    orphans = detected.sql(
        """
        SELECT count(*) FROM (
            SELECT unnest(event_uids) AS uid FROM alerts
        ) a ANTI JOIN events e ON e.event_uid = a.uid
        """
    )[0][0]
    assert orphans == 0


def test_alert_buckets_do_not_overlap(detected):
    """Per (account, source host) the hours have to be disjoint, or the
    analyst is looking at the same incident twice under two ids."""
    overlaps = detected.sql(
        """
        SELECT count(*) FROM detect_units a
        JOIN detect_units b
          ON a.user_uid = b.user_uid
         AND a.src_host = b.src_host
         AND (a.user_uid, a.src_host, a.bucket_start_sec)
           < (b.user_uid, b.src_host, b.bucket_start_sec)
         AND a.bucket_start_sec < b.bucket_end_sec
         AND b.bucket_start_sec < a.bucket_end_sec
        """
    )[0][0]
    assert overlaps == 0


def test_units_are_unique_per_account_source_hour(detected):
    dupes = detected.sql(
        """
        SELECT count(*) FROM (
            SELECT user_uid, src_host, bucket_start_sec, count(*) AS n
            FROM detect_units
            GROUP BY 1, 2, 3
            HAVING n > 1
        )
        """
    )[0][0]
    assert dupes == 0


def test_scoring_is_deterministic(graph):
    first = run_detect(graph)
    scores_a = graph.sql(
        "SELECT user_uid, src_host, bucket_start_sec, score FROM alerts "
        "ORDER BY 1, 2, 3"
    )
    second = run_detect(graph)
    scores_b = graph.sql(
        "SELECT user_uid, src_host, bucket_start_sec, score FROM alerts "
        "ORDER BY 1, 2, 3"
    )
    assert scores_a == scores_b
    assert first.n_alerts == second.n_alerts


def test_combine_is_a_pure_weighted_sum():
    cfg = ScoreConfig()
    raw = {name: 0.0 for name in cfg.weights}
    raw["identity_switch"] = 1.0
    raw["chain_extension"] = 1.0
    score, contrib = combine(raw, cfg)
    assert contrib["identity_switch"] == pytest.approx(cfg.weights["identity_switch"])
    assert contrib["chain_extension"] == pytest.approx(cfg.weights["chain_extension"])
    assert score == pytest.approx(sum(contrib.values()))
    again, _ = combine(raw, cfg)
    assert again == score


def test_detector_refuses_a_stale_graph(graph, tiny_dataset, tmp_path):
    run_ingest(graph, with_extra_auth(tiny_dataset, tmp_path / "more"))
    with pytest.raises(LmoError) as exc:
        run_detect(graph)
    assert "out of date" in exc.value.problem
    assert "build-graph" in exc.value.fix


def test_detect_with_no_events_says_so(warehouse):
    with pytest.raises(LmoError) as exc:
        run_detect(warehouse)
    assert "no authentication" in exc.value.problem.lower() or "out of date" in exc.value.problem


def test_first_contact_fires_exactly_on_first_seen_edges(detected):
    """If this drifts, the naive baseline and the recon burst both lie."""
    extra = detected.sql(
        """
        SELECT count(*) FROM detect_event_signals s
        JOIN events e ON e.event_uid = s.event_uid
        JOIN edge_user_host eh
          ON eh.user_uid = e.src_user_uid AND eh.dst_host = e.dst_endpoint
        WHERE s.signal_name = 'first_contact'
          AND eh.first_seen_sec <> e.time_sec
        """
    )[0][0]
    assert extra == 0
    n = detected.sql(
        "SELECT count(*) FROM detect_event_signals WHERE signal_name = 'first_contact'"
    )[0][0]
    assert n > 0


def test_identity_switch_matches_newcredentials_mismatch(detected):
    n = detected.sql(
        """
        SELECT count(*) FROM detect_event_signals s
        JOIN events e ON e.event_uid = s.event_uid
        WHERE s.signal_name = 'identity_switch'
          AND (e.logon_type <> 'NewCredentials' OR e.src_user_uid = e.dst_user_uid)
        """
    )[0][0]
    assert n == 0


def test_naive_first_contact_is_implemented(detected):
    rows = naive_first_contact_units(detected, 0, 10**6)
    assert rows
    assert all(r["n_first_contact"] >= 1 for r in rows)
    assert all(r["event_uids"] for r in rows)


def test_detect_run_is_recorded(detected):
    n = detected.sql("SELECT count(*) FROM detect_runs")[0][0]
    assert n >= 1
    bands = {r[0] for r in detected.sql("SELECT DISTINCT band FROM alerts")}
    assert bands <= {"high", "medium", "low"}
    assert detected.sql("SELECT count(*) FROM alerts")[0][0] > 0


def test_explain_returns_the_events_the_alert_named(detected):
    uid = detected.sql(
        "SELECT alert_uid FROM alerts ORDER BY score DESC LIMIT 1"
    )[0][0]
    payload = explain_alert(detected, uid)
    named = list(payload["alert"]["event_uids"])
    got = [e["event_uid"] for e in payload["events"]]
    assert named
    assert set(got) == set(named)
    assert payload["signals"]


def test_list_alerts_respects_limit_and_band(detected):
    rows = list_alerts(detected, limit=3)
    assert 1 <= len(rows) <= 3
    if detected.sql("SELECT count(*) FROM alerts WHERE band = 'high'")[0][0]:
        high = list_alerts(detected, band="high", limit=50)
        assert all(r["band"] == "high" for r in high)


def test_new_edge_burst_is_the_first_contact_count(detected):
    bad = detected.sql(
        """
        SELECT count(*) FROM detect_units
        WHERE (first_contact = 0 AND new_edge_burst > 0)
           OR (first_contact > 0 AND new_edge_burst < 1)
        """
    )[0][0]
    assert bad == 0
