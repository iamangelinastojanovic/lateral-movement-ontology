"""The ontology: what it must guarantee before Part 3 can rely on it."""

from __future__ import annotations

import pytest

from helpers import read_gz, with_extra_auth
from lmo.errors import LmoError
from lmo.ingest.pipeline import run_ingest
from lmo.ontology import query as oq
from lmo.ontology.build import build_graph, graph_is_stale


@pytest.fixture
def graph(warehouse, tiny_dataset):
    """A warehouse with events ingested and the ontology built on top."""
    run_ingest(warehouse, tiny_dataset)
    build_graph(warehouse)
    return warehouse


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def test_every_table_is_populated(graph):
    for table in ("entity_user", "entity_host", "entity_session",
                  "edge_user_host", "edge_host_host"):
        assert graph.count(table) > 0, f"{table} is empty"


def test_entities_cover_every_account_and_host_in_events(graph):
    """A node missing from the ontology is a pivot that dead-ends."""
    missing_users = graph.sql(
        """
        SELECT count(*) FROM (
            SELECT DISTINCT src_user_uid FROM events
            WHERE src_dataset = 'auth' AND src_user_uid IS NOT NULL
        ) e ANTI JOIN entity_user u ON u.user_uid = e.src_user_uid
        """
    )[0][0]
    assert missing_users == 0

    missing_hosts = graph.sql(
        """
        SELECT count(*) FROM (
            SELECT DISTINCT src_endpoint AS h FROM events WHERE src_dataset='auth'
            UNION
            SELECT DISTINCT dst_endpoint FROM events WHERE src_dataset='auth'
        ) e ANTI JOIN entity_host x ON x.host = e.h
        WHERE e.h IS NOT NULL
        """
    )[0][0]
    assert missing_hosts == 0


def test_edge_first_seen_matches_the_events_it_summarises(graph):
    """The whole point of the edge table is that these columns are trustworthy."""
    wrong = graph.sql(
        """
        SELECT count(*) FROM edge_user_host e
        JOIN (
            SELECT src_user_uid, dst_endpoint,
                   min(time_sec) AS lo, max(time_sec) AS hi, count(*) AS n
            FROM events WHERE src_dataset = 'auth'
              AND src_user_uid IS NOT NULL AND dst_endpoint IS NOT NULL
            GROUP BY 1, 2
        ) t ON t.src_user_uid = e.user_uid AND t.dst_endpoint = e.dst_host
        WHERE e.first_seen_sec <> t.lo OR e.last_seen_sec <> t.hi
           OR e.n_total <> t.n
        """
    )[0][0]
    assert wrong == 0


def test_host_to_host_edges_exclude_local_logons(graph):
    """A self-loop on nearly every host would make path search wander in place."""
    assert graph.sql(
        "SELECT count(*) FROM edge_host_host WHERE src_host = dst_host"
    )[0][0] == 0


def test_the_graph_never_saw_the_labels(graph):
    """The ontology is Part 3's feature source.

    If it were built with any knowledge of ``redteam_labels``, a detector
    trained on it would learn the answer rather than the pattern, and every
    number Part 3 reports would be fiction.
    """
    for table in ("entity_user", "entity_host", "entity_session",
                  "edge_user_host", "edge_host_host"):
        columns = {r[1].lower() for r in graph.sql(f"PRAGMA table_info('{table}')")}
        for forbidden in ("label", "redteam", "malicious", "truth", "attack"):
            assert not any(forbidden in c for c in columns), f"{table}.{forbidden}"


def test_hub_hosts_are_found(graph):
    """The estate's busiest destinations must be recognisable as infrastructure."""
    hubs = graph.sql("SELECT host, dst_share FROM entity_host WHERE role_hint='hub'")
    assert hubs, "no hub identified; the skew that shapes every query is missing"
    assert max(s for _, s in hubs) > 0.05


def test_broad_accounts_are_a_minority(graph):
    """'broad' is a percentile, so it must stay rare whatever the estate.

    A fixed threshold of 25 hosts once labelled 549 of 599 accounts broad -- a
    category that fits 92% of the population tells a detector nothing.
    """
    total, broad = graph.sql(
        "SELECT count(*), count(*) FILTER (role_hint = 'broad') FROM entity_user"
    )[0]
    assert 0 < broad < total * 0.25


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------


def test_a_fresh_graph_reports_fresh(graph):
    stale, _ = graph_is_stale(graph)
    assert not stale


def test_ingesting_more_events_makes_the_graph_stale(graph, tiny_dataset, tmp_path):
    """A stale graph answers confidently and wrongly, which is worse than refusing."""
    run_ingest(graph, with_extra_auth(tiny_dataset, tmp_path / "more"))
    stale, detail = graph_is_stale(graph)
    assert stale
    assert "events" in detail


def test_queries_refuse_to_run_on_a_stale_graph(graph, tiny_dataset, tmp_path):
    run_ingest(graph, with_extra_auth(tiny_dataset, tmp_path / "more"))
    with pytest.raises(LmoError) as exc:
        oq.first_time_edges(graph, start_sec=0, end_sec=10**9)
    assert "out of date" in exc.value.problem
    assert "build-graph" in exc.value.fix


def test_building_with_no_events_says_so(warehouse):
    with pytest.raises(LmoError) as exc:
        build_graph(warehouse)
    assert "no authentication events" in exc.value.problem


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_sessions_are_internally_consistent(graph):
    bad = graph.sql(
        """
        SELECT count(*) FROM entity_session
        WHERE (closed AND (end_sec IS NULL OR duration_sec IS NULL))
           OR (NOT closed AND (end_sec IS NOT NULL OR duration_sec IS NOT NULL))
           OR duration_sec < 0
           OR end_sec < start_sec
        """
    )[0][0]
    assert bad == 0


def test_open_sessions_are_kept_not_invented(graph):
    """A logon with no observed logoff is a real observation.

    Giving it a guessed end would be the easy option and would quietly corrupt
    every duration statistic built on this table.
    """
    total, closed = graph.sql(
        "SELECT count(*), count(*) FILTER (closed) FROM entity_session"
    )[0]
    assert 0 < closed < total, "either nothing closed, or nothing was left open"


def test_session_durations_are_exact_when_sessions_do_not_overlap(graph):
    """Calibration, not decoration.

    Pairing is exact only while sessions on a triple do not overlap. Network
    logons are short and far apart, so their measured median must land on what
    the generator drew; the schema documents the degradation for the dense
    types. If this drifts, the pairing heuristic changed and the calibration
    table in ``ontology/schema.py`` is stale.
    """
    median = graph.sql(
        """
        SELECT median(duration_sec) FROM entity_session
        WHERE closed AND logon_type = 'Network'
        """
    )[0][0]
    assert median is not None
    assert 90 <= median <= 260, f"Network median {median}s, generated 150s"


def test_every_session_traces_back_to_its_logon_event(graph):
    orphans = graph.sql(
        """
        SELECT count(*) FROM entity_session s
        ANTI JOIN events e ON e.event_uid = s.logon_event_uid
        """
    )[0][0]
    assert orphans == 0


# ---------------------------------------------------------------------------
# Path search
# ---------------------------------------------------------------------------


@pytest.fixture
def campaign(tiny_dataset):
    """The injected intrusion's own description, read from the manifest."""
    import json
    return json.loads(
        (tiny_dataset / "scenario.json").read_text(encoding="utf-8")
    )["ground_truth"]


def test_paths_are_strictly_time_ordered(graph, campaign):
    """The property that makes this lateral movement and not mere connectivity.

    Plain reachability is nearly always true in a real network and says nothing.
    A chain whose timestamps increase is a route somebody could actually have
    walked -- they reached the second host only after arriving at the first.
    """
    paths = oq.paths_between(
        graph, campaign["beachhead"], campaign["objective"],
        start_sec=0, end_sec=10**9, max_hops=3, limit=25,
    )
    for p in paths:
        times = p["times"]
        assert times == sorted(times), f"hops out of order: {times}"
        assert all(a < b for a, b in zip(times, times[1:], strict=False))


def test_paths_never_revisit_a_host(graph, campaign):
    paths = oq.paths_between(
        graph, campaign["beachhead"], campaign["objective"],
        start_sec=0, end_sec=10**9, max_hops=3, limit=25,
    )
    for p in paths:
        assert len(p["path"]) == len(set(p["path"])), f"cycle in {p['path']}"


def test_paths_start_and_end_where_asked(graph, campaign):
    src, dst = campaign["beachhead"], campaign["objective"]
    for p in oq.paths_between(graph, src, dst, start_sec=0, end_sec=10**9,
                              max_hops=3, limit=25):
        assert p["path"][0] == src
        assert p["path"][-1] == dst
        assert p["n_hops"] == len(p["path"]) - 1


def test_the_attackers_route_is_findable(graph, campaign):
    """The question the whole project exists to answer."""
    paths = oq.paths_between(
        graph, campaign["beachhead"], campaign["objective"],
        start_sec=0, end_sec=10**9, max_hops=3,
        user=campaign["stolen_admin"], limit=25,
    )
    assert paths, (
        "no time-ordered route from the beachhead to the objective using the "
        "stolen credential -- the graph cannot reconstruct the intrusion"
    )


def test_restricting_to_one_account_narrows_the_result(graph, campaign):
    kwargs = dict(start_sec=0, end_sec=10**9, max_hops=3, limit=50)
    everyone = oq.paths_between(graph, campaign["beachhead"],
                                campaign["objective"], **kwargs)
    just_one = oq.paths_between(graph, campaign["beachhead"],
                                campaign["objective"],
                                user=campaign["stolen_admin"], **kwargs)
    assert len(just_one) <= len(everyone)
    for p in just_one:
        assert set(p["accounts"]) == {campaign["stolen_admin"]}


def test_unbounded_hop_counts_are_refused(graph):
    """Past four hops almost every pair of hosts is connected and the result
    set grows faster than anyone can read it."""
    with pytest.raises(LmoError, match="max_hops"):
        oq.paths_between(graph, "C00001", "C00002",
                         start_sec=0, end_sec=10**9, max_hops=9)


def test_an_empty_window_is_refused(graph):
    with pytest.raises(LmoError, match="window is empty"):
        oq.paths_between(graph, "C00001", "C00002", start_sec=500, end_sec=100)


# ---------------------------------------------------------------------------
# Point in time
# ---------------------------------------------------------------------------


def test_rarity_ignores_everything_after_as_of(graph):
    """The lookahead guard, and the reason it has to be structural.

    Counting over the whole table and scoring a day-3 event with it lets the
    model see the future. Every metric built on that is too good, the code
    reads perfectly, and nothing in the output looks wrong.
    """
    row = graph.sql(
        """
        SELECT src_user_uid, dst_endpoint, time_sec FROM events
        WHERE src_dataset = 'auth' AND src_user_uid IS NOT NULL
        ORDER BY time_sec LIMIT 1
        """
    )[0]
    user, host, first_sec = row

    at_start = oq.host_rarity_as_of(graph, user, host, first_sec)
    at_end = oq.host_rarity_as_of(graph, user, host, 10**9)

    assert at_start["pair_seen_before"] == 0
    assert at_start["is_first_contact"] is True
    assert at_end["pair_seen_before"] > at_start["pair_seen_before"]
    assert at_end["user_events_before"] > at_start["user_events_before"]


def test_first_time_edges_are_first_by_construction(graph):
    edges = oq.first_time_edges(graph, start_sec=0, end_sec=10**9, limit=50)
    assert edges
    for e in edges:
        earlier = graph.sql(
            """
            SELECT count(*) FROM events
            WHERE src_dataset = 'auth' AND src_user_uid = ? AND dst_endpoint = ?
              AND time_sec < ?
            """,
            [e["user_uid"], e["dst_host"], e["first_seen_sec"]],
        )[0][0]
        assert earlier == 0


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------


def test_a_real_authentication_is_corroborated_by_traffic(graph):
    """The payoff for a Part 1 fix.

    Flows were originally drawn from independent random host pairs while the
    code claimed they backed up the auth stream; 0.7% matched, which is chance.
    Had that gone unnoticed this function would return nothing and look broken.
    """
    hop = graph.sql(
        """
        SELECT time_sec, src_endpoint, dst_endpoint FROM events
        WHERE src_dataset = 'auth' AND activity_name = 'LogOn' AND status_id = 1
          AND src_endpoint <> dst_endpoint
        LIMIT 200
        """
    )
    corroborated = sum(
        oq.corroborate(graph, time_sec=t, src_host=s, dst_host=d)["corroborated"]
        for t, s, d in hop
    )
    assert corroborated > len(hop) * 0.3, (
        f"only {corroborated}/{len(hop)} authentications had matching network "
        f"traffic; corroboration is not discriminating anything"
    )


# ---------------------------------------------------------------------------
# Profiles and timeline
# ---------------------------------------------------------------------------


def test_profiles_describe_a_real_entity(graph):
    uid = graph.sql("SELECT user_uid FROM entity_user LIMIT 1")[0][0]
    prof = oq.user_profile(graph, uid)
    assert prof.key == uid
    assert prof.attributes["n_auth"] > 0
    assert prof.relationships

    host = graph.sql("SELECT host FROM entity_host ORDER BY n_auth_in DESC LIMIT 1")[0][0]
    hp = oq.host_profile(graph, host)
    assert hp.key == host
    assert hp.relationships


def test_an_unknown_entity_is_an_explained_error(graph):
    with pytest.raises(LmoError, match="no account"):
        oq.user_profile(graph, "U99999@NOPE")
    with pytest.raises(LmoError, match="no host"):
        oq.host_profile(graph, "C99999")


def test_timeline_needs_something_to_centre_on(graph):
    with pytest.raises(LmoError, match="account or a host"):
        oq.timeline(graph, start_sec=0, end_sec=100)


def test_timeline_matches_a_host_at_either_end(graph):
    """An analyst investigating a machine cares about both directions."""
    host = graph.sql(
        """
        SELECT host FROM entity_host
        WHERE n_auth_in > 0 AND n_auth_out > 0
        ORDER BY least(n_auth_in, n_auth_out) DESC LIMIT 1
        """
    )[0][0]
    rows = oq.timeline(graph, host=host, start_sec=0, end_sec=10**9, limit=2000)
    assert rows
    assert any(r["src_endpoint"] == host for r in rows)
    assert any(r["dst_endpoint"] == host for r in rows)
    assert [r["time_sec"] for r in rows] == sorted(r["time_sec"] for r in rows)
