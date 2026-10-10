"""The generator has to be trustworthy before anything built on it is.

These tests assert the two properties the rest of the project depends on:
the files are shaped exactly like the real dataset, and the ground truth is a
strict subset of the events rather than a parallel stream that happens to look
similar.
"""

from __future__ import annotations

import json

import pytest

from helpers import read_gz
from lmo.generate.synth import GeneratorConfig, build_population, generate
from lmo.schemas.raw import ALL_SCHEMAS


def test_every_file_matches_its_declared_arity(tiny_dataset):
    for name, schema in ALL_SCHEMAS.items():
        lines = read_gz(tiny_dataset / schema.filename)
        assert lines, f"{name} is empty"
        bad = [ln for ln in lines if len(ln.split(",")) != schema.arity]
        assert not bad, f"{name}: {len(bad)} rows with wrong arity, e.g. {bad[0]!r}"


def test_labels_are_a_strict_subset_of_auth(tiny_dataset):
    """The evaluation in Part 3 joins labels onto events on this exact key.

    If a single label fails to join, recall is silently understated and no
    amount of detection tuning will ever recover it.
    """
    auth_keys = set()
    for ln in read_gz(tiny_dataset / "auth.txt.gz"):
        f = ln.split(",")
        auth_keys.add((f[0], f[1], f[3], f[4]))

    labels = [ln.split(",") for ln in read_gz(tiny_dataset / "redteam.txt.gz")]
    assert labels, "no ground truth was written"

    missing = [l for l in labels if (l[0], l[1], l[2], l[3]) not in auth_keys]
    assert not missing, f"{len(missing)} labels do not join onto auth"


def test_generation_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    cfg = GeneratorConfig.preset("tiny", seed=99)
    generate(cfg, a)
    generate(GeneratorConfig.preset("tiny", seed=99), b)
    assert read_gz(a / "auth.txt.gz") == read_gz(b / "auth.txt.gz")
    assert read_gz(a / "redteam.txt.gz") == read_gz(b / "redteam.txt.gz")


def test_different_seeds_give_different_worlds(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate(GeneratorConfig.preset("tiny", seed=1), a)
    generate(GeneratorConfig.preset("tiny", seed=2), b)
    assert read_gz(a / "auth.txt.gz") != read_gz(b / "auth.txt.gz")


def test_time_is_within_the_collection_window(tiny_dataset):
    cfg = GeneratorConfig.preset("tiny")
    horizon = (cfg.n_days + 2) * 86_400  # the campaign may spill past the last day
    for schema in ALL_SCHEMAS.values():
        for ln in read_gz(tiny_dataset / schema.filename):
            t = int(ln.split(",")[0])
            assert 1 <= t <= horizon, f"{schema.name}: time {t} out of range"


def test_server_skew_exists(tiny_dataset):
    """Without skew, degree centrality would trivially find the attacker."""
    from collections import Counter

    dst = Counter(ln.split(",")[4] for ln in read_gz(tiny_dataset / "auth.txt.gz"))
    total = sum(dst.values())
    top_share = dst.most_common(1)[0][1] / total
    assert top_share > 0.05, (
        f"top destination only takes {top_share:.1%} of traffic; the hub "
        f"structure that makes detection non-trivial is missing"
    )


def test_benign_new_host_drift_is_present(tiny_dataset):
    """Benign users must touch new hosts, or 'unseen edge' becomes a free win."""
    seen: dict[str, set[str]] = {}
    labels = {
        (l.split(",")[0], l.split(",")[1])
        for l in read_gz(tiny_dataset / "redteam.txt.gz")
    }
    benign_new_edges = 0
    for ln in read_gz(tiny_dataset / "auth.txt.gz"):
        f = ln.split(",")
        if (f[0], f[1]) in labels:
            continue
        known = seen.setdefault(f[1], set())
        if f[4] not in known:
            benign_new_edges += 1
            known.add(f[4])
    assert benign_new_edges > 100, (
        f"only {benign_new_edges} benign first-time edges; a naive unseen-edge "
        f"detector would have no false positives to fight"
    )


def test_failures_occur_but_are_not_the_norm(tiny_dataset):
    lines = read_gz(tiny_dataset / "auth.txt.gz")
    fails = sum(1 for ln in lines if ln.split(",")[8] == "Fail")
    rate = fails / len(lines)
    assert 0.001 < rate < 0.25, f"implausible failure rate {rate:.3f}"


def test_manifest_describes_the_campaign(tiny_dataset):
    manifest = json.loads((tiny_dataset / "scenario.json").read_text(encoding="utf-8"))
    gt = manifest["ground_truth"]
    assert gt is not None
    assert gt["n_labelled_events"] > 0
    assert {s["name"] for s in gt["stages"]} == {
        "recon", "credential_theft", "lateral_movement", "objective"
    }
    assert manifest["counts"]["auth_redteam"] == gt["n_labelled_events"]


def test_clean_world_has_no_labels(tmp_path):
    cfg = GeneratorConfig.preset("tiny", seed=7)
    cfg.inject_redteam = False
    manifest = generate(cfg, tmp_path)
    assert manifest["ground_truth"] is None
    assert read_gz(tmp_path / "redteam.txt.gz") == []


def test_service_accounts_look_like_machine_accounts():
    import numpy as np

    cfg = GeneratorConfig.preset("tiny", seed=5)
    pop = build_population(cfg, np.random.default_rng(cfg.seed))
    service = pop.users[pop.roles == "service"]
    assert len(service) > 0
    assert all("$@" in u for u in service)


def _auth_index(dataset) -> dict[tuple[str, str], list[int]]:
    """Host pairs to the times they authenticated, LogOn only.

    A LogOff closes a connection that already existed; it neither resolves a
    name nor opens a flow, so including it would pair derived telemetry with
    the wrong event.
    """
    index: dict[tuple[str, str], list[int]] = {}
    for ln in read_gz(dataset / "auth.txt.gz"):
        f = ln.split(",")
        if f[7] != "LogOn":
            continue
        index.setdefault((f[3], f[4]), []).append(int(f[0]))
    return index


def test_flows_actually_follow_authentications(tiny_dataset):
    """Part 2 corroborates an auth by looking for traffic between the hosts.

    The generator used to draw flows from independent random host pairs while
    the docstring claimed they corroborated the auth stream. Measured, 0.7% of
    flows shared a host pair with any authentication -- chance alone. The
    corroboration feature would have found nothing.
    """
    auth = _auth_index(tiny_dataset)
    rows = [ln.split(",") for ln in read_gz(tiny_dataset / "flows.txt.gz")]
    derived = sum(
        1 for r in rows
        if (r[2], r[4]) in auth
        and any(abs(int(r[0]) - t) <= 8 for t in auth[(r[2], r[4])])
    )
    share = derived / len(rows)
    assert 0.45 < share < 0.85, (
        f"only {share:.1%} of flows follow a real authentication; "
        f"corroboration in Part 2 needs a substantial derived share"
    )


def test_flows_are_not_purely_derived(tiny_dataset):
    """Background traffic has to exist too, or corroboration is a tautology."""
    auth = _auth_index(tiny_dataset)
    rows = [ln.split(",") for ln in read_gz(tiny_dataset / "flows.txt.gz")]
    background = sum(1 for r in rows if (r[2], r[4]) not in auth)
    assert background / len(rows) > 0.1


def test_dns_lookups_precede_the_authentication_they_serve(tiny_dataset):
    """A name is resolved before the connection, not after.

    Asserted as "every derived lookup has an authentication at or after it",
    not by pairing each lookup with its nearest one. Nearest-match is ambiguous
    the moment a host pair authenticates more than once inside the window: a
    lookup three seconds before one logon can sit five seconds after the
    previous one, and the test fails on its own tie-breaking rather than on
    anything the generator did.
    """
    auth = _auth_index(tiny_dataset)
    rows = [ln.split(",") for ln in read_gz(tiny_dataset / "dns.txt.gz")]

    follows, precedes = 0, 0
    for r in rows:
        key, q = (r[1], r[2]), int(r[0])
        if key not in auth:
            continue
        nearby = [t for t in auth[key] if abs(t - q) <= 8]
        if not nearby:
            continue
        if any(t >= q for t in nearby):
            precedes += 1
        else:
            follows += 1

    assert precedes > 50, "too few lookups tied to an authentication to judge"
    assert follows == 0, f"{follows} lookups had no authentication after them"


def test_local_logons_produce_no_network_flow(tiny_dataset):
    """An interactive logon at your own desk does not cross the network."""
    self_pairs = {
        (f[3], f[4]) for f in (ln.split(",") for ln in read_gz(tiny_dataset / "auth.txt.gz"))
        if f[3] == f[4]
    }
    flows = [ln.split(",") for ln in read_gz(tiny_dataset / "flows.txt.gz")]
    # Background noise may still pair a host with itself; what must not happen
    # is a systematic derived flow for every local logon.
    derived_self = sum(1 for r in flows if r[2] == r[4] and (r[2], r[4]) in self_pairs)
    assert derived_self < 0.02 * len(flows)


def test_benign_identity_switches_exist(tiny_dataset):
    """``dst_user`` must sometimes differ from ``src_user``.

    Otherwise the destination-principal columns carry no information, and the
    red team's credential-theft stage -- which is an identity switch -- has
    nothing benign to be weighed against.
    """
    rows = [ln.split(",") for ln in read_gz(tiny_dataset / "auth.txt.gz")]
    switched = [r for r in rows if r[1] != r[2]]
    share = len(switched) / len(rows)
    assert 0.005 < share < 0.12, f"identity switch share is {share:.2%}"


def test_credential_theft_is_recorded_as_an_identity_switch(tiny_dataset):
    labels = {ln.split(",")[0] for ln in read_gz(tiny_dataset / "redteam.txt.gz")}
    theft = [
        f for f in (ln.split(",") for ln in read_gz(tiny_dataset / "auth.txt.gz"))
        if f[0] in labels and f[1] != f[2] and f[7] == "LogOn"
    ]
    assert len(theft) == 1, "expected exactly one labelled identity switch"
    assert theft[0][6] == "NewCredentials"
    assert theft[0][3] == theft[0][4], "the token is obtained on the beachhead"


def test_unknown_preset_is_rejected():
    with pytest.raises(ValueError, match="unknown preset"):
        GeneratorConfig.preset("enormous")


def test_every_account_is_in_the_same_domain(tiny_dataset):
    """One domain, spelled the same way for every account.

    A numpy string array is created at a fixed width taken from its longest
    element, and a longer string assigned in later is truncated SILENTLY. The
    user array was built from ``U00001@DOM1`` (11 characters), so the
    machine-account form ``C00115$@DOM1`` (12) was stored as ``C00115$@DOM``.

    Every service account therefore lost the last character of its domain, and
    the data contained a second domain that does not exist. Nothing downstream
    could have caught it: the value was well formed, just wrong. Part 2 would
    have drawn two domains in the ontology and nobody would have known why.
    """
    domains = {
        f.split("@")[1]
        for ln in read_gz(tiny_dataset / "auth.txt.gz")
        for f in (ln.split(",")[1],)
        if "@" in f
    }
    assert domains == {"DOM1"}, f"expected one domain, found {sorted(domains)}"


def test_machine_account_names_are_not_truncated():
    import numpy as np

    cfg = GeneratorConfig.preset("tiny", seed=11)
    pop = build_population(cfg, np.random.default_rng(cfg.seed))
    for account in pop.users[pop.roles == "service"]:
        assert account.endswith("$@DOM1"), f"truncated name: {account!r}"
