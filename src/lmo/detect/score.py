"""Combine per-unit signals into one score an analyst can read back.

A learned model is the obvious next step and the wrong one here. There is a
single labelled campaign per world, so a tree fitted on it is a lookup table
with extra steps. A weighted sum of named signals can be written down, argued
with, and compared to a naive baseline; that is the thing worth reporting, and
the thing a later model has to beat.

Weights are a config dataclass, not magic numbers scattered through SQL.
Thresholds that turn a score into high/medium/low are chosen against an alert
budget on the tune world, not by intuition about what "feels" anomalous.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _clip01(value: float) -> float:
    if value <= 0.0:
        return 0.0
    if value >= 1.0:
        return 1.0
    return float(value)


def _present(value: float) -> float:
    return 1.0 if value > 0.0 else 0.0


# Normalisers put every signal on [0, 1] so a weight of 2.0 means the same
# thing for a binary flag and for a z-score. Caps are saturating: eight first
# contacts in an hour is already the recon shape, twenty is not twenty times
# more interesting.
NORMALIZERS = {
    "first_contact": _present,
    "identity_switch": _present,
    "ntlm_downgrade": _present,
    "failure_run": _present,
    "fail_then_success": _present,
    "off_hours": _clip01,
    "fan_out": lambda v: _clip01(v / 3.0),
    "new_edge_burst": lambda v: _clip01(v / 8.0),
    "hub_avoidance": _clip01,
    "chain_extension": _present,
    "new_source_host": _present,
    "pair_rarity": _clip01,
    "protocol_rarity": _clip01,
    "host_count_z": lambda v: _clip01(max(v, 0.0) / 4.0),
    "dst_popularity": _clip01,
}

# Same functions as SQL, used by the detect INSERT. Kept next to the Python
# versions so a cap change cannot silently apply to only one path. Scoring
# 4,000 units through Python executemany was ~40ms/row in DuckDB; one INSERT
# SELECT is the difference between "under a minute" and "the suite hangs".
SQL_NORMALIZERS = {
    "first_contact": "CASE WHEN coalesce(first_contact, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "identity_switch": "CASE WHEN coalesce(identity_switch, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "ntlm_downgrade": "CASE WHEN coalesce(ntlm_downgrade, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "failure_run": "CASE WHEN coalesce(failure_run, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "fail_then_success": "CASE WHEN coalesce(fail_then_success, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "off_hours": "least(1.0, greatest(coalesce(off_hours, 0), 0.0))",
    "fan_out": "least(1.0, greatest(coalesce(fan_out, 0), 0.0) / 3.0)",
    "new_edge_burst": "least(1.0, greatest(coalesce(new_edge_burst, 0), 0.0) / 8.0)",
    "hub_avoidance": "least(1.0, greatest(coalesce(hub_avoidance, 0), 0.0))",
    "chain_extension": "CASE WHEN coalesce(chain_extension, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "new_source_host": "CASE WHEN coalesce(new_source_host, 0) > 0 THEN 1.0 ELSE 0.0 END",
    "pair_rarity": "least(1.0, greatest(coalesce(pair_rarity, 0), 0.0))",
    "protocol_rarity": "least(1.0, greatest(coalesce(protocol_rarity, 0), 0.0))",
    "host_count_z": "least(1.0, greatest(coalesce(host_count_z, 0), 0.0) / 4.0)",
    "dst_popularity": "least(1.0, greatest(coalesce(dst_popularity, 0), 0.0))",
}


# Why each weight is where it is -- the table the README quotes. Tune on
# seed 1 only; if a signal only helped by fitting that campaign, its weight
# belongs at zero and the sentence should say so.
WEIGHT_REASONS: dict[str, str] = {
    "chain_extension": (
        "Ties stages together: a hop from a host that already looked like "
        "recon or theft. The most valuable signal if it fires, so the highest "
        "weight; left until the others worked so it could not paper over them."
    ),
    "identity_switch": (
        "The credential-theft stage is a NewCredentials logon where the two "
        "principals differ. Benign runas/service traffic is ~3%, so this is "
        "discriminative only next to other signals, not alone."
    ),
    "new_edge_burst": (
        "Recon from one beachhead produces a handful of first-contact edges "
        "in the same hour. A single first contact is ordinary drift (~1.8%); "
        "a burst of them is the actual signature."
    ),
    "new_source_host": (
        "The stolen account authenticating from the victim's machine is a "
        "source host that account has never used. Suppresses the account's "
        "own first-ever hour, which would otherwise fire for everyone."
    ),
    "fan_out": (
        "Distinct destinations this hour vs the account's own trailing 95th "
        "percentile. Catches sweeps without punishing admins, whose high "
        "baseline is already in the denominator."
    ),
    "fail_then_success": (
        "Recon mixes failures into the same pairs it later succeeds on. "
        "Password-expiry bursts end the same way, so the weight stays modest."
    ),
    "ntlm_downgrade": (
        "The campaign's recon stage uses NTLM against hosts whose trailing "
        "traffic is Kerberos. Misconfigured clients do this too."
    ),
    "pair_rarity": (
        "Smoothed inverse of how often this account has reached this "
        "destination. Weak alone because benign drift creates new pairs "
        "every day; useful as a multiplier on a burst."
    ),
    "host_count_z": (
        "This hour's distinct hosts z-scored against the account's trailing "
        "daily distribution. An hour busier than a typical *day* is the "
        "fan-out we actually care about."
    ),
    "hub_avoidance": (
        "Share of destinations that are endpoints. Ordinary traffic is "
        "hub-heavy; a walk across workstations is not. Lateral movement to "
        "servers scores low here, so the weight is kept small."
    ),
    "dst_popularity": (
        "Inverse of how many accounts reached this destination in the "
        "trailing window. A rarely-visited host is more interesting than a "
        "domain controller; the name is popularity, the value is rarity."
    ),
    "failure_run": (
        "Five failures from one source in ten minutes. Password expiry "
        "produces the same shape, and the injected recon is too spread out "
        "to hit five on one pair, so this is a weak supporting flag."
    ),
    "protocol_rarity": (
        "How unusual this (protocol, logon type) is for the account. "
        "Tried as a way to catch NewCredentials on a user who never uses "
        "it; mostly tracked the identity_switch flag, kept at a low weight "
        "rather than dropped so the comparison stays visible."
    ),
    "first_contact": (
        "Binary: this bucket contains a first-time account→host edge. "
        "Deliberately cheap because ~1.8% of benign auths look like this; "
        "the burst version (new_edge_burst) carries the real weight."
    ),
    "off_hours": (
        "Share of the bucket outside this account's own trailing 10th–90th "
        "percentile hours. Night shift exists, the campaign runs in the "
        "afternoon, and a linear hour percentile wraps badly around "
        "midnight -- kept so the measurement is honest, weighted near zero."
    ),
}


DEFAULT_WEIGHTS: dict[str, float] = {
    "chain_extension": 3.0,
    "identity_switch": 2.4,
    "new_edge_burst": 2.2,
    "new_source_host": 1.6,
    "fan_out": 1.5,
    "fail_then_success": 1.3,
    "ntlm_downgrade": 1.1,
    "pair_rarity": 1.1,
    "host_count_z": 1.0,
    "hub_avoidance": 0.7,
    "dst_popularity": 0.8,
    "failure_run": 0.6,
    "protocol_rarity": 0.4,
    "first_contact": 0.35,
    "off_hours": 0.15,
}


@dataclass(frozen=True)
class ScoreConfig:
    """Weights and the score cuts that become bands.

    They are filled in from the tune world (seed 1, small preset) so that
    high is the score of the 10th alert per day and medium the 25th.
    They are *not* refit on the worlds that get reported. On that tune
    world those cuts sat at 7.68 and 7.24; a clean world (seed 4) produced
    11.2 and 26.3 alerts/day at the same cuts, so the budget is almost
    entirely false positives, which is the cost of looking.
    """

    weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_WEIGHTS)
    )
    high_threshold: float = 7.68
    medium_threshold: float = 7.24
    low_threshold: float = 0.0
    bucket_seconds: int = 3600

    def band_for(self, score: float) -> str:
        if score >= self.high_threshold:
            return "high"
        if score >= self.medium_threshold:
            return "medium"
        return "low"


def normalise(name: str, raw: float) -> float:
    fn = NORMALIZERS.get(name)
    if fn is None:
        return 0.0
    return float(fn(float(raw or 0.0)))


def contributions(raw: dict, config: ScoreConfig) -> dict[str, float]:
    """``{signal: weight * normalised value}`` for every non-zero contribution."""
    out: dict[str, float] = {}
    for name, weight in config.weights.items():
        norm = normalise(name, float(raw.get(name) or 0.0))
        if norm == 0.0 or weight == 0.0:
            continue
        out[name] = round(weight * norm, 6)
    return out


def combine(raw: dict, config: ScoreConfig) -> tuple[float, dict[str, float]]:
    contrib = contributions(raw, config)
    score = round(sum(contrib.values()), 6)
    return score, contrib
