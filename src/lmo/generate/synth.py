"""Synthetic generator producing files byte-compatible with the LANL format.

Why this exists
---------------
The real dataset is ~12 GB gzipped and takes a while to obtain. More importantly,
developing detections directly against it is a trap: you tune until the known
red-team events light up, and you have no way to tell whether you built a
detector or a lookup table.

This generator gives a second, independently-labelled world to develop against.
The pipeline reads its output through exactly the same code path as the real
files, so switching over is a change of input directory and nothing else.

Making it hard on purpose
-------------------------
A generator where benign traffic is uniform noise and the attacker is the only
thing that stands out will make any detector look brilliant. Every element below
exists to deny a naive detector an easy win:

``servers``
    A handful of hosts that almost everyone authenticates to. They dominate the
    degree distribution, so raw degree centrality is useless and any per-host
    aggregate has severe skew -- the same shape as a real domain controller.

``new-host drift``
    Benign users regularly touch a host they have never touched before (new
    project, borrowed desk, a server they were just granted). A detector firing
    on "previously unseen user->host edge" alone will drown. This is the single
    most important benign behaviour in the file.

``admin maintenance``
    Admin accounts legitimately fan out to many hosts in a short window. That is
    the same shape as lateral movement, so fan-out needs a companion signal to
    be usable.

``failure bursts``
    Password expiry and misconfigured services produce runs of failures that are
    not brute force.

``night and weekend activity``
    Service accounts and a night shift mean "off-hours" is a weak prior, not a
    verdict.

The red-team campaign correspondingly uses *valid* credentials, *ordinary* auth
types, and where possible edges that have been seen before, so that it is not
separable by any single field.
"""

from __future__ import annotations

import gzip
import json
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path

import numpy as np

from lmo.errors import LmoError
from lmo.schemas.raw import (
    AUTH_TYPES,
    LOGON_TYPES,
)

SECONDS_PER_DAY = 86_400

# How a benign authentication picks its destination. These four must sum to 1.
# ``p_new_host_drift`` is carved out of the peer share, which is why it cannot
# exceed it -- stated here rather than left as a bare 0.17 in the code, because
# exceeding it used to produce numpy's "Probabilities are not non-negative",
# which says nothing about which knob was turned too far.
P_HOME = 0.50
P_SERVER = 0.33
P_PEER_TOTAL = 0.17


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class GeneratorConfig:
    """Knobs for the synthetic world.

    The defaults describe the ``small`` preset: big enough that skew, drift and
    class imbalance are all real, small enough to regenerate in seconds while
    iterating.
    """

    n_users: int = 600
    n_computers: int = 1_800
    n_days: int = 21
    seed: int = 20260910

    # Population mix
    admin_fraction: float = 0.04
    service_fraction: float = 0.08
    n_servers: int = 24
    n_crown_jewels: int = 3

    # Benign volume
    mean_events_per_user_day: float = 26.0
    weekend_activity_factor: float = 0.22
    night_shift_fraction: float = 0.05

    # Benign behaviours that mimic attack shapes
    p_new_host_drift: float = 0.018
    """Probability a given benign auth targets a host the user has never used.

    Carved out of :data:`P_PEER_TOTAL`, so it cannot exceed it.
    """

    p_admin_maintenance_day: float = 0.12
    """Probability an admin runs a fan-out maintenance sweep on a given day."""

    admin_maintenance_hosts: tuple[int, int] = (8, 22)
    """Range of hosts touched by one maintenance sweep."""

    p_failure: float = 0.021
    """Baseline probability that a single auth fails."""

    p_logoff_observed: float = 0.72
    """Share of successful logons that are followed by an observed LogOff.

    Not 1.0: machines are powered off, agents miss events, sessions outlive the
    collection window. An unclosed session is a normal observation, and Part 2
    keeps it as one rather than inventing an end time.

    Crucially this applies to the red team as well. An earlier version emitted
    LogOn and LogOff as independent coin flips, so no LogOff was the end of any
    particular logon -- session durations were meaningless. Making them real
    without also closing the attacker's sessions would have been worse: "logon
    that never closes" would then identify the intrusion outright.
    """

    session_seconds_median: dict[str, int] = field(
        default_factory=lambda: {
            "Network": 150,           # a share or service reached and released
            "Interactive": 7_200,     # someone at a keyboard
            "RemoteInteractive": 3_600,
            "Service": 900,
            "NewCredentials": 600,
            "Unlock": 1_800,
        }
    )
    """Median session length by logon type. Durations are drawn lognormally
    around these, which is the shape session lengths actually have: most short,
    a long tail of forgotten sessions."""

    p_identity_switch: float = 0.03
    """Share of benign auths where the destination principal differs from the
    source one.

    Real Windows telemetry is full of these: a machine account authenticating on
    behalf of a user, a scheduled task running as a service principal, ``runas``.
    Without any, ``dst_user_*`` is a copy of ``src_user_*`` in every row, the
    columns carry no information, and Part 3 has nothing benign to weigh against
    the credential-theft stage -- which is itself an identity switch.
    """

    n_failure_bursts: int = 40
    """Password-expiry style failure runs across the whole window."""

    # Secondary telemetry
    flows_per_auth: float = 0.75
    proc_per_user_day: float = 6.0
    dns_per_auth: float = 0.35

    flows_derived_share: float = 0.65
    """Share of flows that mirror a real authentication, rather than being noise.

    Part 2 corroborates an authentication by asking whether the two hosts also
    exchanged traffic around that second. That only means anything if some flows
    are genuinely produced by the authentications in the file. The remainder is
    background traffic, so the corroboration is a signal and not a tautology.
    """

    dns_derived_share: float = 0.70
    """Share of DNS lookups that precede an authentication to the same host."""

    # Red-team campaign
    inject_redteam: bool = True
    redteam_start_day: int | None = None
    """Defaults to roughly 55% of the way through the window."""

    redteam_recon_hosts: tuple[int, int] = (10, 18)
    redteam_lateral_hosts: tuple[int, int] = (5, 9)
    redteam_dwell_hours: tuple[int, int] = (2, 9)

    @classmethod
    def preset(cls, name: str, seed: int | None = None) -> "GeneratorConfig":
        presets: dict[str, dict] = {
            "tiny": dict(n_users=60, n_computers=200, n_days=7, n_servers=6,
                         n_failure_bursts=5, mean_events_per_user_day=18.0),
            "small": dict(),
            "medium": dict(n_users=2_500, n_computers=8_000, n_days=45,
                           n_servers=60, n_failure_bursts=160),
            "large": dict(n_users=9_000, n_computers=25_000, n_days=58,
                          n_servers=140, n_failure_bursts=400,
                          mean_events_per_user_day=34.0),
        }
        if name not in presets:
            raise ValueError(
                f"unknown preset {name!r}; choose from {', '.join(presets)}"
            )
        cfg = cls(**presets[name])
        if seed is not None:
            cfg.seed = seed
        return cfg

    #: Workstations that must exist beyond the server block, so that every user
    #: can be given a home host that is not a server.
    MIN_WORKSTATIONS = 10

    def validate(self) -> None:
        """Reject impossible configurations with a message naming the knob.

        Every check here replaces a numpy error raised several frames deep --
        "low >= high", "Probabilities are not non-negative" -- that names an
        internal variable rather than the setting the caller actually changed.
        """
        checks: list[tuple[bool, str, str]] = [
            (self.n_users >= 1, "n_users must be at least 1",
             f"got {self.n_users}"),
            (self.n_days >= 1, "n_days must be at least 1",
             f"got {self.n_days}"),
            (self.n_servers >= 1, "n_servers must be at least 1",
             f"got {self.n_servers}"),
            (self.n_computers >= self.n_servers + self.MIN_WORKSTATIONS,
             "n_computers must leave room for workstations beyond the servers",
             f"n_computers={self.n_computers} but n_servers={self.n_servers}; "
             f"need at least {self.n_servers + self.MIN_WORKSTATIONS}"),
            (self.n_crown_jewels <= self.n_servers,
             "n_crown_jewels cannot exceed n_servers",
             f"{self.n_crown_jewels} > {self.n_servers}"),
            (0.0 <= self.p_new_host_drift < P_PEER_TOTAL,
             f"p_new_host_drift must be between 0 and {P_PEER_TOTAL}",
             f"got {self.p_new_host_drift}; it is carved out of the "
             f"{P_PEER_TOTAL} share reserved for non-server destinations"),
            (0.0 <= self.p_failure <= 1.0,
             "p_failure must be between 0 and 1", f"got {self.p_failure}"),
            (self.admin_fraction + self.service_fraction < 1.0,
             "admin_fraction + service_fraction must be below 1",
             f"got {self.admin_fraction} + {self.service_fraction}"),
            (self.mean_events_per_user_day > 0,
             "mean_events_per_user_day must be positive",
             f"got {self.mean_events_per_user_day}"),
            (self.admin_maintenance_hosts[0] < self.admin_maintenance_hosts[1],
             "admin_maintenance_hosts must be an increasing (low, high) range",
             f"got {self.admin_maintenance_hosts}"),
            (self.redteam_recon_hosts[0] < self.redteam_recon_hosts[1],
             "redteam_recon_hosts must be an increasing (low, high) range",
             f"got {self.redteam_recon_hosts}"),
            (self.redteam_lateral_hosts[0] < self.redteam_lateral_hosts[1],
             "redteam_lateral_hosts must be an increasing (low, high) range",
             f"got {self.redteam_lateral_hosts}"),
            (self.redteam_start_day is None
             or 0 <= self.redteam_start_day < self.n_days,
             "redteam_start_day must fall inside the collection window",
             f"got {self.redteam_start_day} with n_days={self.n_days}"),
        ]
        for ok, problem, detail in checks:
            if not ok:
                raise LmoError(f"invalid generator setting: {problem}", detail)


# ---------------------------------------------------------------------------
# Population
# ---------------------------------------------------------------------------


@dataclass
class Population:
    """Who and what exists in the synthetic estate."""

    users: np.ndarray            # e.g. 'U0042@DOM1'
    roles: np.ndarray            # 'regular' | 'admin' | 'service'
    computers: np.ndarray        # e.g. 'C01234'
    home_host: np.ndarray        # index into computers, per user
    peer_hosts: list[np.ndarray]  # per user, hosts they legitimately use
    server_idx: np.ndarray
    crown_jewel_idx: np.ndarray
    server_weights: np.ndarray
    night_shift: np.ndarray      # bool per user

    @property
    def n_users(self) -> int:
        return len(self.users)


def build_population(cfg: GeneratorConfig, rng: np.random.Generator) -> Population:
    computers = np.array([f"C{i:05d}" for i in range(cfg.n_computers)])

    n_admin = max(1, int(cfg.n_users * cfg.admin_fraction))
    n_service = max(1, int(cfg.n_users * cfg.service_fraction))
    roles = np.array(["regular"] * cfg.n_users, dtype=object)
    shuffled = rng.permutation(cfg.n_users)
    roles[shuffled[:n_admin]] = "admin"
    roles[shuffled[n_admin:n_admin + n_service]] = "service"

    # Names are built only once the roles are known, and the array is created
    # from the finished list.
    #
    # This is not a stylistic preference. A numpy string array has a FIXED width
    # taken from its longest element at creation, and assigning a longer string
    # into it later TRUNCATES SILENTLY -- no error, no warning. Creating the
    # array from "U00001@DOM1" gave it width 11, so the machine-account form
    # "C00115$@DOM1" (12) was stored as "C00115$@DOM". Every service account
    # lost the last character of its domain, and the dataset ended up with a
    # phantom second domain that nothing in the pipeline could have flagged,
    # because the value was well-formed -- just wrong.
    #
    # Service accounts are named like machine accounts so downstream code has
    # something realistic to key the is_machine_account flag on.
    names: list[str] = []
    for i in range(cfg.n_users):
        if roles[i] == "service":
            names.append(f"C{int(rng.integers(0, cfg.n_computers)):05d}$@DOM1")
        else:
            names.append(f"U{i:05d}@DOM1")
    users = np.array(names)

    # Servers are the low-numbered hosts; crown jewels are a subset of those.
    server_idx = np.arange(cfg.n_servers)
    crown_jewel_idx = rng.choice(server_idx, size=cfg.n_crown_jewels, replace=False)

    # Zipf-ish weights: the top server takes a large share of all traffic, which
    # is what produces the join skew we want the design to have to cope with.
    ranks = np.arange(1, cfg.n_servers + 1)
    server_weights = 1.0 / ranks**1.15
    server_weights /= server_weights.sum()

    # Workstations start after the server block so a home host is never a server.
    workstation_lo = cfg.n_servers
    home_host = rng.integers(workstation_lo, cfg.n_computers, size=cfg.n_users)

    peer_hosts: list[np.ndarray] = []
    for i in range(cfg.n_users):
        if roles[i] == "admin":
            k = int(rng.integers(12, 40))
        elif roles[i] == "service":
            k = int(rng.integers(2, 8))
        else:
            k = int(rng.integers(1, 7))
        peers = rng.integers(workstation_lo, cfg.n_computers, size=k)
        peer_hosts.append(np.unique(np.append(peers, home_host[i])))

    night_shift = rng.random(cfg.n_users) < cfg.night_shift_fraction

    return Population(
        users=users,
        roles=roles,
        computers=computers,
        home_host=home_host,
        peer_hosts=peer_hosts,
        server_idx=server_idx,
        crown_jewel_idx=crown_jewel_idx,
        server_weights=server_weights,
        night_shift=night_shift,
    )


# ---------------------------------------------------------------------------
# Event accumulator
# ---------------------------------------------------------------------------


class _Sink:
    """Buffered gzip CSV writer.

    Rows are accumulated as pre-joined strings and flushed in blocks. Writing
    line-by-line through the csv module is roughly an order of magnitude slower
    at these volumes and the format here is simple enough not to need it.
    """

    def __init__(self, path: Path, flush_every: int = 200_000) -> None:
        self.path = path
        self._fh = gzip.open(path, "wt", newline="\n", encoding="utf-8",
                             compresslevel=6)
        self._buf: list[str] = []
        self._flush_every = flush_every
        self.count = 0

    def write(self, row: tuple) -> None:
        self._buf.append(",".join(str(v) for v in row))
        self.count += 1
        if len(self._buf) >= self._flush_every:
            self._flush()

    def _flush(self) -> None:
        if self._buf:
            self._fh.write("\n".join(self._buf) + "\n")
            self._buf.clear()

    def close(self) -> None:
        self._flush()
        self._fh.close()

    def __enter__(self) -> "_Sink":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _session_durations(
    logon_types: np.ndarray, cfg: GeneratorConfig, rng: np.random.Generator
) -> np.ndarray:
    """Draw a session length for each logon, lognormal around its type's median.

    Lognormal rather than uniform or exponential because that is the shape real
    session lengths have: a dense cluster of short ones and a long tail of
    sessions somebody walked away from. The spread is wide enough that duration
    alone never separates one logon type from another -- if it did, Part 3 would
    get a free signal that does not exist in real data.
    """
    medians = np.array(
        [cfg.session_seconds_median.get(str(t), 600) for t in logon_types],
        dtype=np.float64,
    )
    draws = rng.lognormal(np.log(medians), 1.0)
    return np.clip(draws, 5, 12 * 3600).astype(np.int64)


def _hour_offsets(
    n: int, night: bool, rng: np.random.Generator
) -> np.ndarray:
    """Draw second-of-day offsets with a plausible daily shape."""
    if night:
        centre, spread = 1.0, 3.0
    else:
        centre, spread = 11.5, 3.1
    hours = rng.normal(centre, spread, size=n) % 24.0
    return (hours * 3600).astype(np.int64) + rng.integers(0, 3600, size=n)


# ---------------------------------------------------------------------------
# Benign traffic
# ---------------------------------------------------------------------------


def _generate_benign_day(
    day: int,
    cfg: GeneratorConfig,
    pop: Population,
    rng: np.random.Generator,
    auth: _Sink,
) -> int:
    """Emit one day of benign authentication events. Returns the row count."""
    is_weekend = (day % 7) in (5, 6)
    factor = cfg.weekend_activity_factor if is_weekend else 1.0
    day_start = day * SECONDS_PER_DAY

    lam = np.full(pop.n_users, cfg.mean_events_per_user_day * factor)
    lam[pop.roles == "admin"] *= 1.9
    lam[pop.roles == "service"] *= 2.6  # service accounts ignore the weekend
    lam[pop.roles == "service"] /= max(factor, 1e-6)

    counts = rng.poisson(lam)
    total = int(counts.sum())
    if total == 0:
        return 0

    user_idx = np.repeat(np.arange(pop.n_users), counts)

    # Time of day, respecting the night shift and service accounts.
    times = np.empty(total, dtype=np.int64)
    is_offhours_user = pop.night_shift | (pop.roles == "service")
    for flag in (False, True):
        mask = is_offhours_user[user_idx] == flag
        if mask.any():
            times[mask] = _hour_offsets(int(mask.sum()), flag, rng)
    times = day_start + np.clip(times, 0, SECONDS_PER_DAY - 1) + 1

    # Destination category: home / server / known peer / never-seen host.
    p_new = cfg.p_new_host_drift
    cat = rng.choice(
        4, size=total, p=[P_HOME, P_SERVER, P_PEER_TOTAL - p_new, p_new]
    )

    dst = np.empty(total, dtype=np.int64)
    dst[cat == 0] = pop.home_host[user_idx[cat == 0]]
    n_srv = int((cat == 1).sum())
    if n_srv:
        dst[cat == 1] = rng.choice(
            pop.server_idx, size=n_srv, p=pop.server_weights
        )
    for pos in np.where(cat == 2)[0]:
        peers = pop.peer_hosts[user_idx[pos]]
        dst[pos] = peers[rng.integers(0, len(peers))]
    n_new = int((cat == 3).sum())
    if n_new:
        dst[cat == 3] = rng.integers(cfg.n_servers, cfg.n_computers, size=n_new)

    src = pop.home_host[user_idx]
    self_auth = dst == src

    auth_type = np.where(
        rng.random(total) < 0.12,
        "NTLM",
        np.where(rng.random(total) < 0.30, "Negotiate", "Kerberos"),
    )
    # A person signs in at their own desk once or twice a day and then leaves
    # the session running; coming back to an already-open desktop is an Unlock,
    # not a fresh logon.
    #
    # This matters beyond realism. An earlier version made every home-host event
    # Interactive, which produced an interactive logon every ~37 minutes per
    # user against a generated session length of ~120 minutes -- so sessions
    # overlapped by construction, and no pairing heuristic in Part 2 could
    # recover their durations. The generator was manufacturing an ambiguity that
    # does not exist in real telemetry, and then the ontology was being blamed
    # for failing to resolve it.
    logon_type = np.where(self_auth, "Unlock", "Network")
    order = np.lexsort((times, user_idx))
    first_home = np.zeros(total, dtype=bool)
    seen: set[int] = set()
    for pos in order:
        if self_auth[pos] and user_idx[pos] not in seen:
            seen.add(int(user_idx[pos]))
            first_home[pos] = True
    logon_type = np.where(first_home, "Interactive", logon_type)
    logon_type = np.where(
        (pop.roles[user_idx] == "service"), "Service", logon_type
    )
    outcome = np.where(rng.random(total) < cfg.p_failure, "Fail", "Success")

    users = pop.users[user_idx]
    src_names = pop.computers[src]
    dst_names = pop.computers[dst]

    # Benign identity switches: the account that authenticated is not the
    # account the session runs as. Confined to Service and NewCredentials logon
    # types, which is where Windows actually produces them.
    dst_users = users.copy()
    switch = rng.random(total) < cfg.p_identity_switch
    n_switch = int(switch.sum())
    if n_switch:
        dst_users[switch] = pop.users[rng.integers(0, pop.n_users, size=n_switch)]
        logon_type = np.where(
            switch & (logon_type == "Network"), "NewCredentials", logon_type
        )

    # A logon that succeeded may later be observed closing. The LogOff carries
    # the same principals and hosts, so Part 2 can pair them into a session.
    durations = _session_durations(logon_type, cfg, rng)
    closes = (outcome == "Success") & (rng.random(total) < cfg.p_logoff_observed)

    written = 0
    for i in range(total):
        row = (
            times[i], users[i], dst_users[i], src_names[i], dst_names[i],
            auth_type[i], logon_type[i],
        )
        auth.write((*row, "LogOn", outcome[i]))
        written += 1
        if closes[i]:
            auth.write((times[i] + durations[i], *row[1:], "LogOff", "Success"))
            written += 1
    return written


def _generate_admin_maintenance(
    cfg: GeneratorConfig,
    pop: Population,
    rng: np.random.Generator,
    auth: _Sink,
) -> int:
    """Benign admin fan-out -- the main false-positive source for Part 3."""
    admins = np.where(pop.roles == "admin")[0]
    written = 0
    lo, hi = cfg.admin_maintenance_hosts
    for day in range(cfg.n_days):
        for a in admins:
            if rng.random() >= cfg.p_admin_maintenance_day:
                continue
            n_hosts = int(rng.integers(lo, hi))
            targets = rng.integers(0, cfg.n_computers, size=n_hosts)
            base = day * SECONDS_PER_DAY + int(rng.integers(7 * 3600, 19 * 3600))
            for j, t in enumerate(targets):
                ts = base + j * int(rng.integers(20, 240)) + 1
                row = (
                    pop.users[a],
                    pop.users[a],
                    pop.computers[pop.home_host[a]],
                    pop.computers[t],
                    "Kerberos",
                    "Network",
                )
                auth.write((ts, *row, "LogOn", "Success"))
                written += 1
                # Closed at the same rate as any other logon. If only the
                # ordinary daily traffic produced LogOffs, whether a session
                # closes would reveal which part of the generator wrote the row.
                if rng.random() < cfg.p_logoff_observed:
                    median = cfg.session_seconds_median.get("Network", 600)
                    end = ts + int(
                        np.clip(rng.lognormal(np.log(median), 1.0), 5, 12 * 3600)
                    )
                    auth.write((end, *row, "LogOff", "Success"))
                    written += 1
    return written


def _generate_failure_bursts(
    cfg: GeneratorConfig,
    pop: Population,
    rng: np.random.Generator,
    auth: _Sink,
) -> int:
    """Password-expiry style failure runs -- benign, but brute-force shaped."""
    written = 0
    for _ in range(cfg.n_failure_bursts):
        u = int(rng.integers(0, pop.n_users))
        day = int(rng.integers(0, cfg.n_days))
        base = day * SECONDS_PER_DAY + int(rng.integers(6 * 3600, 20 * 3600))
        n_fail = int(rng.integers(4, 18))
        target = pop.home_host[u] if rng.random() < 0.6 else int(
            rng.choice(pop.server_idx, p=pop.server_weights)
        )
        for j in range(n_fail):
            auth.write(
                (
                    base + j * int(rng.integers(3, 45)) + 1,
                    pop.users[u],
                    pop.users[u],
                    pop.computers[pop.home_host[u]],
                    pop.computers[target],
                    "NTLM",
                    "Network",
                    "LogOn",
                    "Fail",
                )
            )
            written += 1
        # Most bursts end in a success once the password is reset.
        if rng.random() < 0.8:
            auth.write(
                (
                    base + n_fail * 50 + 1,
                    pop.users[u],
                    pop.users[u],
                    pop.computers[pop.home_host[u]],
                    pop.computers[target],
                    "Kerberos",
                    "Network",
                    "LogOn",
                    "Success",
                )
            )
            written += 1
    return written


# ---------------------------------------------------------------------------
# Red-team campaign
# ---------------------------------------------------------------------------


@dataclass
class Campaign:
    """A described, labelled intrusion -- the ground truth for Part 3."""

    start_time: int
    victim_user: str
    beachhead: str
    stolen_admin: str
    recon_targets: list[str] = field(default_factory=list)
    lateral_targets: list[str] = field(default_factory=list)
    objective: str = ""
    n_labelled_events: int = 0
    stages: list[dict] = field(default_factory=list)


def _generate_redteam(
    cfg: GeneratorConfig,
    pop: Population,
    rng: np.random.Generator,
    auth: _Sink,
    redteam: _Sink,
) -> Campaign:
    """Emit a four-stage campaign into both auth and the label file.

    Every row written here also goes to ``redteam.txt.gz``, so the labels are by
    construction a strict subset of the events -- the same relationship the real
    dataset has, and the thing an evaluation join depends on.
    """
    start_day = (
        cfg.redteam_start_day
        if cfg.redteam_start_day is not None
        else int(cfg.n_days * 0.55)
    )

    # The victim is an ordinary user; the attacker later steals an admin token.
    regulars = np.where(pop.roles == "regular")[0]
    admins = np.where(pop.roles == "admin")[0]
    victim = int(rng.choice(regulars))
    stolen = int(rng.choice(admins))
    beachhead = int(pop.home_host[victim])

    t = start_day * SECONDS_PER_DAY + int(rng.integers(9 * 3600, 16 * 3600))
    campaign = Campaign(
        start_time=t,
        victim_user=str(pop.users[victim]),
        beachhead=str(pop.computers[beachhead]),
        stolen_admin=str(pop.users[stolen]),
    )

    def emit(ts: int, user_i: int, src_i: int, dst_i: int, ok: bool,
             auth_type: str, logon: str, as_user_i: int | None = None) -> None:
        row = (
            ts,
            pop.users[user_i],
            pop.users[user_i if as_user_i is None else as_user_i],
            pop.computers[src_i],
            pop.computers[dst_i],
            auth_type,
            logon,
            "LogOn",
            "Success" if ok else "Fail",
        )
        auth.write(row)
        redteam.write(
            (ts, pop.users[user_i], pop.computers[src_i], pop.computers[dst_i])
        )
        campaign.n_labelled_events += 1

        # The attacker's sessions close at the same rate as everyone else's.
        # Without this, "a logon that is never followed by a logoff" would
        # single out the intrusion on its own -- a giveaway no real dataset
        # offers, and the kind of accidental tell this generator exists to
        # avoid.
        if ok and rng.random() < cfg.p_logoff_observed:
            median = cfg.session_seconds_median.get(logon, 600)
            end = ts + int(np.clip(rng.lognormal(np.log(median), 1.0), 5, 12 * 3600))
            auth.write((end, *row[1:7], "LogOff", "Success"))
            redteam.write(
                (end, pop.users[user_i], pop.computers[src_i],
                 pop.computers[dst_i])
            )
            campaign.n_labelled_events += 1

    # -- Stage 1: recon from the beachhead ---------------------------------
    # Deliberately mixes hosts the victim has legitimately used with hosts they
    # never have, so "unseen edge" catches only part of the stage.
    lo, hi = cfg.redteam_recon_hosts
    n_recon = int(rng.integers(lo, hi))
    known = pop.peer_hosts[victim]
    n_known = min(len(known), max(1, n_recon // 3))
    recon = np.concatenate([
        rng.choice(known, size=n_known, replace=False),
        rng.integers(0, cfg.n_computers, size=n_recon - n_known),
    ])
    for host in recon:
        t += int(rng.integers(25, 400))
        ok = rng.random() < 0.55  # a lot of recon fails
        emit(t, victim, beachhead, int(host), ok, "NTLM", "Network")
    campaign.recon_targets = [str(pop.computers[int(h)]) for h in recon]
    campaign.stages.append(
        {"stage": 1, "name": "recon", "hosts": len(recon), "start": campaign.start_time}
    )

    # -- Stage 2: dwell, then the stolen admin credential appears ----------
    dwell_lo, dwell_hi = cfg.redteam_dwell_hours
    t += int(rng.integers(dwell_lo, dwell_hi)) * 3600
    stage2_start = t
    # The victim's session obtains the admin token: source principal is still
    # the victim, destination principal is the stolen account. A NewCredentials
    # logon where the two differ is the actual Windows signature of this, and it
    # is only a usable signal because benign identity switches also exist above.
    emit(t, victim, beachhead, beachhead, True, "Kerberos", "NewCredentials",
         as_user_i=stolen)
    campaign.stages.append(
        {"stage": 2, "name": "credential_theft", "hosts": 1, "start": stage2_start}
    )

    # -- Stage 3: lateral movement using the admin credential --------------
    lo, hi = cfg.redteam_lateral_hosts
    n_lat = int(rng.integers(lo, hi))
    lateral = rng.choice(pop.server_idx, size=min(n_lat, len(pop.server_idx)),
                         replace=False)
    stage3_start = t
    for host in lateral:
        t += int(rng.integers(120, 1800))
        emit(t, stolen, beachhead, int(host), True, "Kerberos", "Network")
        # Attacker chains onward from the host just taken.
        if rng.random() < 0.5:
            t += int(rng.integers(60, 600))
            nxt = int(rng.integers(0, cfg.n_computers))
            emit(t, stolen, int(host), nxt, True, "Kerberos", "Network")
    campaign.lateral_targets = [str(pop.computers[int(h)]) for h in lateral]
    campaign.stages.append(
        {"stage": 3, "name": "lateral_movement", "hosts": len(lateral),
         "start": stage3_start}
    )

    # -- Stage 4: the objective -------------------------------------------
    t += int(rng.integers(1, 4)) * 3600
    # The objective must not be a host the attacker already took during lateral
    # movement, or this stage degenerates into a hop from a host to itself --
    # filtered out everywhere as a local logon, leaving the campaign with no
    # final move at all. Crown jewels and lateral targets are both drawn from
    # the server pool, so the overlap happens often enough to matter.
    remaining = [int(c) for c in pop.crown_jewel_idx if int(c) not in set(map(int, lateral))]
    objective = int(rng.choice(remaining)) if remaining else int(
        rng.choice([s for s in map(int, pop.server_idx)
                    if s not in set(map(int, lateral))] or [int(pop.server_idx[0])])
    )
    hop_from = int(lateral[-1]) if len(lateral) else beachhead
    emit(t, stolen, hop_from, objective, True, "Kerberos", "RemoteInteractive")
    for _ in range(int(rng.integers(3, 9))):
        t += int(rng.integers(30, 400))
        emit(t, stolen, objective, objective, True, "Kerberos", "Interactive")
    campaign.objective = str(pop.computers[objective])
    campaign.stages.append(
        {"stage": 4, "name": "objective", "hosts": 1, "start": t}
    )

    return campaign


# ---------------------------------------------------------------------------
# Secondary telemetry
# ---------------------------------------------------------------------------


def _generate_secondary(
    cfg: GeneratorConfig,
    pop: Population,
    rng: np.random.Generator,
    out_dir: Path,
    n_auth: int,
) -> dict[str, int]:
    """Emit proc, flows and dns, partly derived from the authentications.

    An earlier version drew all three from independent random host pairs while
    claiming they corroborated the auth stream. They did not: measured against
    the generated data, 0.7% of flows happened to share a host pair with any
    authentication, which is what chance alone produces. Part 2's corroboration
    step would have found nothing, and the claim would have collapsed the first
    time anyone checked it.

    Now a configurable share of flows and DNS lookups is generated *from* the
    authentication file: a network logon from C1 to C2 produces a flow between
    those hosts a second or two later, and usually a DNS lookup a few seconds
    before it. Self-authentications are excluded from flows -- an interactive
    logon at your own desk does not cross the network. The rest stays background
    noise so that corroboration discriminates instead of being automatic.

    Note the ordering: derived rows follow the order of ``auth.txt.gz``, which
    is grouped by generation stage rather than strictly sorted by time. Nothing
    in the pipeline depends on input ordering -- every query works from
    ``time_sec`` -- but the files are not claimed to be time-sorted.
    """
    counts: dict[str, int] = {}
    ports = ["N22", "N80", "N443", "N445", "N3389", "N53"] + [
        f"N{int(p)}" for p in rng.integers(1024, 65535, size=200)
    ]
    horizon = cfg.n_days * SECONDS_PER_DAY

    # Only an authentication that opens a network connection can produce a
    # flow: a LogOff ends one that already existed, and a local logon never
    # crosses the network. Both the volume target and the emission probability
    # are computed against that eligible population rather than the whole file.
    #
    # Getting this wrong is quiet. Basing the target on every auth row while
    # deriving only from eligible ones inflated the target without enlarging the
    # pool, so the derived share came out at 37% against a configured 65% --
    # the setting kept its name and stopped meaning it.
    n_eligible = 0
    with gzip.open(out_dir / "auth.txt.gz", "rt", encoding="utf-8") as fh:
        for line in fh:
            f = line.rstrip("\n").split(",")
            if len(f) == 9 and f[7] == "LogOn" and f[3] != f[4]:
                n_eligible += 1
    n_eligible = max(n_eligible, 1)

    n_flows_target = int(n_eligible * cfg.flows_per_auth)
    n_dns_target = int(n_eligible * cfg.dns_per_auth)

    p_flow = min(1.0, (n_flows_target * cfg.flows_derived_share) / n_eligible)
    p_dns = min(1.0, (n_dns_target * cfg.dns_derived_share) / n_eligible)

    def _traffic() -> tuple[int, int, int]:
        """Duration, packets and bytes for one flow."""
        pk = int(rng.geometric(0.05)) * 3
        return int(rng.geometric(0.08)), pk, pk * int(rng.integers(60, 1500))

    # -- pass one: telemetry that an authentication actually produced ---------
    with _Sink(out_dir / "flows.txt.gz") as flows, \
            _Sink(out_dir / "dns.txt.gz") as dns:
        with gzip.open(out_dir / "auth.txt.gz", "rt", encoding="utf-8") as fh:
            for line in fh:
                f = line.rstrip("\n").split(",")
                if len(f) != 9:
                    continue
                # Only a LogOn opens a connection. A LogOff ends one that
                # already existed, so it produces neither a DNS lookup nor a
                # fresh flow -- deriving from it invented traffic that had no
                # cause, and put DNS lookups *after* the authentication they
                # were supposed to precede.
                if f[7] != "LogOn":
                    continue
                t, src, dst = int(f[0]), f[3], f[4]
                if src == dst:
                    continue  # local logon, nothing crosses the network
                if rng.random() < p_dns:
                    # The name is resolved before the connection is made.
                    dns.write((max(1, t - int(rng.integers(1, 7))), src, dst))
                if rng.random() < p_flow:
                    dur, pk, by = _traffic()
                    dns_port = "N445" if f[6] == "Network" else "N3389"
                    flows.write((
                        t + int(rng.integers(0, 5)), dur, src,
                        ports[int(rng.integers(6, len(ports)))],
                        dst, dns_port, "6", pk, by,
                    ))

        # -- pass two: background traffic unrelated to any authentication ----
        n_bg_flows = max(0, n_flows_target - flows.count)
        if n_bg_flows:
            times = np.sort(rng.integers(1, horizon, size=n_bg_flows))
            s = rng.integers(0, cfg.n_computers, size=n_bg_flows)
            d = rng.integers(0, cfg.n_computers, size=n_bg_flows)
            sp = rng.integers(0, len(ports), size=n_bg_flows)
            dp = rng.integers(0, 6, size=n_bg_flows)
            proto = np.where(rng.random(n_bg_flows) < 0.85, "6", "17")
            for i in range(n_bg_flows):
                dur, pk, by = _traffic()
                flows.write((times[i], dur, pop.computers[s[i]], ports[sp[i]],
                             pop.computers[d[i]], ports[dp[i]], proto[i], pk, by))

        n_bg_dns = max(0, n_dns_target - dns.count)
        if n_bg_dns:
            times = np.sort(rng.integers(1, horizon, size=n_bg_dns))
            s = rng.integers(0, cfg.n_computers, size=n_bg_dns)
            d = rng.integers(0, cfg.n_computers, size=n_bg_dns)
            for i in range(n_bg_dns):
                dns.write((times[i], pop.computers[s[i]], pop.computers[d[i]]))

        counts["flows"] = flows.count
        counts["dns"] = dns.count

    with _Sink(out_dir / "proc.txt.gz") as proc:
        n = int(cfg.n_users * cfg.n_days * cfg.proc_per_user_day)
        times = np.sort(rng.integers(1, horizon, size=n))
        u = rng.integers(0, pop.n_users, size=n)
        pnames = rng.integers(1, 380, size=n)
        act = np.where(rng.random(n) < 0.5, "Start", "End")
        for i in range(n):
            ui = u[i]
            proc.write(
                (times[i], pop.users[ui], pop.computers[pop.home_host[ui]],
                 f"P{pnames[i]}", act[i])
            )
        counts["proc"] = proc.count

    return counts


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def generate(cfg: GeneratorConfig, out_dir: Path) -> dict:
    """Write a full synthetic dataset to ``out_dir`` and return a manifest.

    The manifest is written alongside the data as ``scenario.json`` and is the
    only place the ground truth is described in prose. Part 3 reads the labels
    from ``redteam.txt.gz``; the manifest is for humans and for the demo script.
    """
    cfg.validate()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(cfg.seed)
    pop = build_population(cfg, rng)

    campaign: Campaign | None = None
    with _Sink(out_dir / "auth.txt.gz") as auth, \
            _Sink(out_dir / "redteam.txt.gz") as redteam:
        benign = 0
        for day in range(cfg.n_days):
            benign += _generate_benign_day(day, cfg, pop, rng, auth)
        benign += _generate_admin_maintenance(cfg, pop, rng, auth)
        benign += _generate_failure_bursts(cfg, pop, rng, auth)
        if cfg.inject_redteam:
            campaign = _generate_redteam(cfg, pop, rng, auth, redteam)
        n_auth = auth.count

    secondary = _generate_secondary(cfg, pop, rng, out_dir, n_auth)

    n_labelled = campaign.n_labelled_events if campaign else 0
    manifest = {
        "generator_version": "1.0.0",
        "config": asdict(cfg),
        "population": {
            "n_users": cfg.n_users,
            "n_computers": cfg.n_computers,
            "n_admins": int((pop.roles == "admin").sum()),
            "n_service_accounts": int((pop.roles == "service").sum()),
            "servers": [str(c) for c in pop.computers[pop.server_idx]],
            "crown_jewels": [str(c) for c in pop.computers[pop.crown_jewel_idx]],
        },
        "counts": {
            "auth": n_auth,
            "auth_benign": n_auth - n_labelled,
            "auth_redteam": n_labelled,
            **secondary,
        },
        "class_balance": {
            "redteam_fraction": (n_labelled / n_auth) if n_auth else 0.0,
            "note": (
                "The positive class is on the order of 1 in 10^4 to 1 in 10^5. "
                "Any evaluation reporting accuracy rather than recall at a fixed "
                "alert budget is meaningless at this imbalance."
            ),
        },
        "ground_truth": asdict(campaign) if campaign else None,
        "benign_confounders": {
            "new_host_drift_rate": cfg.p_new_host_drift,
            "admin_maintenance_sweeps": "fan-out shaped, benign",
            "failure_bursts": cfg.n_failure_bursts,
            "server_skew": "top server takes ~15-20% of all destinations",
            "off_hours_users": int(pop.night_shift.sum()),
        },
    }
    (out_dir / "scenario.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
