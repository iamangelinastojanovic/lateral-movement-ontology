"""Investigation primitives: the questions an analyst actually asks.

Each function here answers one question a person has while working an alert, and
returns rows rather than printing, so the same call serves the CLI today and the
API in Part 4.

Two rules run through all of it.

**Point in time.** Anything that judges whether something is unusual takes an
``as_of`` and looks only at what had been observed by then. Computing "this host
is rare" over the whole collection and applying it to day 3 uses data that had
not arrived yet; every metric built on that is inflated, and the inflation is
invisible because the code looks reasonable. Part 3's evaluation depends on this
rule holding here.

**Bounded work.** Path search over an event graph is combinatorial. Every entry
point takes a mandatory time window and a hop limit, and returns at most a stated
number of results, because an investigation tool that hangs is an investigation
tool nobody uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ontology.build import AUTH, require_fresh_graph

#: Ceiling on rows returned by any single investigation query.
DEFAULT_LIMIT = 200

#: Hops allowed in a path search. Three covers beachhead -> pivot -> target,
#: which is the shape most campaigns take; beyond four the result set grows
#: faster than a person can read it.
DEFAULT_MAX_HOPS = 3

#: Seconds either side of an authentication in which a network flow or DNS
#: lookup counts as corroborating it. Generous enough for clock skew between
#: sources, tight enough that unrelated traffic rarely lands inside.
CORROBORATION_WINDOW = 8


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


@dataclass
class Profile:
    """What is known about one entity, plus its strongest relationships."""

    kind: str
    key: str
    attributes: dict
    relationships: list[dict] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"{self.kind} {self.key}", ""]
        width = max((len(k) for k in self.attributes), default=0)
        for k, v in self.attributes.items():
            shown = f"{v:,}" if isinstance(v, int) else v
            lines.append(f"  {k:<{width}}  {shown}")
        if self.relationships:
            lines += ["", "  strongest relationships:"]
            for r in self.relationships:
                parts = "  ".join(
                    f"{k}={v:,}" if isinstance(v, int) else f"{k}={v}"
                    for k, v in r.items()
                )
                lines.append(f"    {parts}")
        return "\n".join(lines)


def user_profile(wh: Warehouse, uid: str, limit: int = 10) -> Profile:
    require_fresh_graph(wh)
    row = wh.con.execute(
        "SELECT * FROM entity_user WHERE user_uid = ?", [uid]
    ).fetchone()
    if row is None:
        raise LmoError(
            f"no account {uid!r} in the ontology",
            "Account names look like 'U00123@DOM1'. "
            "Try: SELECT user_uid FROM entity_user LIMIT 5",
        )
    cols = [d[0] for d in wh.con.description]
    attrs = dict(zip(cols, row, strict=True))

    rels = [
        {"host": h, "events": n, "failures": f, "first_seen": str(fs)}
        for h, n, f, fs in wh.con.execute(
            """
            SELECT dst_host, n_total, n_fail, first_seen
            FROM edge_user_host WHERE user_uid = ?
            ORDER BY n_total DESC LIMIT ?
            """,
            [uid, limit],
        ).fetchall()
    ]
    return Profile("account", uid, attrs, rels)


def host_profile(wh: Warehouse, host: str, limit: int = 10) -> Profile:
    require_fresh_graph(wh)
    row = wh.con.execute(
        "SELECT * FROM entity_host WHERE host = ?", [host]
    ).fetchone()
    if row is None:
        raise LmoError(
            f"no host {host!r} in the ontology",
            "Host names look like 'C00123'. "
            "Try: SELECT host FROM entity_host LIMIT 5",
        )
    cols = [d[0] for d in wh.con.description]
    attrs = dict(zip(cols, row, strict=True))

    rels = [
        {"account": u, "events": n, "failures": f, "first_seen": str(fs)}
        for u, n, f, fs in wh.con.execute(
            """
            SELECT user_uid, n_total, n_fail, first_seen
            FROM edge_user_host WHERE dst_host = ?
            ORDER BY n_total DESC LIMIT ?
            """,
            [host, limit],
        ).fetchall()
    ]
    return Profile("host", host, attrs, rels)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def timeline(
    wh: Warehouse,
    *,
    user: str | None = None,
    host: str | None = None,
    start_sec: int,
    end_sec: int,
    limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """Everything involving an account or a host, in order.

    The first thing anyone does with an alert is ask what else was happening
    around it. Filtering on a host matches it as *either* end: an analyst
    investigating a machine cares equally about what reached it and what it
    reached.
    """
    if user is None and host is None:
        raise LmoError("timeline needs either an account or a host to centre on",
                       "Pass --user or --host.")
    require_fresh_graph(wh)

    clauses = [AUTH, "time_sec BETWEEN ? AND ?"]
    params: list = [start_sec, end_sec]
    if user is not None:
        clauses.append("(src_user_uid = ? OR dst_user_uid = ?)")
        params += [user, user]
    if host is not None:
        clauses.append("(src_endpoint = ? OR dst_endpoint = ?)")
        params += [host, host]

    rows = wh.con.execute(
        f"""
        SELECT event_time, time_sec, src_user_uid, dst_user_uid,
               src_endpoint, dst_endpoint, auth_protocol, logon_type,
               activity_name, status, event_uid
        FROM events
        WHERE {' AND '.join(clauses)}
        ORDER BY time_sec
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


# ---------------------------------------------------------------------------
# Neighbourhood
# ---------------------------------------------------------------------------


def neighbours(
    wh: Warehouse, host: str, *, start_sec: int, end_sec: int,
    limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """Hosts one hop away in the window, in both directions."""
    require_fresh_graph(wh)
    rows = wh.con.execute(
        f"""
        SELECT 'out' AS direction, dst_endpoint AS other,
               count(*) AS events, count(DISTINCT src_user_uid) AS accounts,
               min(event_time) AS first_seen
        FROM events
        WHERE {AUTH} AND src_endpoint = ? AND dst_endpoint <> ?
          AND time_sec BETWEEN ? AND ?
        GROUP BY 2
        UNION ALL
        SELECT 'in', src_endpoint,
               count(*), count(DISTINCT src_user_uid), min(event_time)
        FROM events
        WHERE {AUTH} AND dst_endpoint = ? AND src_endpoint <> ?
          AND time_sec BETWEEN ? AND ?
        GROUP BY 2
        ORDER BY events DESC
        LIMIT ?
        """,
        [host, host, start_sec, end_sec, host, host, start_sec, end_sec, limit],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


# ---------------------------------------------------------------------------
# Time-ordered path search
# ---------------------------------------------------------------------------


def paths_between(
    wh: Warehouse,
    src_host: str,
    dst_host: str,
    *,
    start_sec: int,
    end_sec: int,
    max_hops: int = DEFAULT_MAX_HOPS,
    user: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Routes from one host to another where each hop happens *after* the last.

    This is the question the whole project is built around, and the time
    ordering is what makes it that question rather than a different one.

    Plain connectivity -- "is there a chain of authentications linking A to B" --
    is nearly always yes in a real network, and says nothing. A chain whose
    timestamps strictly increase is a route somebody *could have walked*: they
    reached the second host only after arriving at the first. That is lateral
    movement, and it is a far smaller set.

    The search runs over individual authentications rather than the aggregated
    edge table, because an aggregate edge has one first-seen timestamp and would
    silently allow a traversal at a time the hop never actually happened.

    Cost is why the window is mandatory rather than optional: each hop multiplies
    the frontier by the average out-degree, and on an unbounded window this does
    not finish. Traversals also refuse to revisit a host, both because an
    attacker looping back adds nothing and because cycles would not terminate.
    """
    if max_hops < 1 or max_hops > 6:
        raise LmoError(
            f"max_hops must be between 1 and 6, got {max_hops}",
            "Beyond four hops the result set grows faster than anyone can read "
            "it, and almost every pair of hosts becomes connected.",
        )
    if end_sec <= start_sec:
        raise LmoError("the time window is empty",
                       "end must be after start.")
    require_fresh_graph(wh)

    user_clause = "AND src_user_uid = ?" if user else ""
    params: list = [start_sec, end_sec]
    if user:
        params.append(user)

    rows = wh.con.execute(
        f"""
        WITH RECURSIVE hops AS (
            SELECT src_endpoint AS s, dst_endpoint AS d, time_sec AS t,
                   src_user_uid AS u, event_uid
            FROM events
            WHERE {AUTH}
              AND status_id = 1
              -- Only LogOn is a traversal. A LogOff is the end of a session
              -- that already happened, and counting it as a hop invents routes
              -- that run backwards out of a host nobody moved from.
              AND activity_name = 'LogOn'
              AND src_endpoint IS NOT NULL AND dst_endpoint IS NOT NULL
              AND src_endpoint <> dst_endpoint
              AND time_sec BETWEEN ? AND ?
              {user_clause}
        ),
        walk AS (
            SELECT d, t, 1 AS n_hops,
                   [s, d] AS path, [t] AS times, [u] AS accounts,
                   [event_uid] AS event_uids
            FROM hops
            WHERE s = ?

            UNION ALL

            SELECT h.d, h.t, w.n_hops + 1,
                   list_append(w.path, h.d),
                   list_append(w.times, h.t),
                   list_append(w.accounts, h.u),
                   list_append(w.event_uids, h.event_uid)
            FROM walk w
            JOIN hops h
              ON h.s = w.d
             AND h.t > w.t                          -- strictly later: the hop
             AND w.n_hops < ?                       -- could only be taken after
            WHERE NOT list_contains(w.path, h.d)    -- arriving
        )
        -- One row per distinct route, not per traversal of it. A pair of hosts
        -- that talk hourly would otherwise return the same three-host path
        -- hundreds of times and bury everything else.
        SELECT
            any_value(n_hops)    AS n_hops,
            path,
            any_value(times)     AS times,
            list_distinct(flatten(list(accounts))) AS accounts,
            any_value(event_uids) AS event_uids,
            min(times[1])        AS started_sec,
            min(t)               AS finished_sec,
            min(t - times[1])    AS elapsed_sec,
            count(*)             AS n_traversals
        FROM walk
        WHERE d = ?
        GROUP BY path
        ORDER BY n_hops, elapsed_sec
        LIMIT ?
        """,
        [*params, src_host, max_hops, dst_host, limit],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def render_paths(paths: list[dict]) -> str:
    if not paths:
        return "no time-ordered route found in this window"
    lines = []
    for p in paths:
        hops = " -> ".join(p["path"])
        who = sorted(set(p["accounts"]))
        mins = p["elapsed_sec"] / 60
        seen = p.get("n_traversals", 1)
        lines.append(
            f"{p['n_hops']} hop(s), {mins:,.0f} min, seen {seen}x   {hops}\n"
            f"    accounts: {', '.join(who)}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Point-in-time questions
# ---------------------------------------------------------------------------


def first_time_edges(
    wh: Warehouse, *, start_sec: int, end_sec: int, limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """Account-to-host pairs observed for the very first time in this window.

    Causal by construction: ``first_seen_sec`` is a fact about an edge's past,
    so "this pair had never been seen before now" uses nothing from the future.

    This is deliberately *not* a detection. On the generated data it fires
    thousands of times a week from ordinary behaviour -- people change projects,
    get new access, borrow a desk. It is the raw material Part 3 has to combine
    with other signals, and its false-positive volume is the whole reason the
    generator manufactures benign drift.
    """
    require_fresh_graph(wh)
    rows = wh.con.execute(
        """
        SELECT e.user_uid, e.dst_host, e.first_seen, e.first_seen_sec,
               e.n_total, e.n_fail,
               u.role_hint AS account_role, h.role_hint AS host_role
        FROM edge_user_host e
        JOIN entity_user u ON u.user_uid = e.user_uid
        JOIN entity_host h ON h.host = e.dst_host
        WHERE e.first_seen_sec BETWEEN ? AND ?
        ORDER BY e.first_seen_sec
        LIMIT ?
        """,
        [start_sec, end_sec, limit],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]


def host_rarity_as_of(
    wh: Warehouse, user: str, host: str, as_of_sec: int
) -> dict:
    """How unusual this account reaching this host is, judged only on the past.

    ``as_of_sec`` is not decoration. The tempting version counts over the whole
    table and is wrong: scoring a day-3 event with a count that includes day 40
    lets the model see the future, and every number it produces afterwards is
    too good. The bug leaves no trace in the output -- the code reads fine and
    the metrics simply improve -- so the guard has to be structural.
    """
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT
            count(*) FILTER (src_user_uid = ? AND dst_endpoint = ?) AS pair_before,
            count(*) FILTER (src_user_uid = ?)                      AS user_before,
            count(*) FILTER (dst_endpoint = ?)                      AS host_before,
            count(DISTINCT dst_endpoint) FILTER (src_user_uid = ?)  AS user_hosts_before
        FROM events
        WHERE {AUTH} AND time_sec < ?
        """,
        [user, host, user, host, user, as_of_sec],
    ).fetchone()
    pair, by_user, by_host, user_hosts = row
    return {
        "user_uid": user,
        "dst_host": host,
        "as_of_sec": as_of_sec,
        "pair_seen_before": pair,
        "is_first_contact": pair == 0,
        "user_events_before": by_user,
        "host_events_before": by_host,
        "user_distinct_hosts_before": user_hosts,
    }


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------


def corroborate(
    wh: Warehouse, *, time_sec: int, src_host: str, dst_host: str,
    window: int = CORROBORATION_WINDOW,
) -> dict:
    """Did the network agree that these two hosts talked around then?

    An authentication is one source's claim. A flow between the same pair of
    hosts seconds later, or a DNS lookup seconds before, is a second source
    saying the same thing -- which is worth far more than a higher score from
    the first one.

    This is the payoff for a fix made in Part 1: the generator originally drew
    flows from independent random host pairs while claiming they corroborated
    the auth stream, and 0.7% of them happened to match -- chance. Had that not
    been caught, this function would have returned nothing and looked broken.
    """
    lo, hi = time_sec - window, time_sec + window
    flows = wh.con.execute(
        """
        SELECT count(*), sum(byte_count), sum(packet_count)
        FROM events
        WHERE src_dataset = 'flows'
          AND src_endpoint = ? AND dst_endpoint = ?
          AND time_sec BETWEEN ? AND ?
        """,
        [src_host, dst_host, lo, hi],
    ).fetchone()
    dns = wh.con.execute(
        """
        SELECT count(*) FROM events
        WHERE src_dataset = 'dns'
          AND src_endpoint = ? AND resolved_endpoint = ?
          AND time_sec BETWEEN ? AND ?
        """,
        [src_host, dst_host, lo, time_sec],
    ).fetchone()[0]
    return {
        "src_host": src_host,
        "dst_host": dst_host,
        "time_sec": time_sec,
        "window_sec": window,
        "flows": flows[0],
        "flow_bytes": flows[1] or 0,
        "flow_packets": flows[2] or 0,
        "dns_lookups": dns,
        "corroborated": bool(flows[0] or dns),
    }
