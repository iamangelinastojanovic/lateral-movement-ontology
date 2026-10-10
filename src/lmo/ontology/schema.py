"""The ontology: entities, the edges between them, and why each column exists.

What an ontology buys over a table of events
--------------------------------------------
``events`` answers "what happened". It cannot answer "has this account ever
reached this host before", "which hosts could someone have moved through between
02:00 and 04:00", or "who else touched the machine this alert is about" without
rescanning everything, every time.

The ontology answers those by materialising what an analyst actually pivots on:
nodes for the things that have identity (accounts, machines, logon sessions) and
edges for the relationships between them, each edge carrying **when it was first
and last observed**. That one pair of columns is what turns "has this ever
happened before" from a scan into a lookup, and it is the foundation of every
detection in Part 3.

Point-in-time, not hindsight
----------------------------
``first_seen_sec`` on an edge is a fact about the past of that edge, so asking
"was this event the first time this pair was observed" is causal and safe.

What is *not* safe is asking a question whose answer depends on data that had not
arrived yet -- "is this host rare" computed over the whole 58 days, then used to
score an event on day 3. That is lookahead, and it inflates every metric. The
query layer therefore takes an ``as_of`` on any rarity question and looks only
backwards; see ``query.py``. Building that rule into the ontology now is cheaper
than discovering in Part 3 that the numbers were fiction.

Materialised, not views
-----------------------
These tables are built once by ``lmo build-graph`` rather than defined as views.
A view would always be fresh but would re-aggregate ~700k events on every
question, and an analyst pivoting through an investigation asks dozens of
questions a minute. The cost is that the graph goes stale after a new ingest,
which ``graph_runs`` records so a stale graph can be detected rather than
silently trusted.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    doc: str


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------

USER_COLUMNS: tuple[Column, ...] = (
    Column("user_uid", "VARCHAR", "Canonical 'name@domain'. The node's identity."),
    Column("user_name", "VARCHAR", "Account portion."),
    Column("user_domain", "VARCHAR", "Domain portion."),
    Column("is_machine_account", "BOOLEAN", "Name ends in '$'."),
    Column("is_anonymous", "BOOLEAN", "ANONYMOUS LOGON."),
    Column("first_seen_sec", "BIGINT", "Dataset clock of the first observation."),
    Column("last_seen_sec", "BIGINT", "Dataset clock of the last."),
    Column("first_seen", "TIMESTAMP", "Same, as a timestamp."),
    Column("last_seen", "TIMESTAMP", ""),
    Column("n_auth", "BIGINT", "Authentications where this is the source principal."),
    Column("n_auth_success", "BIGINT", ""),
    Column("n_auth_fail", "BIGINT", ""),
    Column("n_dst_hosts", "BIGINT", "Distinct hosts authenticated to."),
    Column("n_src_hosts", "BIGINT", "Distinct hosts authenticated from."),
    Column("n_active_days", "BIGINT", "Days with at least one event."),
    Column(
        "role_hint",
        "VARCHAR",
        "'service' | 'broad' | 'normal'. A HINT, not ground truth -- inferred "
        "from behaviour, and wrong for anyone whose job looks unusual.",
    ),
)

HOST_COLUMNS: tuple[Column, ...] = (
    Column("host", "VARCHAR", "Machine name. The node's identity."),
    Column("first_seen_sec", "BIGINT", ""),
    Column("last_seen_sec", "BIGINT", ""),
    Column("first_seen", "TIMESTAMP", ""),
    Column("last_seen", "TIMESTAMP", ""),
    Column("n_auth_in", "BIGINT", "Authentications where this is the destination."),
    Column("n_auth_out", "BIGINT", "...where it is the source."),
    Column("n_users_in", "BIGINT", "Distinct accounts that reached it."),
    Column("n_users_out", "BIGINT", "Distinct accounts that acted from it."),
    Column("in_degree", "BIGINT", "Distinct source hosts."),
    Column("out_degree", "BIGINT", "Distinct destination hosts."),
    Column(
        "dst_share",
        "DOUBLE",
        "Share of all authentication destinations. The hub measure: in this "
        "data one host takes ~10%, which is what a domain controller looks "
        "like, and why raw degree centrality finds nothing useful.",
    ),
    Column(
        "role_hint",
        "VARCHAR",
        "'hub' | 'server' | 'endpoint'. Behavioural inference, not inventory.",
    ),
)

#: A logon session, reconstructed by pairing each LogOff with the most recent
#: LogOn before it on the same (account, source, destination).
#:
#: The data has no session identifier, so every pairing is a heuristic, and a
#: LogOff is not guaranteed for every LogOn -- machines are powered off, agents
#: miss events. Unclosed sessions keep ``closed = false`` and a NULL end rather
#: than an invented one: an open session is a real observation, and guessing its
#: length would corrupt every duration statistic built on top.
#:
#: **``duration_sec`` is a lower bound, not a measurement.** Calibrated against
#: the generator, where the true length of every session is known:
#:
#: =================  =========  =========  ==================================
#: logon type         generated  recovered  why
#: =================  =========  =========  ==================================
#: Network              2.5 min    2.5 min  sparse; each session ends before
#:                                          the next begins, so exact
#: NewCredentials        10 min    9.5 min  same
#: Service               15 min    9.6 min  moderately dense
#: Unlock                30 min     14 min  dense
#: Interactive          120 min     61 min  long sessions, frequent returns
#: =================  =========  =========  ==================================
#:
#: The rule is one thing: pairing is exact while sessions on a triple do not
#: overlap, and under-reports once they do, because a logoff can be claimed by a
#: later logon than the one that opened it. Anything downstream that compares
#: durations should compare within a logon type, never across.
#:
#: This calibration is only possible because the synthetic world has ground
#: truth. On the real LANL data the same heuristic would run with no way to know
#: its error -- which is a large part of what the generator is for.
SESSION_COLUMNS: tuple[Column, ...] = (
    Column("session_uid", "VARCHAR", "Deterministic id of the logon."),
    Column("user_uid", "VARCHAR", ""),
    Column("src_host", "VARCHAR", "Where the logon came from."),
    Column("dst_host", "VARCHAR", "What was logged on to."),
    Column("logon_type", "VARCHAR", "Interactive / Network / Service / ..."),
    Column("auth_protocol", "VARCHAR", ""),
    Column("start_sec", "BIGINT", ""),
    Column("end_sec", "BIGINT", "NULL when no LogOff was observed."),
    Column("start_time", "TIMESTAMP", ""),
    Column("end_time", "TIMESTAMP", ""),
    Column("duration_sec", "BIGINT", "NULL for unclosed sessions."),
    Column("closed", "BOOLEAN", "Whether a matching LogOff was found."),
    Column("logon_event_uid", "VARCHAR", "Lineage back to the originating event."),
)

# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------

#: account -> host it authenticated to.
#:
#: The edge Part 3's first detection is built on. ``first_seen_sec`` makes
#: "this account has never reached this host before" a lookup.
EDGE_USER_HOST_COLUMNS: tuple[Column, ...] = (
    Column("user_uid", "VARCHAR", ""),
    Column("dst_host", "VARCHAR", ""),
    Column("first_seen_sec", "BIGINT", "When this pair was first observed."),
    Column("last_seen_sec", "BIGINT", ""),
    Column("first_seen", "TIMESTAMP", ""),
    Column("last_seen", "TIMESTAMP", ""),
    Column("n_total", "BIGINT", ""),
    Column("n_success", "BIGINT", ""),
    Column("n_fail", "BIGINT", ""),
    Column("n_src_hosts", "BIGINT", "From how many different machines."),
    Column("n_active_days", "BIGINT", "Days this pair was seen."),
)

#: host -> host, carried by an authentication.
#:
#: This is the lateral-movement edge. A path through this graph with increasing
#: timestamps is exactly the shape of an attacker walking through a network,
#: which is why ``paths_between`` in the query layer enforces time ordering
#: rather than mere connectivity.
EDGE_HOST_HOST_COLUMNS: tuple[Column, ...] = (
    Column("src_host", "VARCHAR", ""),
    Column("dst_host", "VARCHAR", ""),
    Column("first_seen_sec", "BIGINT", ""),
    Column("last_seen_sec", "BIGINT", ""),
    Column("first_seen", "TIMESTAMP", ""),
    Column("last_seen", "TIMESTAMP", ""),
    Column("n_total", "BIGINT", ""),
    Column("n_success", "BIGINT", ""),
    Column("n_fail", "BIGINT", ""),
    Column("n_users", "BIGINT", "Distinct accounts that used this hop."),
    Column("n_active_days", "BIGINT", ""),
)

GRAPH_TABLES: dict[str, tuple[Column, ...]] = {
    "entity_user": USER_COLUMNS,
    "entity_host": HOST_COLUMNS,
    "entity_session": SESSION_COLUMNS,
    "edge_user_host": EDGE_USER_HOST_COLUMNS,
    "edge_host_host": EDGE_HOST_HOST_COLUMNS,
}

GRAPH_SCHEMA_VERSION = "1.0.0"

#: A host above this share of all authentication destinations is called a hub.
#: Chosen from the data rather than from theory: in the generated world the top
#: destination sits near 10% and the next few near 3-5%, so 2% separates
#: infrastructure from ordinary machines without needing a fixed host list.
HUB_DST_SHARE = 0.02

#: Below this, a host that still receives from many distinct sources is a
#: "server" rather than an endpoint.
SERVER_MIN_USERS_IN = 20

#: 'broad' is the top slice of this population's own host-count distribution,
#: not a fixed number. A constant does not survive a change of estate: at 25
#: hosts, 549 of 599 generated accounts qualified, and a label that fits 92% of
#: the population carries no information. Admins and maintenance sweeps are
#: supposed to land here -- Part 3 needs to know which accounts touching many
#: machines is normal for.
BROAD_USER_PERCENTILE = 0.95

#: Floor under the percentile, for the degenerate case of a tiny or uniform
#: population where the 95th percentile would otherwise sit at a handful of
#: hosts and flag ordinary behaviour.
BROAD_USER_MIN_HOSTS = 25

#: Sessions longer than this are treated as never closed. A logon still open
#: after two weeks is a missing LogOff, not a fortnight at the keyboard.
MAX_SESSION_SECONDS = 14 * 24 * 3600


def create_table_sql(table: str, columns: tuple[Column, ...]) -> str:
    body = ",\n    ".join(f"{c.name} {c.type}" for c in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} (\n    {body}\n)"


def column_names(columns: tuple[Column, ...]) -> tuple[str, ...]:
    return tuple(c.name for c in columns)
