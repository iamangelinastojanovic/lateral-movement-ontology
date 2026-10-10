"""Build the ontology from the normalised event table.

One pass per table, all of it SQL. The Python here assembles statements and
records what was built; DuckDB does the work.

Everything is derived from ``events`` and nothing from ``redteam_labels``. That
is not an oversight to fix later -- the graph is the feature source for Part 3,
and a graph that has seen the labels would teach any detector built on it to
recognise the answer rather than the pattern. A test asserts the separation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse, timer
from lmo.ontology.schema import (
    BROAD_USER_MIN_HOSTS,
    BROAD_USER_PERCENTILE,
    GRAPH_SCHEMA_VERSION,
    GRAPH_TABLES,
    HUB_DST_SHARE,
    MAX_SESSION_SECONDS,
    SERVER_MIN_USERS_IN,
    create_table_sql,
)

#: Every ontology query is about authentication. Declared once so a change of
#: source (adding Sysmon logons, say) happens in one place.
AUTH = "src_dataset = 'auth' AND class_uid = 3002"


@dataclass
class GraphStats:
    table: str
    rows: int = 0
    seconds: float = 0.0

    def as_dict(self) -> dict:
        return {"table": self.table, "rows": self.rows,
                "seconds": round(self.seconds, 3)}


@dataclass
class GraphReport:
    graph_id: str
    stats: list[GraphStats] = field(default_factory=list)
    seconds: float = 0.0
    source_runs: list[str] = field(default_factory=list)
    events_covered: int = 0

    def render(self) -> str:
        lines = [
            f"graph {self.graph_id}",
            f"built from {self.events_covered:,} events "
            f"across {len(self.source_runs)} ingest run(s)",
            "",
            f"{'table':<20}{'rows':>12}{'sec':>9}",
            "-" * 41,
        ]
        for s in self.stats:
            lines.append(f"{s.table:<20}{s.rows:>12,}{s.seconds:>9.2f}")
        lines += ["-" * 41,
                  f"{'total':<20}{sum(s.rows for s in self.stats):>12,}"
                  f"{self.seconds:>9.2f}"]
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "graph_id": self.graph_id,
            "seconds": round(self.seconds, 2),
            "events_covered": self.events_covered,
            "source_runs": self.source_runs,
            "tables": [s.as_dict() for s in self.stats],
        }


def create_graph_tables(wh: Warehouse) -> None:
    for table, columns in GRAPH_TABLES.items():
        wh.con.execute(create_table_sql(table, columns))
    wh.con.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_runs (
            graph_id VARCHAR PRIMARY KEY,
            built_at TIMESTAMP,
            schema_version VARCHAR,
            events_covered BIGINT,
            source_runs_json VARCHAR,
            max_event_time_sec BIGINT,
            stats_json VARCHAR
        )
        """
    )


def drop_graph(wh: Warehouse) -> None:
    for table in GRAPH_TABLES:
        wh.con.execute(f"DROP TABLE IF EXISTS {table}")
    create_graph_tables(wh)


# ---------------------------------------------------------------------------
# Individual builders
# ---------------------------------------------------------------------------


def _build_users(wh: Warehouse) -> int:
    wh.con.execute("DELETE FROM entity_user")
    wh.con.execute(
        f"""
        INSERT INTO entity_user
        WITH per_user AS (
            SELECT src_user_uid AS uid, count(DISTINCT dst_endpoint) AS n_hosts
            FROM events WHERE {AUTH} AND src_user_uid IS NOT NULL
            GROUP BY 1
        ),
        -- 'broad' is a percentile, not a fixed number. A constant tuned on one
        -- estate is meaningless on another: at 25 hosts, 549 of 599 accounts
        -- here qualified, which is a label that says nothing. The cut-off is
        -- the {BROAD_USER_PERCENTILE:.0%} point of this population's own
        -- distribution, so it keeps meaning "unusually many for here".
        cutoff AS (
            SELECT greatest(
                quantile_cont(n_hosts, {BROAD_USER_PERCENTILE}),
                {BROAD_USER_MIN_HOSTS}
            ) AS n FROM per_user
        )
        SELECT
            src_user_uid,
            any_value(src_user_name),
            any_value(src_user_domain),
            any_value(is_machine_account),
            any_value(is_anonymous),
            min(time_sec), max(time_sec),
            min(event_time), max(event_time),
            count(*),
            count(*) FILTER (status_id = 1),
            count(*) FILTER (status_id = 2),
            count(DISTINCT dst_endpoint),
            count(DISTINCT src_endpoint),
            count(DISTINCT day_index),
            CASE
                WHEN any_value(is_machine_account) THEN 'service'
                WHEN count(DISTINCT dst_endpoint) >= (SELECT n FROM cutoff)
                    THEN 'broad'
                ELSE 'normal'
            END
        FROM events
        WHERE {AUTH} AND src_user_uid IS NOT NULL
        GROUP BY src_user_uid
        """
    )
    return wh.count("entity_user")


def _build_hosts(wh: Warehouse) -> int:
    wh.con.execute("DELETE FROM entity_host")
    wh.con.execute(
        f"""
        INSERT INTO entity_host
        WITH total AS (
            SELECT count(*)::DOUBLE AS n FROM events WHERE {AUTH}
        ),
        inbound AS (
            SELECT dst_endpoint AS host,
                   min(time_sec) AS first_sec, max(time_sec) AS last_sec,
                   min(event_time) AS first_time, max(event_time) AS last_time,
                   count(*) AS n_in,
                   count(DISTINCT src_user_uid) AS n_users_in,
                   count(DISTINCT src_endpoint) AS in_degree
            FROM events WHERE {AUTH} AND dst_endpoint IS NOT NULL
            GROUP BY 1
        ),
        outbound AS (
            SELECT src_endpoint AS host,
                   min(time_sec) AS first_sec, max(time_sec) AS last_sec,
                   min(event_time) AS first_time, max(event_time) AS last_time,
                   count(*) AS n_out,
                   count(DISTINCT src_user_uid) AS n_users_out,
                   count(DISTINCT dst_endpoint) AS out_degree
            FROM events WHERE {AUTH} AND src_endpoint IS NOT NULL
            GROUP BY 1
        ),
        joined AS (
            -- A host may appear only as a source, only as a destination, or
            -- both, so this is a FULL OUTER JOIN and every aggregate needs a
            -- coalesce. least()/greatest() ignore NULLs in DuckDB, which is
            -- exactly what a one-sided host needs.
            SELECT
                coalesce(i.host, o.host) AS host,
                least(i.first_sec, o.first_sec) AS first_sec,
                greatest(i.last_sec, o.last_sec) AS last_sec,
                least(i.first_time, o.first_time) AS first_time,
                greatest(i.last_time, o.last_time) AS last_time,
                coalesce(i.n_in, 0) AS n_in,
                coalesce(o.n_out, 0) AS n_out,
                coalesce(i.n_users_in, 0) AS n_users_in,
                coalesce(o.n_users_out, 0) AS n_users_out,
                coalesce(i.in_degree, 0) AS in_degree,
                coalesce(o.out_degree, 0) AS out_degree
            FROM inbound i
            FULL OUTER JOIN outbound o ON i.host = o.host
        )
        SELECT
            j.host,
            j.first_sec, j.last_sec, j.first_time, j.last_time,
            j.n_in, j.n_out, j.n_users_in, j.n_users_out,
            j.in_degree, j.out_degree,
            j.n_in / t.n AS dst_share,
            CASE
                WHEN j.n_in / t.n >= {HUB_DST_SHARE} THEN 'hub'
                WHEN j.n_users_in >= {SERVER_MIN_USERS_IN} THEN 'server'
                ELSE 'endpoint'
            END
        FROM joined j CROSS JOIN total t
        """
    )
    return wh.count("entity_host")


def _build_edge_user_host(wh: Warehouse) -> int:
    wh.con.execute("DELETE FROM edge_user_host")
    wh.con.execute(
        f"""
        INSERT INTO edge_user_host
        SELECT
            src_user_uid, dst_endpoint,
            min(time_sec), max(time_sec),
            min(event_time), max(event_time),
            count(*),
            count(*) FILTER (status_id = 1),
            count(*) FILTER (status_id = 2),
            count(DISTINCT src_endpoint),
            count(DISTINCT day_index)
        FROM events
        WHERE {AUTH} AND src_user_uid IS NOT NULL AND dst_endpoint IS NOT NULL
        GROUP BY 1, 2
        """
    )
    return wh.count("edge_user_host")


def _build_edge_host_host(wh: Warehouse) -> int:
    """Host-to-host hops, excluding local logons.

    ``src = dst`` is someone logging on at their own machine. It is not a hop,
    and leaving it in would put a self-loop on nearly every host -- enough to
    make any path search wander in place.
    """
    wh.con.execute("DELETE FROM edge_host_host")
    wh.con.execute(
        f"""
        INSERT INTO edge_host_host
        SELECT
            src_endpoint, dst_endpoint,
            min(time_sec), max(time_sec),
            min(event_time), max(event_time),
            count(*),
            count(*) FILTER (status_id = 1),
            count(*) FILTER (status_id = 2),
            count(DISTINCT src_user_uid),
            count(DISTINCT day_index)
        FROM events
        WHERE {AUTH}
          AND src_endpoint IS NOT NULL AND dst_endpoint IS NOT NULL
          AND src_endpoint <> dst_endpoint
        GROUP BY 1, 2
        """
    )
    return wh.count("edge_host_host")


def _build_sessions(wh: Warehouse) -> int:
    """Close each logon with the logoff that actually belongs to it.

    Three pairings were tried; the first two are wrong in ways that look fine.

    *Next event is a logoff.* Breaks whenever sessions overlap -- an account
    logs on twice to a host before either closes, and the second logon claims
    the first one's logoff. Measured: interactive sessions came out at a
    25-minute median against a generated 120.

    *k-th logon with k-th logoff.* Handles overlap, but only if every logon
    closes. Roughly a quarter never do, so one missing logoff shifts every
    ordinal after it and the pairing drifts further the longer the window runs.
    Measured: a 72-hour median, which is worse and no more obviously wrong.

    *Each logoff closes the most recent logon before it* -- what runs here, as
    an ASOF join. Logoffs are the scarcer event, so letting each one consume
    exactly one logon is the direction that degrades gracefully: a missing
    logoff leaves its session open instead of corrupting its neighbours. Where
    two logoffs follow one logon, the earlier closes it and the later is
    dropped rather than reused.

    Still a heuristic -- the data carries no session identifier, so no pairing
    can be exact. Unclosed sessions keep a NULL end rather than an invented
    one; guessing would poison every duration built on this table.
    """
    wh.con.execute("DELETE FROM entity_session")
    wh.con.execute(
        f"""
        INSERT INTO entity_session
        WITH logs AS (
            SELECT event_uid, time_sec, event_time, src_user_uid,
                   src_endpoint, dst_endpoint, logon_type, auth_protocol,
                   activity_name
            FROM events
            WHERE {AUTH}
              AND status_id = 1
              AND activity_name IN ('LogOn', 'LogOff')
              AND src_user_uid IS NOT NULL
              AND src_endpoint IS NOT NULL AND dst_endpoint IS NOT NULL
        ),
        ons  AS (SELECT * FROM logs WHERE activity_name = 'LogOn'),
        offs AS (SELECT * FROM logs WHERE activity_name = 'LogOff'),
        -- For every logoff, the latest logon at or before it on the same
        -- triple. ASOF is what makes this one pass rather than a self-join
        -- with a correlated max().
        claimed AS (
            SELECT o.event_uid AS logon_uid, f.time_sec AS off_sec,
                   f.event_time AS off_time
            FROM offs f
            ASOF JOIN ons o
              ON f.src_user_uid = o.src_user_uid
             AND f.src_endpoint = o.src_endpoint
             AND f.dst_endpoint = o.dst_endpoint
             AND f.time_sec    >= o.time_sec
        ),
        -- A logon claimed by several logoffs closes at the first of them.
        closes AS (
            SELECT logon_uid, min(off_sec) AS off_sec, min(off_time) AS off_time
            FROM claimed GROUP BY 1
        )
        SELECT
            md5(o.event_uid || '|session'),
            o.src_user_uid, o.src_endpoint, o.dst_endpoint,
            o.logon_type, o.auth_protocol,
            o.time_sec,
            c.off_sec,
            o.event_time,
            c.off_time,
            c.off_sec - o.time_sec,
            c.off_sec IS NOT NULL,
            o.event_uid
        FROM ons o
        LEFT JOIN closes c
               ON c.logon_uid = o.event_uid
              -- A close further out than the cap is a lost event, not a
              -- fortnight at the keyboard. Better open than fabricated.
              AND c.off_sec <= o.time_sec + {MAX_SESSION_SECONDS}
        """
    )
    return wh.count("entity_session")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

_BUILDERS = (
    ("entity_user", _build_users),
    ("entity_host", _build_hosts),
    ("edge_user_host", _build_edge_user_host),
    ("edge_host_host", _build_edge_host_host),
    ("entity_session", _build_sessions),
)


def build_graph(wh: Warehouse) -> GraphReport:
    """Rebuild every ontology table from the current contents of ``events``."""
    create_graph_tables(wh)

    n_events = wh.con.execute(
        f"SELECT count(*) FROM events WHERE {AUTH}"
    ).fetchone()[0]
    if n_events == 0:
        raise LmoError(
            "there are no authentication events to build a graph from",
            "Run 'lmo ingest' first -- the ontology is derived from the "
            "'events' table, which is currently empty.",
        )

    graph_id = f"graph_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}"
    report = GraphReport(graph_id=graph_id, events_covered=n_events)
    t0 = timer()

    for table, builder in _BUILDERS:
        t = timer()
        rows = builder(wh)
        report.stats.append(GraphStats(table, rows, timer() - t))

    report.seconds = timer() - t0
    report.source_runs = [
        r[0] for r in wh.con.execute(
            f"SELECT DISTINCT run_id FROM events WHERE {AUTH} ORDER BY 1"
        ).fetchall()
    ]
    max_t = wh.con.execute(
        f"SELECT max(time_sec) FROM events WHERE {AUTH}"
    ).fetchone()[0]

    wh.con.execute(
        "INSERT OR REPLACE INTO graph_runs VALUES (?,?,?,?,?,?,?)",
        [
            graph_id,
            datetime.now(timezone.utc),
            GRAPH_SCHEMA_VERSION,
            n_events,
            json.dumps(report.source_runs),
            max_t,
            json.dumps([s.as_dict() for s in report.stats]),
        ],
    )
    return report


def graph_is_stale(wh: Warehouse) -> tuple[bool, str]:
    """Has ``events`` changed since the graph was last built?

    A stale graph answers confidently and wrongly, which is worse than refusing.
    Every query entry point checks this.
    """
    tables = {
        r[0] for r in wh.con.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
    }
    if "graph_runs" not in tables:
        return True, "no graph has been built yet"
    row = wh.con.execute(
        "SELECT graph_id, events_covered FROM graph_runs "
        "ORDER BY built_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return True, "no graph has been built yet"

    graph_id, covered = row
    now = wh.con.execute(
        f"SELECT count(*) FROM events WHERE {AUTH}"
    ).fetchone()[0]
    if now != covered:
        return True, (
            f"{graph_id} was built from {covered:,} authentication events, "
            f"but the warehouse now holds {now:,}"
        )
    return False, graph_id


def require_fresh_graph(wh: Warehouse) -> str:
    stale, detail = graph_is_stale(wh)
    if stale:
        raise LmoError(
            f"the ontology is out of date: {detail}",
            "Run 'lmo build-graph' to rebuild it from the current events.",
        )
    return detail
