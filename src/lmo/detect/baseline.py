"""Trailing-only statistical rarity, materialised once per detect run.

The lookahead trap
------------------
Computing "this pair is rare" over the whole collection and applying it to a
day-3 event lets the score see the future. The metrics improve, the code reads
fine, and nothing in the output looks wrong. Every table in this module is
keyed by ``day_index`` D and populated from ``day_index < D`` only -- the
production equivalent of ``query.host_rarity_as_of``, which takes an ``as_of``
and looks strictly backwards.

Keyed by day, not by bucket, because a per-bucket join against 770k events is
the thing we are trying not to do. A 3pm event is therefore scored with data
through yesterday: slightly stale same-day, never future. Same-day earlier
hours are the conservative miss; later hours of the same day are the bug this
exists to prevent.

Insufficient history (fewer than ``MIN_BASELINE_DAYS`` trailing days for the
account) zeroes the rarity signals rather than treating "we have never seen
this account" as "this pair is infinitely rare". Without that floor, day 0
would dominate every ranking.
"""

from __future__ import annotations

from lmo.detect.schema import (
    AUTH,
    FANOUT_DAYS,
    MIN_BASELINE_DAYS,
    TRAILING_DAYS,
)
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ontology.build import require_fresh_graph


def build_detect_auth(wh: Warehouse) -> None:
    """Project authentications once. Every later pass reads this, not ``events``.

    Joining ``events`` to itself for failure-runs was joining flows and DNS in
    as well: the filter lived in WHERE, after the join, and the detector spent
    its time hashing traffic that cannot be an authentication. Materialising
    the auth slice makes that class of mistake a scan of the wrong table
    instead of a silent cross product.
    """
    wh.con.execute(
        f"""
        CREATE OR REPLACE TABLE detect_auth AS
        SELECT event_uid, time_sec, day_index, hour_of_day,
               src_user_uid, dst_user_uid, src_endpoint, dst_endpoint,
               auth_protocol, logon_type, activity_name, status_id
        FROM events
        WHERE {AUTH}
          AND src_user_uid IS NOT NULL
        """
    )


def build_trailing(wh: Warehouse) -> None:
    """Materialise every trailing-window table from ``detect_auth``.

    Idempotent: each table is ``CREATE OR REPLACE``. Called once per detect
    run, before any signal that reads it. Joins run against the daily
    aggregates, not the raw event table -- a days × events join on the full
    warehouse is how this step used to spend its minute.
    """
    con = wh.con
    con.execute("CREATE OR REPLACE TABLE detect_days AS SELECT DISTINCT day_index FROM detect_auth")
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_daily_pair AS
        SELECT day_index,
               src_user_uid AS user_uid,
               dst_endpoint AS dst_host,
               count(*) AS n
        FROM detect_auth
        WHERE dst_endpoint IS NOT NULL
        GROUP BY 1, 2, 3
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_pair AS
        SELECT d.day_index, p.user_uid, p.dst_host, sum(p.n) AS n_trailing
        FROM detect_days d
        JOIN trailing_daily_pair p
          ON p.day_index < d.day_index
         AND p.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2, 3
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_daily_protocol AS
        SELECT day_index,
               src_user_uid AS user_uid,
               auth_protocol,
               logon_type,
               count(*) AS n
        FROM detect_auth
        GROUP BY 1, 2, 3, 4
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_protocol AS
        SELECT d.day_index, p.user_uid, p.auth_protocol, p.logon_type,
               sum(p.n) AS n_trailing
        FROM detect_days d
        JOIN trailing_daily_protocol p
          ON p.day_index < d.day_index
         AND p.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2, 3, 4
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_daily_hosts AS
        SELECT day_index,
               src_user_uid AS user_uid,
               count(DISTINCT dst_endpoint) AS n_dst
        FROM detect_auth
        GROUP BY 1, 2
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_host_count AS
        SELECT d.day_index, h.user_uid,
               avg(h.n_dst) AS mean_dsts,
               stddev_pop(h.n_dst) AS std_dsts,
               count(*) AS n_days
        FROM detect_days d
        JOIN trailing_daily_hosts h
          ON h.day_index < d.day_index
         AND h.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_hourly_fanout AS
        SELECT src_user_uid AS user_uid,
               day_index,
               (time_sec // 3600) * 3600 AS bucket_start_sec,
               count(DISTINCT dst_endpoint) AS n_dst
        FROM detect_auth
        GROUP BY 1, 2, 3
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_fanout_p95 AS
        SELECT d.day_index, h.user_uid,
               quantile_cont(h.n_dst, 0.95) AS p95_dsts,
               count(*) AS n_buckets
        FROM detect_days d
        JOIN trailing_hourly_fanout h
          ON h.day_index < d.day_index
         AND h.day_index >= d.day_index - {FANOUT_DAYS}
        GROUP BY 1, 2
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_daily_dst_users AS
        SELECT day_index, dst_endpoint AS dst_host, src_user_uid AS user_uid
        FROM detect_auth
        WHERE dst_endpoint IS NOT NULL
        GROUP BY 1, 2, 3
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_dst_popularity AS
        SELECT d.day_index, p.dst_host, count(DISTINCT p.user_uid) AS n_users
        FROM detect_days d
        JOIN trailing_daily_dst_users p
          ON p.day_index < d.day_index
         AND p.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_daily_kerberos AS
        SELECT day_index, dst_endpoint AS dst_host,
               count(*) FILTER (auth_protocol = 'Kerberos') AS n_krb,
               count(*) AS n_auth
        FROM detect_auth
        WHERE dst_endpoint IS NOT NULL
        GROUP BY 1, 2
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_host_kerberos AS
        SELECT d.day_index, k.dst_host,
               sum(k.n_krb)::DOUBLE / sum(k.n_auth) AS kerberos_share,
               sum(k.n_auth) AS n_auth
        FROM detect_days d
        JOIN trailing_daily_kerberos k
          ON k.day_index < d.day_index
         AND k.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_user_hours AS
        SELECT d.day_index, a.src_user_uid AS user_uid,
               quantile_cont(a.hour_of_day, 0.10) AS p10_hour,
               quantile_cont(a.hour_of_day, 0.90) AS p90_hour,
               count(*) AS n_events
        FROM detect_days d
        JOIN detect_auth a
          ON a.day_index < d.day_index
         AND a.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE trailing_user_volume AS
        SELECT d.day_index, h.user_uid,
               count(*) AS n_days,
               sum(h.n_dst) AS n_events
        FROM detect_days d
        JOIN trailing_daily_hosts h
          ON h.day_index < d.day_index
         AND h.day_index >= d.day_index - {TRAILING_DAYS}
        GROUP BY 1, 2
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_src_first AS
        SELECT src_user_uid AS user_uid,
               src_endpoint AS src_host,
               min(time_sec) AS first_from_sec
        FROM detect_auth
        WHERE src_endpoint IS NOT NULL
        GROUP BY 1, 2
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE trailing_user_first AS
        SELECT src_user_uid AS user_uid, min(time_sec) AS first_any_sec
        FROM detect_auth
        GROUP BY 1
        """
    )


def build_bucket_dsts(wh: Warehouse) -> None:
    """Distinct destinations per unit. Shared by rarity, hub-avoidance, chain."""
    wh.con.execute(
        f"""
        CREATE OR REPLACE TABLE detect_bucket_dsts AS
        SELECT src_user_uid AS user_uid,
               src_endpoint AS src_host,
               (time_sec // 3600) * 3600 AS bucket_start_sec,
               dst_endpoint AS dst_host
        FROM detect_auth
        WHERE src_endpoint IS NOT NULL
          AND dst_endpoint IS NOT NULL
        GROUP BY 1, 2, 3, 4
        """
    )


def apply_baseline_signals(wh: Warehouse) -> None:
    """Fill layer-3 columns on ``detect_units`` from the trailing tables."""
    con = wh.con
    con.execute(
        """
        UPDATE detect_units u
        SET pair_rarity = s.rarity
        FROM (
            SELECT b.user_uid, b.src_host, b.bucket_start_sec,
                   avg(1.0 / (coalesce(t.n_trailing, 0) + 1.0)) AS rarity
            FROM detect_bucket_dsts b
            JOIN detect_units u2
              ON u2.user_uid = b.user_uid
             AND u2.src_host = b.src_host
             AND u2.bucket_start_sec = b.bucket_start_sec
            LEFT JOIN trailing_pair t
              ON t.day_index = u2.day_index
             AND t.user_uid = b.user_uid
             AND t.dst_host = b.dst_host
            GROUP BY 1, 2, 3
        ) s
        WHERE u.user_uid = s.user_uid
          AND u.src_host = s.src_host
          AND u.bucket_start_sec = s.bucket_start_sec
        """
    )
    con.execute(
        f"""
        UPDATE detect_units u
        SET protocol_rarity = s.rarity
        FROM (
            SELECT e.src_user_uid AS user_uid,
                   e.src_endpoint AS src_host,
                   (e.time_sec // 3600) * 3600 AS bucket_start_sec,
                   avg(1.0 / (coalesce(t.n_trailing, 0) + 1.0)) AS rarity
            FROM detect_auth e
            LEFT JOIN trailing_protocol t
              ON t.day_index = e.day_index
             AND t.user_uid = e.src_user_uid
             AND t.auth_protocol IS NOT DISTINCT FROM e.auth_protocol
             AND t.logon_type IS NOT DISTINCT FROM e.logon_type
            WHERE e.src_endpoint IS NOT NULL
            GROUP BY 1, 2, 3
        ) s
        WHERE u.user_uid = s.user_uid
          AND u.src_host = s.src_host
          AND u.bucket_start_sec = s.bucket_start_sec
        """
    )
    con.execute(
        """
        UPDATE detect_units u
        SET host_count_z = CASE
            WHEN t.mean_dsts IS NULL THEN 0
            WHEN t.std_dsts IS NULL OR t.std_dsts = 0 THEN
                CASE WHEN u.n_distinct_dst > t.mean_dsts THEN 4.0 ELSE 0 END
            ELSE (u.n_distinct_dst - t.mean_dsts) / t.std_dsts
        END
        FROM trailing_host_count t
        WHERE t.day_index = u.day_index
          AND t.user_uid = u.user_uid
        """
    )
    con.execute(
        """
        UPDATE detect_units u
        SET dst_popularity = s.rarity
        FROM (
            SELECT b.user_uid, b.src_host, b.bucket_start_sec,
                   avg(1.0 / (coalesce(t.n_users, 0) + 1.0)) AS rarity
            FROM detect_bucket_dsts b
            JOIN detect_units u2
              ON u2.user_uid = b.user_uid
             AND u2.src_host = b.src_host
             AND u2.bucket_start_sec = b.bucket_start_sec
            LEFT JOIN trailing_dst_popularity t
              ON t.day_index = u2.day_index
             AND t.dst_host = b.dst_host
            GROUP BY 1, 2, 3
        ) s
        WHERE u.user_uid = s.user_uid
          AND u.src_host = s.src_host
          AND u.bucket_start_sec = s.bucket_start_sec
        """
    )
    # Without a few days of this account's own past, "rare" just means "new
    # to the collection". Zero the trailing signals rather than let day 0
    # rank above the campaign.
    con.execute(
        f"""
        UPDATE detect_units u
        SET pair_rarity = 0,
            protocol_rarity = 0,
            host_count_z = 0,
            dst_popularity = 0,
            fan_out = 0,
            off_hours = 0
        FROM (
            SELECT u2.user_uid, u2.src_host, u2.bucket_start_sec
            FROM detect_units u2
            LEFT JOIN trailing_user_volume v
              ON v.day_index = u2.day_index
             AND v.user_uid = u2.user_uid
            WHERE v.n_days IS NULL OR v.n_days < {MIN_BASELINE_DAYS}
        ) s
        WHERE u.user_uid = s.user_uid
          AND u.src_host = s.src_host
          AND u.bucket_start_sec = s.bucket_start_sec
        """
    )


def pair_count_as_of(wh: Warehouse, user: str, host: str, as_of_sec: int) -> int:
    """Occurrences of (account, dest) strictly before ``as_of_sec``.

    Mirrors ``query.host_rarity_as_of``: the ``as_of`` is not decoration.
    """
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT count(*) FROM events
        WHERE {AUTH}
          AND src_user_uid = ? AND dst_endpoint = ?
          AND time_sec < ?
          AND time_sec >= ? - {TRAILING_DAYS} * 86400
        """,
        [user, host, as_of_sec, as_of_sec],
    ).fetchone()
    return int(row[0])


def protocol_count_as_of(
    wh: Warehouse, user: str, protocol: str, logon_type: str, as_of_sec: int
) -> int:
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT count(*) FROM events
        WHERE {AUTH}
          AND src_user_uid = ?
          AND auth_protocol IS NOT DISTINCT FROM ?
          AND logon_type IS NOT DISTINCT FROM ?
          AND time_sec < ?
          AND time_sec >= ? - {TRAILING_DAYS} * 86400
        """,
        [user, protocol, logon_type, as_of_sec, as_of_sec],
    ).fetchone()
    return int(row[0])


def dst_users_as_of(wh: Warehouse, host: str, as_of_sec: int) -> int:
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT count(DISTINCT src_user_uid) FROM events
        WHERE {AUTH}
          AND dst_endpoint = ?
          AND time_sec < ?
          AND time_sec >= ? - {TRAILING_DAYS} * 86400
        """,
        [host, as_of_sec, as_of_sec],
    ).fetchone()
    return int(row[0])


def host_count_mean_as_of(wh: Warehouse, user: str, as_of_sec: int) -> float | None:
    """Mean of this account's daily distinct-dest counts before ``as_of_sec``."""
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT avg(n_dst) FROM (
            SELECT day_index, count(DISTINCT dst_endpoint) AS n_dst
            FROM events
            WHERE {AUTH} AND src_user_uid = ? AND time_sec < ?
            GROUP BY 1
        )
        """,
        [user, as_of_sec],
    ).fetchone()
    return None if row[0] is None else float(row[0])


def kerberos_share_as_of(wh: Warehouse, host: str, as_of_sec: int) -> float | None:
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT count(*) FILTER (auth_protocol = 'Kerberos')::DOUBLE / nullif(count(*), 0)
        FROM events
        WHERE {AUTH} AND dst_endpoint = ? AND time_sec < ?
        """,
        [host, as_of_sec],
    ).fetchone()
    return None if row[0] is None else float(row[0])


def hour_percentiles_as_of(
    wh: Warehouse, user: str, as_of_sec: int
) -> tuple[float, float] | None:
    require_fresh_graph(wh)
    row = wh.con.execute(
        f"""
        SELECT quantile_cont(hour_of_day, 0.10), quantile_cont(hour_of_day, 0.90)
        FROM events
        WHERE {AUTH} AND src_user_uid = ? AND time_sec < ?
        """,
        [user, as_of_sec],
    ).fetchone()
    if row[0] is None:
        return None
    return float(row[0]), float(row[1])


def resolve_day_range(
    wh: Warehouse, start_day: int | None, end_day: int | None
) -> tuple[int, int]:
    row = wh.con.execute(
        f"SELECT min(day_index), max(day_index) FROM events WHERE {AUTH}"
    ).fetchone()
    if row[0] is None:
        raise LmoError(
            "there are no authentication events to detect over",
            "Run 'lmo ingest' and 'lmo build-graph' first.",
        )
    lo, hi = int(row[0]), int(row[1])
    if start_day is None:
        start_day = lo
    if end_day is None:
        end_day = hi
    if start_day > end_day:
        raise LmoError(
            f"start-day {start_day} is after end-day {end_day}",
            "The range is inclusive; swap them, or omit both to use every day.",
        )
    return start_day, end_day
