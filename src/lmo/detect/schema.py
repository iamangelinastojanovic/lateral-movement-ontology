"""Alert units, signal tables, and the bookkeeping around a detect run.

The alerting unit is (account, source host, hour), not an event. 770k events
cannot each be a candidate, and a campaign spread over 30 events would otherwise
produce 30 alerts for one incident. An analyst triages "this account, from this
machine, in this hour"; that is also the grain Part 4 will render.

Every baseline that feeds these tables is computed from ``time_sec`` strictly
before the bucket starts. The trailing tables are keyed by ``day_index`` and
built once per run so a rarity lookup is a join, not a per-row scan. See
``baseline.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from lmo.ingest.engine import Warehouse


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    doc: str


BUCKET_SECONDS = 3600
TRAILING_DAYS = 30
FANOUT_DAYS = 14
FAILURE_WINDOW_SEC = 600
FAILURE_RUN_MIN = 5
KERBEROS_SHARE_MIN = 0.90
NTLM_MIN_TRAILING = 10
HOUR_MIN_TRAILING = 20
MIN_BASELINE_DAYS = 3
CHAIN_BURST_MIN = 2

AUTH = "src_dataset = 'auth' AND class_uid = 3002"

SIGNAL_NAMES: tuple[str, ...] = (
    "first_contact",
    "identity_switch",
    "ntlm_downgrade",
    "failure_run",
    "fail_then_success",
    "off_hours",
    "fan_out",
    "new_edge_burst",
    "hub_avoidance",
    "chain_extension",
    "new_source_host",
    "pair_rarity",
    "protocol_rarity",
    "host_count_z",
    "dst_popularity",
)

DETECT_SCHEMA_VERSION = "1.0.0"

ALERT_COLUMNS: tuple[Column, ...] = (
    Column("alert_uid", "VARCHAR", "md5(run_id|user|src|bucket_start)."),
    Column("run_id", "VARCHAR", "Detect run that produced this row."),
    Column("user_uid", "VARCHAR", "Account the activity is attributed to."),
    Column("src_host", "VARCHAR", "Machine the authentications came from."),
    Column("bucket_start_sec", "BIGINT", "Inclusive start of the hour."),
    Column("bucket_end_sec", "BIGINT", "Exclusive end of the hour."),
    Column("score", "DOUBLE", "Weighted sum of normalised signals."),
    Column("band", "VARCHAR", "'high' | 'medium' | 'low'."),
    Column("n_events", "BIGINT", "Authentications in the bucket."),
    Column("n_distinct_dst", "BIGINT", "Distinct destinations in the bucket."),
    Column("n_fail", "BIGINT", "Failures in the bucket."),
    Column("signals_json", "VARCHAR", "{signal_name: contribution}."),
    Column("event_uids", "VARCHAR[]", "Contributing events, for lineage."),
    Column("created_at", "TIMESTAMP", ""),
)

EVENT_SIGNAL_COLUMNS: tuple[Column, ...] = (
    Column("run_id", "VARCHAR", ""),
    Column("event_uid", "VARCHAR", ""),
    Column("signal_name", "VARCHAR", ""),
    Column("value", "DOUBLE", ""),
)

# Wide per-unit table. Defaults are 0 so a missing join is "signal did not
# fire", not NULL arithmetic. event_uids stay on this table so scoring can
# copy them onto alerts without a second aggregation.
_UNIT_SIGNAL_SQL = ",\n    ".join(
    f"{name} DOUBLE DEFAULT 0" for name in SIGNAL_NAMES
)

DETECT_UNITS_SQL = f"""
CREATE TABLE IF NOT EXISTS detect_units (
    user_uid VARCHAR,
    src_host VARCHAR,
    bucket_start_sec BIGINT,
    bucket_end_sec BIGINT,
    day_index INTEGER,
    n_events BIGINT,
    n_distinct_dst BIGINT,
    n_fail BIGINT,
    event_uids VARCHAR[],
    {_UNIT_SIGNAL_SQL}
)
"""

TRAILING_TABLES: tuple[str, ...] = (
    "trailing_daily_pair",
    "trailing_pair",
    "trailing_daily_protocol",
    "trailing_protocol",
    "trailing_daily_hosts",
    "trailing_host_count",
    "trailing_hourly_fanout",
    "trailing_fanout_p95",
    "trailing_dst_popularity",
    "trailing_host_kerberos",
    "trailing_user_hours",
    "trailing_user_volume",
    "trailing_src_first",
    "detect_bucket_dsts",
    "detect_activated",
    "detect_chain",
    "detect_auth",
    "detect_days",
    "trailing_user_first",
    "trailing_daily_dst_users",
    "trailing_daily_kerberos",
)


def _create_table_sql(table: str, columns: tuple[Column, ...]) -> str:
    body = ",\n    ".join(f"{c.name} {c.type}" for c in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} (\n    {body}\n)"


def create_detect_tables(wh: Warehouse) -> None:
    wh.con.execute(_create_table_sql("alerts", ALERT_COLUMNS))
    wh.con.execute(_create_table_sql("detect_event_signals", EVENT_SIGNAL_COLUMNS))
    wh.con.execute(DETECT_UNITS_SQL)
    wh.con.execute(
        """
        CREATE TABLE IF NOT EXISTS detect_runs (
            run_id VARCHAR PRIMARY KEY,
            built_at TIMESTAMP,
            schema_version VARCHAR,
            graph_id VARCHAR,
            start_day INTEGER,
            end_day INTEGER,
            n_units BIGINT,
            n_alerts BIGINT,
            n_signals BIGINT,
            seconds DOUBLE,
            weights_json VARCHAR,
            stats_json VARCHAR
        )
        """
    )


def reset_detect_outputs(wh: Warehouse) -> None:
    """Drop derived detect tables; keep ``detect_runs`` as history."""
    for table in (
        "alerts",
        "detect_event_signals",
        "detect_units",
        *TRAILING_TABLES,
    ):
        wh.con.execute(f"DROP TABLE IF EXISTS {table}")
    create_detect_tables(wh)
