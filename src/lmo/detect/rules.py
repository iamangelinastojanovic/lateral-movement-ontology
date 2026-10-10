"""Layer 1 — deterministic rules, each individually weak.

Implemented as SQL returning ``(event_uid, signal_name, value)``. Python
loops over 770k events would work and would be the wrong default: the same
predicates are cheaper as scans, and a rule that cannot be written in SQL is
usually a rule that is doing scoring in disguise.

Each row is weak on purpose. ~1.8% of benign authentications are first
contacts, ~3% are identity switches, password-expiry looks like a failure
run. The point of the layer is to name the shapes so the later layers can
combine them, not to catch the campaign alone.
"""

from __future__ import annotations

from lmo.detect.schema import (
    AUTH,
    BUCKET_SECONDS,
    FAILURE_RUN_MIN,
    FAILURE_WINDOW_SEC,
    HOUR_MIN_TRAILING,
    KERBEROS_SHARE_MIN,
    NTLM_MIN_TRAILING,
)
from lmo.ingest.engine import Warehouse


def emit_rule_signals(wh: Warehouse, run_id: str) -> int:
    """Write every layer-1 firing into ``detect_event_signals``. Returns rows."""
    before = wh.count("detect_event_signals")
    _first_contact(wh, run_id)
    _identity_switch(wh, run_id)
    _ntlm_downgrade(wh, run_id)
    _failure_run(wh, run_id)
    _fail_then_success(wh, run_id)
    _off_hours(wh, run_id)
    return wh.count("detect_event_signals") - before


def _insert(wh: Warehouse, run_id: str, signal: str, select_event_uid: str) -> None:
    wh.con.execute(
        f"""
        INSERT INTO detect_event_signals (run_id, event_uid, signal_name, value)
        SELECT ?, event_uid, '{signal}', 1.0
        FROM ({select_event_uid})
        """,
        [run_id],
    )


def _first_contact(wh: Warehouse, run_id: str) -> None:
    """The event *is* the first time this account reached this host.

    Causal by construction: ``first_seen_sec`` is a fact about the edge's
    past. Scoring a first-contact with a count that includes later repeats of
    the same pair would be lookahead, and is not what this does.
    """
    _insert(
        wh, run_id, "first_contact",
        f"""
        SELECT e.event_uid
        FROM detect_auth e
        JOIN edge_user_host eh
          ON eh.user_uid = e.src_user_uid
         AND eh.dst_host = e.dst_endpoint
        WHERE eh.first_seen_sec = e.time_sec
        """,
    )


def _identity_switch(wh: Warehouse, run_id: str) -> None:
    _insert(
        wh, run_id, "identity_switch",
        f"""
        SELECT event_uid FROM detect_auth
        WHERE dst_user_uid IS NOT NULL
          AND src_user_uid <> dst_user_uid
          AND logon_type = 'NewCredentials'
        """,
    )


def _ntlm_downgrade(wh: Warehouse, run_id: str) -> None:
    """NTLM to a host whose *trailing* traffic is almost all Kerberos.

    Using the whole collection would let a host that later flipped to NTLM
    look mixed when scored on day 3. The join is onto the day-keyed trailing
    table, which only contains ``day_index < today``.
    """
    _insert(
        wh, run_id, "ntlm_downgrade",
        f"""
        SELECT e.event_uid
        FROM detect_auth e
        JOIN trailing_host_kerberos t
          ON t.day_index = e.day_index
         AND t.dst_host = e.dst_endpoint
        WHERE e.auth_protocol = 'NTLM'
          AND t.kerberos_share >= {KERBEROS_SHARE_MIN}
          AND t.n_auth >= {NTLM_MIN_TRAILING}
        """,
    )


def _failure_run(wh: Warehouse, run_id: str) -> None:
    """≥5 failures from the same account and source host in ten minutes."""
    _insert(
        wh, run_id, "failure_run",
        f"""
        SELECT event_uid FROM (
            SELECT event_uid,
                   count(*) OVER (
                       PARTITION BY src_user_uid, src_endpoint
                       ORDER BY time_sec
                       RANGE BETWEEN {FAILURE_WINDOW_SEC} PRECEDING AND CURRENT ROW
                   ) AS n_fail_window
            FROM detect_auth
            WHERE status_id = 2 AND src_endpoint IS NOT NULL
        )
        WHERE n_fail_window >= {FAILURE_RUN_MIN}
        """,
    )


def _fail_then_success(wh: Warehouse, run_id: str) -> None:
    """A success on a pair that just had a failure run.

    Same (account, source, destination), failures in the ten minutes before
    the success. Password-expiry bursts end this way too, which is why the
    weight on this signal stays modest.
    """
    _insert(
        wh, run_id, "fail_then_success",
        f"""
        SELECT s.event_uid
        FROM detect_auth s
        JOIN detect_auth f
          ON f.src_user_uid = s.src_user_uid
         AND f.src_endpoint = s.src_endpoint
         AND f.dst_endpoint = s.dst_endpoint
         AND f.status_id = 2
         AND f.time_sec >= s.time_sec - {FAILURE_WINDOW_SEC}
         AND f.time_sec < s.time_sec
        WHERE s.status_id = 1
        GROUP BY s.event_uid
        HAVING count(*) >= {FAILURE_RUN_MIN}
        """,
    )


def _off_hours(wh: Warehouse, run_id: str) -> None:
    """Outside this account's own trailing 10th–90th percentile hours.

    Linear percentiles wrap badly around midnight, so a night-shift account
    whose hours are 22–06 looks like it works 0–22 and will not flag a noon
    login. That is a known miss, not an oversight: circular hour statistics
    were tried and made the join harder to test than the signal was worth.
    """
    _insert(
        wh, run_id, "off_hours",
        f"""
        SELECT e.event_uid
        FROM detect_auth e
        JOIN trailing_user_hours h
          ON h.day_index = e.day_index
         AND h.user_uid = e.src_user_uid
        WHERE h.n_events >= {HOUR_MIN_TRAILING}
          AND (e.hour_of_day < h.p10_hour OR e.hour_of_day > h.p90_hour)
        """,
    )


def aggregate_rules_onto_units(wh: Warehouse) -> None:
    """Roll event-level firings up onto (account, source, hour)."""
    wh.con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE rule_agg AS
        SELECT e.src_user_uid AS user_uid,
               e.src_endpoint AS src_host,
               (e.time_sec // {BUCKET_SECONDS}) * {BUCKET_SECONDS} AS bucket_start_sec,
               s.signal_name,
               count(*) AS n,
               max(s.value) AS mx
        FROM detect_event_signals s
        JOIN detect_auth e ON e.event_uid = s.event_uid
        GROUP BY 1, 2, 3, 4
        """
    )
    # Binary rules: any firing in the bucket.
    for name in (
        "identity_switch",
        "ntlm_downgrade",
        "failure_run",
        "fail_then_success",
    ):
        wh.con.execute(
            f"""
            UPDATE detect_units u
            SET {name} = a.mx
            FROM rule_agg a
            WHERE a.signal_name = '{name}'
              AND u.user_uid = a.user_uid
              AND u.src_host = a.src_host
              AND u.bucket_start_sec = a.bucket_start_sec
            """
        )
    # first_contact is presence; new_edge_burst is the count -- the recon
    # signature is several first contacts from the same source in one hour,
    # which a boolean cannot say.
    wh.con.execute(
        """
        UPDATE detect_units u
        SET first_contact = 1,
            new_edge_burst = a.n
        FROM rule_agg a
        WHERE a.signal_name = 'first_contact'
          AND u.user_uid = a.user_uid
          AND u.src_host = a.src_host
          AND u.bucket_start_sec = a.bucket_start_sec
        """
    )
    # off_hours as a share, not a flag: one night login in a busy hour is
    # weaker than an hour that is entirely outside the account's band.
    wh.con.execute(
        """
        UPDATE detect_units u
        SET off_hours = a.n::DOUBLE / nullif(u.n_events, 0)
        FROM rule_agg a
        WHERE a.signal_name = 'off_hours'
          AND u.user_uid = a.user_uid
          AND u.src_host = a.src_host
          AND u.bucket_start_sec = a.bucket_start_sec
        """
    )


def naive_first_contact_units(
    wh: Warehouse, start_day: int, end_day: int
) -> list[dict]:
    """Alert on every first-contact edge, nothing else.

    The baseline a layered detector has to beat. If it does not, that is a
    finding, not something to hide by omitting the comparison.
    """
    rows = wh.con.execute(
        f"""
        SELECT e.src_user_uid AS user_uid,
               e.src_endpoint AS src_host,
               (e.time_sec // {BUCKET_SECONDS}) * {BUCKET_SECONDS} AS bucket_start_sec,
               (e.time_sec // {BUCKET_SECONDS}) * {BUCKET_SECONDS} + {BUCKET_SECONDS}
                   AS bucket_end_sec,
               count(*) AS n_first_contact,
               list(e.event_uid ORDER BY e.time_sec, e.event_uid) AS event_uids,
               min(e.time_sec) AS first_event_sec
        FROM events e
        JOIN edge_user_host eh
          ON eh.user_uid = e.src_user_uid
         AND eh.dst_host = e.dst_endpoint
        WHERE {AUTH}
          AND e.src_user_uid IS NOT NULL
          AND e.src_endpoint IS NOT NULL
          AND eh.first_seen_sec = e.time_sec
          AND e.day_index BETWEEN ? AND ?
        GROUP BY 1, 2, 3, 4
        ORDER BY n_first_contact DESC, bucket_start_sec, user_uid, src_host
        """,
        [start_day, end_day],
    ).fetchall()
    cols = [d[0] for d in wh.con.description]
    return [dict(zip(cols, r, strict=True)) for r in rows]
