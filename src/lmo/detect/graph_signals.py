"""Layer 2 — structural signals against the ontology, per alert unit.

These are the questions the graph was built to answer: is this hour a fan-out
against the account's own past, is the source host new for this account, did
the hop extend a walk that already looked interesting. They are computed per
(account, source host, hour) rather than per event, which is the grain an
analyst actually triages.
"""

from __future__ import annotations

from lmo.detect.schema import CHAIN_BURST_MIN
from lmo.ingest.engine import Warehouse


def apply_graph_signals(wh: Warehouse) -> None:
    _fan_out(wh)
    _hub_avoidance(wh)
    _new_source_host(wh)
    _chain_extension(wh)


def _fan_out(wh: Warehouse) -> None:
    """Distinct destinations this hour / the account's trailing per-hour 95th.

    Admins who routinely sweep 15 hosts have a high denominator and will not
    light up; an ordinary account doing the same thing will. That is the
    whole reason ``role_hint='broad'`` exists on ``entity_user``.
    """
    wh.con.execute(
        """
        UPDATE detect_units u
        SET fan_out = CASE
            WHEN t.p95_dsts IS NULL OR t.p95_dsts = 0 THEN 0
            ELSE u.n_distinct_dst::DOUBLE / t.p95_dsts
        END
        FROM trailing_fanout_p95 t
        WHERE t.day_index = u.day_index
          AND t.user_uid = u.user_uid
        """
    )


def _hub_avoidance(wh: Warehouse) -> None:
    """Share of this hour's destinations that are endpoints, not hubs.

    Ordinary traffic is hub-heavy: a handful of servers take a large share of
    destinations. A walk across workstations is not. ``role_hint`` is an
    estate property computed over the whole graph on purpose -- a domain
    controller does not stop being one at 3pm -- and is not a rarity score.
    """
    wh.con.execute(
        """
        UPDATE detect_units u
        SET hub_avoidance = s.share
        FROM (
            SELECT b.user_uid, b.src_host, b.bucket_start_sec,
                   count(*) FILTER (h.role_hint = 'endpoint')::DOUBLE
                       / nullif(count(*), 0) AS share
            FROM detect_bucket_dsts b
            JOIN entity_host h ON h.host = b.dst_host
            GROUP BY 1, 2, 3
        ) s
        WHERE u.user_uid = s.user_uid
          AND u.src_host = s.src_host
          AND u.bucket_start_sec = s.bucket_start_sec
        """
    )


def _new_source_host(wh: Warehouse) -> None:
    """This account has never authenticated *from* this machine before.

    Uses ``min(time_sec)`` for the (account, source) pair, the same causal
    construction as ``first_seen_sec`` on edges. The extra EXISTS stops the
    account's first-ever hour from firing -- everyone is new on day 0, and
    that would drown the ranking. The stolen admin on the victim's beachhead
    has plenty of history elsewhere, so it still fires.
    """
    wh.con.execute(
        """
        UPDATE detect_units u
        SET new_source_host = CASE
            WHEN f.first_from_sec >= u.bucket_start_sec
             AND a.first_any_sec < u.bucket_start_sec
            THEN 1 ELSE 0
        END
        FROM trailing_src_first f, trailing_user_first a
        WHERE f.user_uid = u.user_uid
          AND f.src_host = u.src_host
          AND a.user_uid = u.user_uid
        """
    )


def _chain_extension(wh: Warehouse) -> None:
    """Did a hop this hour leave a host that already looked interesting?

    This is the signal that ties stages together. It is also the one that is
    easiest to make circular: scoring a bucket, then treating "scored" as
    the seed for the next bucket, fits the campaign you just scored.

    Seeds are therefore defined on *raw layer-1/2 firings*, not on the
    weighted score: an identity switch, a first-contact burst, or a
    fail-then-success. A host becomes active at the *end* of a seed bucket
    (so the seed itself does not self-fire) if it was the source of that
    bucket or a successful hop destination inside it. A later bucket whose
    source is an active host is a chain extension.

    ``paths_between`` answers the pairwise version of the same question for
    an analyst; doing that search per unit is the investigation tool, not
    the detector. The activation walk is that search, materialised.
    """
    wh.con.execute(
        f"""
        CREATE OR REPLACE TABLE detect_activated AS
        WITH seeds AS (
            SELECT user_uid, src_host, bucket_start_sec, bucket_end_sec
            FROM detect_units
            WHERE identity_switch > 0
               OR new_edge_burst >= {CHAIN_BURST_MIN}
               OR fail_then_success > 0
        ),
        from_src AS (
            SELECT src_host AS host, bucket_end_sec AS active_from_sec
            FROM seeds
        ),
        from_dst AS (
            SELECT e.dst_endpoint AS host, s.bucket_end_sec AS active_from_sec
            FROM seeds s
            JOIN detect_auth e
              ON e.src_user_uid = s.user_uid
             AND e.src_endpoint = s.src_host
             AND e.time_sec >= s.bucket_start_sec
             AND e.time_sec < s.bucket_end_sec
             AND e.status_id = 1
             AND e.activity_name = 'LogOn'
             AND e.src_endpoint <> e.dst_endpoint
        )
        SELECT host, min(active_from_sec) AS active_from_sec
        FROM (SELECT * FROM from_src UNION ALL SELECT * FROM from_dst)
        GROUP BY 1
        """
    )
    wh.con.execute(
        """
        CREATE OR REPLACE TABLE detect_chain AS
        SELECT u.user_uid, u.src_host, u.bucket_start_sec,
               max(CASE WHEN a.host IS NOT NULL THEN 1.0 ELSE 0.0 END)
                   AS chain_extension
        FROM detect_units u
        LEFT JOIN detect_activated a
          ON a.host = u.src_host
         AND a.active_from_sec <= u.bucket_start_sec
        GROUP BY 1, 2, 3
        """
    )
    wh.con.execute(
        """
        UPDATE detect_units u
        SET chain_extension = c.chain_extension
        FROM detect_chain c
        WHERE u.user_uid = c.user_uid
          AND u.src_host = c.src_host
          AND u.bucket_start_sec = c.bucket_start_sec
        """
    )
