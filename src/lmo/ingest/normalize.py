"""Raw LANL rows -> the unified normalised event model.

Parsing strategy
----------------
Two modes, both available from the CLI:

``defensive`` (default)
    Each file is read as one VARCHAR column per *line*, then split in SQL. This
    costs throughput but buys two things the project actually needs: exact
    1-based line numbers for every row, good or bad, and full control over what
    counts as malformed. Every rejected row lands in ``quarantine`` with a
    reason code and its verbatim text.

``fast``
    Native CSV parsing with a declared column layout. Materially faster on the
    full 12 GB release. The trade-off is that ``src_line_no`` becomes an ordinal
    over successfully-parsed rows rather than a true file line number, so it is
    marked approximate. ``src_line_hash`` stays authoritative in both modes.

The default is the slower one on purpose. Part 5 puts a "show me the raw record"
button in the analyst UI, and a provenance link that is usually right is worse
than none -- it invites trust it has not earned.

Nulls
-----
The dataset writes ``?`` for "not recorded". Left alone it becomes a host named
``?`` that appears to authenticate to everything, and a user named ``?`` who
appears everywhere -- phantom entities that would sit at the centre of the graph
built in Part 2. Every field is passed through ``nullif`` for both ``?`` and the
empty string.
"""

from __future__ import annotations

from pathlib import Path

from lmo.ingest.engine import DEFAULT_EPOCH, RunStats, Warehouse, timer
from lmo.schemas.normalized import (
    CATEGORY_OF_CLASS,
    CLASS_AUTHENTICATION,
    CLASS_DNS_ACTIVITY,
    CLASS_NAMES,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    SCHEMA_VERSION,
    ReasonCode,
)
from lmo.schemas.raw import COLLECTION_SECONDS, RawSchema, get_schema

# A byte that does not occur in the dataset, used so the CSV reader hands us
# whole lines instead of parsed fields.
_LINE_DELIM = "\\x01"


def _clean(expr: str) -> str:
    """NULL out the dataset's '?' marker and empty strings."""
    return f"nullif(nullif(trim({expr}), '?'), '')"


def _user_parts(expr: str) -> tuple[str, str, str]:
    """Split 'U147@DOM1' into (name, domain, canonical uid)."""
    uid = _clean(expr)
    name = f"split_part({uid}, '@', 1)"
    domain = f"nullif(split_part({uid}, '@', 2), '')"
    return name, domain, uid


def _time_columns(epoch_literal: str) -> dict[str, str]:
    """Derived time columns. ``time_sec`` is 1-based, hence the -1 everywhere.

    Integer division is written ``//``, not ``/``. In DuckDB ``/`` on integers
    produces a DOUBLE, and casting that to INTEGER *rounds* rather than
    truncates -- so ``/`` here would put every event after midday into the next
    day, and roughly half of all events into the wrong bucket. The weekend
    assertion in ``tests/test_ingest.py`` is what catches this; it is cheap and
    it has already earned its place once.
    """
    return {
        "event_time": (
            f"TIMESTAMP '{epoch_literal}' + INTERVAL (time_sec - 1) SECOND"
        ),
        "day_index": "((time_sec - 1) // 86400)::INTEGER",
        "hour_of_day": "(((time_sec - 1) % 86400) // 3600)::SMALLINT",
        "is_weekend": "(((time_sec - 1) // 86400) % 7) IN (5, 6)",
    }


# ---------------------------------------------------------------------------
# Stage 1 -- raw lines
# ---------------------------------------------------------------------------


def _stage_raw_lines(wh: Warehouse, path: Path, defensive: bool,
                     schema: RawSchema) -> None:
    """Materialise ``_raw`` (line_no, raw_line, parts) and ``_csv_rejects``.

    ``_csv_rejects`` is always created, empty in defensive mode. It exists
    because of a genuine hole in the fast path: DuckDB's ``ignore_errors``
    silently discards unparseable lines *before* the scan returns, so counting
    the scan gave a ``rows_in`` that already excluded them. Reconciliation then
    compared two numbers that had both lost the same rows and reported success
    -- the one failure mode the invariant exists to catch. ``store_rejects``
    hands those lines back, with their true file line numbers, so they can be
    quarantined and counted like any other malformed row.
    """
    wh.con.execute("DROP TABLE IF EXISTS _raw")
    wh.con.execute("DROP TABLE IF EXISTS _csv_rejects")
    wh.con.execute("DROP TABLE IF EXISTS _rj_errors")
    wh.con.execute("DROP TABLE IF EXISTS _rj_scans")
    if defensive:
        with wh.sequential_read():
            wh.con.execute(
                f"""
                CREATE TEMP TABLE _raw AS
                SELECT
                    row_number() OVER () AS line_no,
                    line                 AS raw_line,
                    str_split(line, ',') AS parts
                FROM read_csv(
                    ?,
                    delim = '{_LINE_DELIM}',
                    quote = '',
                    escape = '',
                    header = false,
                    columns = {{'line': 'VARCHAR'}},
                    ignore_errors = false
                )
                """,
                [str(path)],
            )
        wh.con.execute(
            """
            CREATE TEMP TABLE _csv_rejects (
                line_no BIGINT, raw_line VARCHAR,
                reason_code VARCHAR, reason_detail VARCHAR
            )
            """
        )
    else:
        cols = schema.duckdb_column_spec()
        concat = " || ',' || ".join(f"coalesce({c}::VARCHAR, '')"
                                    for c in schema.columns)
        parts = "[" + ", ".join(f"{c}::VARCHAR" for c in schema.columns) + "]"
        with wh.sequential_read():
            wh.con.execute(
                f"""
                CREATE TEMP TABLE _raw AS
                SELECT
                    row_number() OVER () AS line_no,
                    {concat}             AS raw_line,
                    {parts}              AS parts
                FROM read_csv(
                    ?,
                    delim = ',',
                    header = false,
                    columns = {cols},
                    all_varchar = true,
                    store_rejects = true,
                    rejects_table = '_rj_errors',
                    rejects_scan = '_rj_scans'
                )
                """,
                [str(path)],
            )
        # DuckDB reports one reject row per offending column, so a line with
        # five missing fields appears five times. Collapse to one row per line.
        wh.con.execute(
            f"""
            CREATE TEMP TABLE _csv_rejects AS
            SELECT
                line AS line_no,
                any_value(csv_line) AS raw_line,
                CASE
                    WHEN any_value(error_type) IN ('MISSING COLUMNS',
                                                   'TOO MANY COLUMNS')
                        THEN '{ReasonCode.WRONG_ARITY}'
                    ELSE '{ReasonCode.CSV_PARSE_ERROR}'
                END AS reason_code,
                'csv reader rejected the line: '
                    || string_agg(DISTINCT error_type, ', ') AS reason_detail
            FROM _rj_errors
            GROUP BY line
            """
        )


# ---------------------------------------------------------------------------
# Stage 2 -- validation
# ---------------------------------------------------------------------------


def _validate(wh: Warehouse, schema: RawSchema, key_positions: list[int]) -> None:
    """Split ``_raw`` into ``_good`` and ``_bad`` with explicit reason codes.

    ``key_positions`` are the 1-based field positions the ontology keys on. A
    row missing one of them cannot be attached to an entity, so it is rejected
    rather than allowed to create an anonymous orphan node.
    """
    key_check = " OR ".join(
        f"{_clean(f'parts[{p}]')} IS NULL" for p in key_positions
    ) or "false"

    wh.con.execute("DROP TABLE IF EXISTS _bad")
    wh.con.execute(
        f"""
        CREATE TEMP TABLE _bad AS
        SELECT
            line_no,
            raw_line,
            CASE
                WHEN len(parts) <> {schema.arity} THEN '{ReasonCode.WRONG_ARITY}'
                WHEN try_cast(trim(parts[1]) AS BIGINT) IS NULL
                    THEN '{ReasonCode.BAD_TIME}'
                WHEN try_cast(trim(parts[1]) AS BIGINT) < 1
                    OR try_cast(trim(parts[1]) AS BIGINT) > {COLLECTION_SECONDS * 2}
                    THEN '{ReasonCode.BAD_TIME}'
                ELSE '{ReasonCode.EMPTY_KEY_FIELD}'
            END AS reason_code,
            CASE
                WHEN len(parts) <> {schema.arity}
                    THEN 'expected {schema.arity} fields, got ' || len(parts)::VARCHAR
                WHEN try_cast(trim(parts[1]) AS BIGINT) IS NULL
                    THEN 'time is not an integer: ' || coalesce(parts[1], '<null>')
                WHEN try_cast(trim(parts[1]) AS BIGINT) < 1
                    OR try_cast(trim(parts[1]) AS BIGINT) > {COLLECTION_SECONDS * 2}
                    THEN 'time outside plausible collection window: ' || parts[1]
                ELSE 'a field the ontology keys on was empty'
            END AS reason_detail
        FROM _raw
        WHERE len(parts) <> {schema.arity}
           OR try_cast(trim(parts[1]) AS BIGINT) IS NULL
           OR try_cast(trim(parts[1]) AS BIGINT) < 1
           OR try_cast(trim(parts[1]) AS BIGINT) > {COLLECTION_SECONDS * 2}
           OR ({key_check})
        """
    )

    wh.con.execute("DROP TABLE IF EXISTS _good")
    wh.con.execute(
        """
        CREATE TEMP TABLE _good AS
        SELECT r.line_no, r.raw_line, r.parts
        FROM _raw r
        ANTI JOIN _bad b ON b.line_no = r.line_no
        """
    )


def _flush_quarantine(wh: Warehouse, run_id: str, schema: RawSchema,
                      filename: str) -> int:
    """Write both rejection sources to ``quarantine`` and return the total.

    ``_bad`` and ``_csv_rejects`` are kept as separate tables rather than
    unioned earlier, because their line numbers mean different things. In fast
    mode ``_raw.line_no`` is an ordinal over rows the CSV reader accepted, while
    ``_csv_rejects.line_no`` is a true file line. Merging them before the
    anti-join in :func:`_validate` would let a reject at file line 5002 knock out
    the good row that happened to be 5002nd -- dropping a valid row to punish a
    different one.
    """
    total = 0
    for table in ("_bad", "_csv_rejects"):
        wh.con.execute(
            f"""
            INSERT INTO quarantine
            SELECT ?, ?, ?, line_no, raw_line, reason_code, reason_detail, now()
            FROM {table}
            """,
            [run_id, schema.name, filename],
        )
        total += wh.con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    return total


# ---------------------------------------------------------------------------
# Stage 3 -- projection into the event model
# ---------------------------------------------------------------------------

_LINEAGE = """
    '{dataset}'          AS src_dataset,
    '{filename}'         AS src_file,
    line_no              AS src_line_no,
    md5(raw_line)        AS src_line_hash,
    now()                AS ingested_at,
    '{run_id}'           AS run_id,
    '{schema_version}'   AS schema_version
"""


def _projection(dataset: str, filename: str, run_id: str,
                epoch_literal: str) -> str:
    """Build the full SELECT that maps ``_good`` onto EVENT_COLUMNS order."""
    t = _time_columns(epoch_literal)
    lineage = _LINEAGE.format(
        dataset=dataset, filename=filename, run_id=run_id,
        schema_version=SCHEMA_VERSION,
    )
    uid = "md5('{d}' || '|' || '{f}' || '|' || line_no::VARCHAR || '|' || raw_line)".format(
        d=dataset, f=filename
    )
    head = f"""
        {uid} AS event_uid,
        try_cast(trim(parts[1]) AS BIGINT) AS time_sec,
    """
    # event_time and friends are expressed against the already-projected
    # time_sec, so the projection runs inside a subquery.
    tail_time = f"""
        {t['event_time']}   AS event_time,
        {t['day_index']}    AS day_index,
        {t['hour_of_day']}  AS hour_of_day,
        {t['is_weekend']}   AS is_weekend,
    """

    if dataset == "auth":
        src_name, src_dom, src_uid = _user_parts("parts[2]")
        dst_name, dst_dom, dst_uid = _user_parts("parts[3]")
        body = f"""
        {CATEGORY_OF_CLASS[CLASS_AUTHENTICATION]}::SMALLINT AS category_uid,
        {CLASS_AUTHENTICATION} AS class_uid,
        '{CLASS_NAMES[CLASS_AUTHENTICATION]}' AS class_name,
        CASE {_clean('parts[8]')}
            WHEN 'LogOn' THEN 1 WHEN 'LogOff' THEN 2
            WHEN 'TGT' THEN 3 WHEN 'TGS' THEN 4 ELSE 99
        END::SMALLINT AS activity_id,
        {_clean('parts[8]')} AS activity_name,
        {src_name} AS src_user_name,
        {src_dom}  AS src_user_domain,
        {src_uid}  AS src_user_uid,
        {dst_name} AS dst_user_name,
        {dst_dom}  AS dst_user_domain,
        {dst_uid}  AS dst_user_uid,
        ({src_name} LIKE '%$') AS is_machine_account,
        (upper({src_name}) = 'ANONYMOUS LOGON') AS is_anonymous,
        {_clean('parts[4]')} AS src_endpoint,
        {_clean('parts[5]')} AS dst_endpoint,
        ({_clean('parts[4]')} = {_clean('parts[5]')}) AS is_self_auth,
        NULL AS src_port, NULL AS dst_port, NULL AS protocol_num,
        {_clean('parts[6]')} AS auth_protocol,
        {_clean('parts[7]')} AS logon_type,
        CASE {_clean('parts[9]')}
            WHEN 'Success' THEN 1 WHEN 'Fail' THEN 2 ELSE 0
        END::SMALLINT AS status_id,
        {_clean('parts[9]')} AS status,
        NULL AS process_name, NULL AS process_action,
        NULL::BIGINT AS duration_sec, NULL::BIGINT AS packet_count,
        NULL::BIGINT AS byte_count, NULL AS resolved_endpoint,
        """
    elif dataset == "proc":
        name, dom, uid_ = _user_parts("parts[2]")
        body = f"""
        {CATEGORY_OF_CLASS[CLASS_PROCESS_ACTIVITY]}::SMALLINT AS category_uid,
        {CLASS_PROCESS_ACTIVITY} AS class_uid,
        '{CLASS_NAMES[CLASS_PROCESS_ACTIVITY]}' AS class_name,
        CASE {_clean('parts[5]')} WHEN 'Start' THEN 1 WHEN 'End' THEN 2
             ELSE 99 END::SMALLINT AS activity_id,
        {_clean('parts[5]')} AS activity_name,
        {name} AS src_user_name, {dom} AS src_user_domain, {uid_} AS src_user_uid,
        NULL AS dst_user_name, NULL AS dst_user_domain, NULL AS dst_user_uid,
        ({name} LIKE '%$') AS is_machine_account,
        false AS is_anonymous,
        {_clean('parts[3]')} AS src_endpoint,
        {_clean('parts[3]')} AS dst_endpoint,
        true AS is_self_auth,
        NULL AS src_port, NULL AS dst_port, NULL AS protocol_num,
        NULL AS auth_protocol, NULL AS logon_type,
        0::SMALLINT AS status_id, NULL AS status,
        {_clean('parts[4]')} AS process_name,
        {_clean('parts[5]')} AS process_action,
        NULL::BIGINT AS duration_sec, NULL::BIGINT AS packet_count,
        NULL::BIGINT AS byte_count, NULL AS resolved_endpoint,
        """
    elif dataset == "flows":
        body = f"""
        {CATEGORY_OF_CLASS[CLASS_NETWORK_ACTIVITY]}::SMALLINT AS category_uid,
        {CLASS_NETWORK_ACTIVITY} AS class_uid,
        '{CLASS_NAMES[CLASS_NETWORK_ACTIVITY]}' AS class_name,
        6::SMALLINT AS activity_id,
        'Traffic' AS activity_name,
        NULL AS src_user_name, NULL AS src_user_domain, NULL AS src_user_uid,
        NULL AS dst_user_name, NULL AS dst_user_domain, NULL AS dst_user_uid,
        false AS is_machine_account, false AS is_anonymous,
        {_clean('parts[3]')} AS src_endpoint,
        {_clean('parts[5]')} AS dst_endpoint,
        ({_clean('parts[3]')} = {_clean('parts[5]')}) AS is_self_auth,
        {_clean('parts[4]')} AS src_port,
        {_clean('parts[6]')} AS dst_port,
        {_clean('parts[7]')} AS protocol_num,
        NULL AS auth_protocol, NULL AS logon_type,
        0::SMALLINT AS status_id, NULL AS status,
        NULL AS process_name, NULL AS process_action,
        try_cast(trim(parts[2]) AS BIGINT) AS duration_sec,
        try_cast(trim(parts[8]) AS BIGINT) AS packet_count,
        try_cast(trim(parts[9]) AS BIGINT) AS byte_count,
        NULL AS resolved_endpoint,
        """
    elif dataset == "dns":
        body = f"""
        {CATEGORY_OF_CLASS[CLASS_DNS_ACTIVITY]}::SMALLINT AS category_uid,
        {CLASS_DNS_ACTIVITY} AS class_uid,
        '{CLASS_NAMES[CLASS_DNS_ACTIVITY]}' AS class_name,
        1::SMALLINT AS activity_id,
        'Query' AS activity_name,
        NULL AS src_user_name, NULL AS src_user_domain, NULL AS src_user_uid,
        NULL AS dst_user_name, NULL AS dst_user_domain, NULL AS dst_user_uid,
        false AS is_machine_account, false AS is_anonymous,
        {_clean('parts[2]')} AS src_endpoint,
        {_clean('parts[3]')} AS dst_endpoint,
        false AS is_self_auth,
        NULL AS src_port, NULL AS dst_port, NULL AS protocol_num,
        NULL AS auth_protocol, NULL AS logon_type,
        0::SMALLINT AS status_id, NULL AS status,
        NULL AS process_name, NULL AS process_action,
        NULL::BIGINT AS duration_sec, NULL::BIGINT AS packet_count,
        NULL::BIGINT AS byte_count,
        {_clean('parts[3]')} AS resolved_endpoint,
        """
    else:
        raise ValueError(f"no projection defined for dataset {dataset!r}")

    return f"""
        SELECT
            event_uid, time_sec,
            {tail_time}
            category_uid, class_uid, class_name, activity_id, activity_name,
            src_user_name, src_user_domain, src_user_uid,
            dst_user_name, dst_user_domain, dst_user_uid,
            is_machine_account, is_anonymous,
            src_endpoint, dst_endpoint, is_self_auth,
            src_port, dst_port, protocol_num,
            auth_protocol, logon_type, status_id, status,
            process_name, process_action,
            duration_sec, packet_count, byte_count, resolved_endpoint,
            src_dataset, src_file, src_line_no, src_line_hash,
            ingested_at, run_id, schema_version
        FROM (
            SELECT
                {head}
                {body}
                {lineage}
            FROM _good
        )
    """


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _count_rows_in(wh: Warehouse) -> int:
    """Lines the file actually contained: parsed plus rejected by the reader.

    Counting only ``_raw`` would exclude what the CSV reader threw away, which
    is what made the fast path's reconciliation vacuous.
    """
    return wh.con.execute(
        "SELECT (SELECT count(*) FROM _raw) + (SELECT count(*) FROM _csv_rejects)"
    ).fetchone()[0]


def _insert_projected_events(
    wh: Warehouse,
    proj: str,
    run_id: str,
    dataset: str,
    n_good: int,
    max_day: int | None,
) -> tuple[int, int, int]:
    """Insert projected rows, skipping the day window and already-seen hashes.

    Identity for "already seen" is ``(src_dataset, src_file, src_line_hash)``,
    not ``event_uid``. The uid embeds ``src_line_no``, which is approximate
    under ``--fast-parse``; the hash is the line.
    """
    wh.con.execute(f"CREATE OR REPLACE TEMP TABLE _projected AS {proj}")
    if max_day is None:
        n_window = n_good
        beyond = 0
        day_sql = "TRUE"
        bind: list = []
    else:
        n_window = wh.con.execute(
            "SELECT count(*) FROM _projected WHERE day_index <= ?",
            [max_day],
        ).fetchone()[0]
        beyond = n_good - n_window
        day_sql = "p.day_index <= ?"
        bind = [max_day]
    before = wh.con.execute(
        "SELECT count(*) FROM events WHERE run_id = ? AND src_dataset = ?",
        [run_id, dataset],
    ).fetchone()[0]
    sql = f"""
        INSERT INTO events
        SELECT * FROM _projected p
        WHERE {day_sql}
          AND NOT EXISTS (
            SELECT 1 FROM events e
            WHERE e.src_dataset = p.src_dataset
              AND e.src_file = p.src_file
              AND e.src_line_hash = p.src_line_hash
          )
    """
    if bind:
        wh.con.execute(sql, bind)
    else:
        wh.con.execute(sql)
    after = wh.con.execute(
        "SELECT count(*) FROM events WHERE run_id = ? AND src_dataset = ?",
        [run_id, dataset],
    ).fetchone()[0]
    inserted = after - before
    duplicate = n_window - inserted
    wh.con.execute("DROP TABLE IF EXISTS _projected")
    return inserted, beyond, duplicate
    """Lines the file actually contained: parsed plus rejected by the reader.

    Counting only ``_raw`` would exclude what the CSV reader threw away, which
    is what made the fast path's reconciliation vacuous.
    """
    return wh.con.execute(
        "SELECT (SELECT count(*) FROM _raw) + (SELECT count(*) FROM _csv_rejects)"
    ).fetchone()[0]


#: Field positions (1-based) each dataset's ontology keys on.
KEY_POSITIONS: dict[str, list[int]] = {
    "auth": [2, 4, 5],      # source user, source host, destination host
    "proc": [2, 3],         # user, host
    "flows": [3, 5],        # source host, destination host
    "dns": [2, 3],          # source host, resolved host
    "redteam": [2, 3, 4],
}


def ingest_dataset(
    wh: Warehouse,
    dataset: str,
    path: Path,
    run_id: str,
    *,
    defensive: bool = True,
    epoch=DEFAULT_EPOCH,
    max_day: int | None = None,
) -> RunStats:
    """Ingest one raw file into ``events``, quarantining what will not parse."""
    schema = get_schema(dataset)
    stats = RunStats(dataset=dataset)
    t0 = timer()

    _stage_raw_lines(wh, path, defensive, schema)
    stats.rows_in = _count_rows_in(wh)

    _validate(wh, schema, KEY_POSITIONS[dataset])
    stats.rows_quarantined = _flush_quarantine(wh, run_id, schema, path.name)

    epoch_literal = epoch.strftime("%Y-%m-%d %H:%M:%S")
    proj = _projection(dataset, path.name, run_id, epoch_literal)
    n_good = wh.con.execute("SELECT count(*) FROM _good").fetchone()[0]
    inserted, beyond, duplicate = _insert_projected_events(
        wh, proj, run_id, dataset, n_good, max_day,
    )
    stats.rows_out = inserted
    stats.rows_beyond_window = beyond
    stats.rows_duplicate = duplicate

    # Values outside the documented vocabulary are warned about, not rejected --
    # an unknown auth type is a real event we do not want to lose, but a sudden
    # burst of them means the source format changed under us.
    unknown = wh.con.execute(
        """
        SELECT count(*) FROM events
        WHERE run_id = ? AND src_dataset = 'auth'
          AND auth_protocol IS NOT NULL
          AND auth_protocol NOT IN (
              'Negotiate','Kerberos','NTLM',
              'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0','CredSSP'
          )
        """,
        [run_id],
    ).fetchone()[0]
    if unknown:
        stats.warnings[ReasonCode.UNKNOWN_ENUM] = int(unknown)

    stats.seconds = timer() - t0
    return stats


def ingest_labels(wh: Warehouse, path: Path, run_id: str,
                  *, defensive: bool = True,
                  max_day: int | None = None) -> RunStats:
    """Load ``redteam.txt.gz`` into ``redteam_labels``.

    Labels are kept in their own table, never joined into ``events`` as a
    column. Anything that can read the label from a feature table will
    eventually leak it into a model, and the resulting metrics would be
    fiction.

    ``max_day`` uses the same ``day_index`` formula as events
    (``(time_sec - 1) // 86400``) so a sliced ingest cannot leave labels
    that have no matching rows and then report a false ``label_join_rate``.
    """
    schema = get_schema("redteam")
    stats = RunStats(dataset="redteam")
    t0 = timer()

    _stage_raw_lines(wh, path, defensive, schema)
    stats.rows_in = _count_rows_in(wh)
    _validate(wh, schema, KEY_POSITIONS["redteam"])
    stats.rows_quarantined = _flush_quarantine(wh, run_id, schema, path.name)

    n_good = wh.con.execute("SELECT count(*) FROM _good").fetchone()[0]
    day_sql = "((try_cast(trim(parts[1]) AS BIGINT) - 1) // 86400)"
    if max_day is None:
        n_window = n_good
        beyond = 0
        window_sql = "TRUE"
        params: list = []
    else:
        n_window = wh.con.execute(
            f"SELECT count(*) FROM _good WHERE {day_sql} <= ?",
            [max_day],
        ).fetchone()[0]
        beyond = n_good - n_window
        window_sql = f"{day_sql} <= ?"
        params = [max_day]
    before = wh.con.execute("SELECT count(*) FROM redteam_labels").fetchone()[0]
    sql = f"""
        INSERT INTO redteam_labels
        SELECT
            try_cast(trim(parts[1]) AS BIGINT),
            {_clean('parts[2]')},
            {_clean('parts[3]')},
            {_clean('parts[4]')},
            md5('redteam|' || raw_line)
        FROM _good
        WHERE {window_sql}
          AND NOT EXISTS (
            SELECT 1 FROM redteam_labels l
            WHERE l.label_uid = md5('redteam|' || _good.raw_line)
          )
    """
    if params:
        wh.con.execute(sql, params)
    else:
        wh.con.execute(sql)
    after = wh.con.execute("SELECT count(*) FROM redteam_labels").fetchone()[0]
    stats.rows_out = after - before
    stats.rows_beyond_window = beyond
    stats.rows_duplicate = n_window - stats.rows_out
    stats.seconds = timer() - t0
    return stats
