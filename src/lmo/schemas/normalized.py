"""The normalised event model that every raw source is mapped into.

Design notes worth defending in an interview
--------------------------------------------
1. **One table, not four.** Analysts do not think in source files; they think
   "what happened around this host between 02:00 and 04:00". A single event
   table with a discriminating ``class_uid`` makes that a single scan instead of
   a four-way union written by hand every time.

2. **OCSF-shaped, not OCSF-certified.** Field names and the class/activity
   identifiers follow the Open Cybersecurity Schema Framework so the vocabulary
   is one a SOC already speaks, and so a second source (Sysmon, CloudTrail)
   could be added without redesigning anything. We deliberately do not claim
   full OCSF conformance -- the dataset is anonymised and lacks most required
   fields. Claiming conformance we do not have would be worse than not claiming
   it.

3. **Lineage is a column, not a feature request.** Every normalised row carries
   the dataset, file, line number and a hash of the exact raw line it came from.
   Part 5 turns that into a "show me the raw record" button, but the cost has to
   be paid here, at write time -- you cannot reconstruct provenance later.

4. **Entities are resolved at ingest.** ``src_user_name``/``src_user_domain``
   are split out of ``U147@DOM1`` once, here, rather than by every downstream
   query. The ontology in Part 2 keys off these columns.
"""

from __future__ import annotations

from dataclasses import dataclass

# --------------------------------------------------------------------------
# OCSF class / activity identifiers
# --------------------------------------------------------------------------

CLASS_AUTHENTICATION = 3002
CLASS_PROCESS_ACTIVITY = 1007
CLASS_NETWORK_ACTIVITY = 4001
CLASS_DNS_ACTIVITY = 4003

CLASS_NAMES: dict[int, str] = {
    CLASS_AUTHENTICATION: "Authentication",
    CLASS_PROCESS_ACTIVITY: "Process Activity",
    CLASS_NETWORK_ACTIVITY: "Network Activity",
    CLASS_DNS_ACTIVITY: "DNS Activity",
}

CATEGORY_OF_CLASS: dict[int, int] = {
    CLASS_AUTHENTICATION: 3,  # Identity & Access Management
    CLASS_PROCESS_ACTIVITY: 1,  # System Activity
    CLASS_NETWORK_ACTIVITY: 4,  # Network Activity
    CLASS_DNS_ACTIVITY: 4,
}

# Activity ids within the authentication class.
ACTIVITY_LOGON = 1
ACTIVITY_LOGOFF = 2
ACTIVITY_AUTH_TICKET = 3
ACTIVITY_SERVICE_TICKET = 4
ACTIVITY_OTHER = 99

#: Maps the LANL ``auth_orientation`` value onto an OCSF activity id.
ORIENTATION_TO_ACTIVITY: dict[str, int] = {
    "LogOn": ACTIVITY_LOGON,
    "LogOff": ACTIVITY_LOGOFF,
    "TGT": ACTIVITY_AUTH_TICKET,
    "TGS": ACTIVITY_SERVICE_TICKET,
    "AuthMap": ACTIVITY_OTHER,
    "ScreenLock": ACTIVITY_OTHER,
    "ScreenUnlock": ACTIVITY_OTHER,
}

# Status ids follow OCSF: 1 = Success, 2 = Failure, 0 = Unknown.
STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

OUTCOME_TO_STATUS: dict[str, int] = {"Success": STATUS_SUCCESS, "Fail": STATUS_FAILURE}


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    doc: str


#: The unified event table. Order matters -- it is the physical column order.
EVENT_COLUMNS: tuple[Column, ...] = (
    # -- identity of the event ------------------------------------------------
    Column("event_uid", "VARCHAR", "Deterministic id: hash of lineage + payload."),
    Column("time_sec", "BIGINT", "Raw dataset clock, seconds from collection start."),
    Column("event_time", "TIMESTAMP", "time_sec anchored to the configured epoch."),
    Column("day_index", "INTEGER", "0-based day, the natural partition key."),
    Column("hour_of_day", "SMALLINT", "0-23, precomputed for off-hours features."),
    Column("is_weekend", "BOOLEAN", "Precomputed; the baseline model needs it."),
    # -- classification -------------------------------------------------------
    Column("category_uid", "SMALLINT", "OCSF category."),
    Column("class_uid", "INTEGER", "OCSF class, e.g. 3002 Authentication."),
    Column("class_name", "VARCHAR", "Human-readable class name."),
    Column("activity_id", "SMALLINT", "OCSF activity within the class."),
    Column("activity_name", "VARCHAR", "Original source verb, e.g. 'LogOn'."),
    # -- actors ---------------------------------------------------------------
    Column("src_user_name", "VARCHAR", "Account portion of the source principal."),
    Column("src_user_domain", "VARCHAR", "Domain portion, NULL for local accounts."),
    Column("src_user_uid", "VARCHAR", "Canonical 'user@domain', NULL if absent."),
    Column("dst_user_name", "VARCHAR", "Account the source authenticated as."),
    Column("dst_user_domain", "VARCHAR", "Domain of the destination principal."),
    Column("dst_user_uid", "VARCHAR", "Canonical 'user@domain'."),
    Column("is_machine_account", "BOOLEAN", "Source principal ends in '$'."),
    Column("is_anonymous", "BOOLEAN", "ANONYMOUS LOGON, kept but flagged."),
    # -- endpoints ------------------------------------------------------------
    Column("src_endpoint", "VARCHAR", "Source host."),
    Column("dst_endpoint", "VARCHAR", "Destination host."),
    Column("is_self_auth", "BOOLEAN", "src_endpoint = dst_endpoint (local logon)."),
    Column("src_port", "VARCHAR", "Anonymised port label, flows only."),
    Column("dst_port", "VARCHAR", "Anonymised port label, flows only."),
    Column("protocol_num", "VARCHAR", "IP protocol number, flows only."),
    # -- authentication detail ------------------------------------------------
    Column("auth_protocol", "VARCHAR", "Kerberos / NTLM / Negotiate / ..."),
    Column("logon_type", "VARCHAR", "Network / Interactive / Service / ..."),
    Column("status_id", "SMALLINT", "0 unknown, 1 success, 2 failure."),
    Column("status", "VARCHAR", "Original outcome string."),
    # -- process / traffic detail --------------------------------------------
    Column("process_name", "VARCHAR", "Anonymised process id, proc only."),
    Column("process_action", "VARCHAR", "Start / End, proc only."),
    Column("duration_sec", "BIGINT", "Flow duration."),
    Column("packet_count", "BIGINT", "Flow packets."),
    Column("byte_count", "BIGINT", "Flow bytes."),
    Column("resolved_endpoint", "VARCHAR", "DNS answer, dns only."),
    # -- lineage --------------------------------------------------------------
    Column("src_dataset", "VARCHAR", "Which raw dataset this came from."),
    Column("src_file", "VARCHAR", "File name it was read from."),
    Column("src_line_no", "BIGINT", "1-based line number within that file."),
    Column("src_line_hash", "VARCHAR", "Hash of the exact raw line."),
    Column("ingested_at", "TIMESTAMP", "Wall-clock time of the ingest run."),
    Column("run_id", "VARCHAR", "Id of the pipeline run that produced this row."),
    Column("schema_version", "VARCHAR", "Version of this normalised model."),
)

SCHEMA_VERSION = "1.0.0"

#: Rows that could not be normalised land here instead of being dropped.
QUARANTINE_COLUMNS: tuple[Column, ...] = (
    Column("run_id", "VARCHAR", "Pipeline run that rejected the row."),
    Column("src_dataset", "VARCHAR", "Dataset the row came from."),
    Column("src_file", "VARCHAR", "File the row came from."),
    Column("src_line_no", "BIGINT", "1-based line number."),
    Column("raw_line", "VARCHAR", "The offending line, verbatim."),
    Column("reason_code", "VARCHAR", "Machine-readable rejection reason."),
    Column("reason_detail", "VARCHAR", "Human-readable detail."),
    Column("quarantined_at", "TIMESTAMP", "When it was rejected."),
)


class ReasonCode:
    """Why a raw row was quarantined.

    Kept as codes rather than free text so Part 4 can chart the mix, and so a
    spike in one reason is a visible operational signal rather than a wall of
    log lines.
    """

    WRONG_ARITY = "WRONG_ARITY"
    """Row had a different number of comma-separated fields than the schema."""

    BAD_TIME = "BAD_TIME"
    """``time`` was missing, non-numeric, negative, or beyond the window."""

    EMPTY_KEY_FIELD = "EMPTY_KEY_FIELD"
    """A field the ontology keys on (host, user) was empty after trimming."""

    UNPARSEABLE_NUMBER = "UNPARSEABLE_NUMBER"
    """A numeric column could not be parsed."""

    CSV_PARSE_ERROR = "CSV_PARSE_ERROR"
    """The CSV reader itself rejected the line, in ``--fast-parse`` mode.

    Recovered from DuckDB's reject tables rather than left to vanish. Before
    this existed, the fast path handed back only the rows it could parse, so
    ``rows_in`` was already the post-drop count and reconciliation compared two
    numbers that both excluded the losses -- the invariant reported success
    precisely when it should have failed.
    """

    UNKNOWN_ENUM = "UNKNOWN_ENUM"
    """A value outside the documented vocabulary. Warned, not rejected."""


def create_table_sql(table: str, columns: tuple[Column, ...]) -> str:
    body = ",\n    ".join(f"{c.name} {c.type}" for c in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} (\n    {body}\n)"


def column_names(columns: tuple[Column, ...]) -> tuple[str, ...]:
    return tuple(c.name for c in columns)
