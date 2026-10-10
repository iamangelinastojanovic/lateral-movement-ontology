"""Raw source schemas for the LANL 2015 cyber-security events dataset.

Reference: A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events",
Los Alamos National Laboratory (2015). https://csr.lanl.gov/data/cyber1/

All five files are headerless, comma-separated and gzipped. ``time`` is an
integer number of seconds since the start of collection (the first event is at
t=1); the collection spans 58 days, so t runs to roughly 5,011,199.

IMPORTANT -- verifying the column order
---------------------------------------
These layouts are transcribed from the dataset documentation. Before running the
pipeline over the real files, verify them once against the actual data::

    zcat auth.txt.gz | head -3

and compare with ``AUTH.example``. If a column is off, this module is the single
place that needs changing -- nothing downstream hardcodes positions. The CLI
command ``lmo verify-schema`` does this check for you.

A ``?`` in any field means "not recorded" and is normalised to NULL, not to the
literal string. Failing to do this is a classic source of phantom entities: a
host literally named "?" that appears to talk to everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RawSchema:
    """Column layout of one headerless LANL source file."""

    name: str
    """Logical dataset name, e.g. ``auth``."""

    filename: str
    """Expected file name in the raw data directory."""

    columns: tuple[str, ...]
    """Column names in file order."""

    types: tuple[str, ...]
    """DuckDB types, positionally aligned with :attr:`columns`."""

    example: str
    """A representative line, used by ``lmo verify-schema`` and by tests."""

    nullable_marker: str = "?"
    """Token the dataset uses for "not recorded"."""

    description: str = ""

    def __post_init__(self) -> None:
        if len(self.columns) != len(self.types):
            raise ValueError(
                f"{self.name}: {len(self.columns)} columns but {len(self.types)} types"
            )

    @property
    def arity(self) -> int:
        return len(self.columns)

    def duckdb_column_spec(self) -> str:
        """Render the ``columns={...}`` argument for ``read_csv``.

        We always declare every column as its declared type and let malformed
        rows be rejected explicitly rather than silently coerced.
        """
        pairs = ", ".join(
            f"'{c}': '{t}'" for c, t in zip(self.columns, self.types, strict=True)
        )
        return "{" + pairs + "}"


AUTH = RawSchema(
    name="auth",
    filename="auth.txt.gz",
    columns=(
        "time",
        "src_user",
        "dst_user",
        "src_computer",
        "dst_computer",
        "auth_type",
        "logon_type",
        "auth_orientation",
        "outcome",
    ),
    types=(
        "BIGINT",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
    ),
    example="1,C625@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success",
    description=(
        "Authentication events from individual Windows-based desktops and "
        "servers. The spine of the project: every lateral-movement signal is "
        "derived from the src_user/src_computer/dst_computer triple."
    ),
)

PROC = RawSchema(
    name="proc",
    filename="proc.txt.gz",
    columns=("time", "user", "computer", "process_name", "action"),
    types=("BIGINT", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR"),
    example="1,C553@DOM1,C553,P16,Start",
    description=(
        "Process start/stop events. Process names are anonymised (P1, P2, ...), "
        "so these are useful as corroborating context on a host during an "
        "incident window rather than as a detection source of their own."
    ),
)

FLOWS = RawSchema(
    name="flows",
    filename="flows.txt.gz",
    columns=(
        "time",
        "duration",
        "src_computer",
        "src_port",
        "dst_computer",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
    ),
    types=(
        "BIGINT",
        "BIGINT",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "VARCHAR",
        "BIGINT",
        "BIGINT",
    ),
    example="1,9,C3090,N10039,C3420,N22,6,10,5323",
    description=(
        "Network flow records. Ports are anonymised except well-known ones "
        "(N22, N80, N445 keep their meaning), which is why ports stay VARCHAR."
    ),
)

DNS = RawSchema(
    name="dns",
    filename="dns.txt.gz",
    columns=("time", "src_computer", "resolved_computer"),
    types=("BIGINT", "VARCHAR", "VARCHAR"),
    example="1,C4653,C5030",
    description="DNS lookups, one row per resolution.",
)

REDTEAM = RawSchema(
    name="redteam",
    filename="redteam.txt.gz",
    columns=("time", "user", "src_computer", "dst_computer"),
    types=("BIGINT", "VARCHAR", "VARCHAR", "VARCHAR"),
    example="150885,U620@DOM1,C17693,C1003",
    description=(
        "Ground truth. Each row is a known red-team authentication, and joins "
        "onto auth on (time, user, src_computer, dst_computer). This is the "
        "label set the whole evaluation in Part 3 rests on -- it is a subset of "
        "auth, never a separate event stream."
    ),
)

ALL_SCHEMAS: dict[str, RawSchema] = {
    s.name: s for s in (AUTH, PROC, FLOWS, DNS, REDTEAM)
}

#: Datasets that carry security events. ``redteam`` is excluded because it is
#: labels, not events, and must never leak into the feature pipeline.
EVENT_SCHEMAS: tuple[RawSchema, ...] = (AUTH, PROC, FLOWS, DNS)


def get_schema(name: str) -> RawSchema:
    try:
        return ALL_SCHEMAS[name]
    except KeyError:
        known = ", ".join(sorted(ALL_SCHEMAS))
        raise KeyError(f"unknown dataset {name!r}; known datasets: {known}") from None


# --------------------------------------------------------------------------
# Vocabularies
# --------------------------------------------------------------------------
# Observed value sets, used by the synthetic generator to stay faithful to the
# real distribution and by quality checks to flag values we have never seen.

AUTH_TYPES: tuple[str, ...] = (
    "Negotiate",
    "Kerberos",
    "NTLM",
    "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
    "CredSSP",
)

LOGON_TYPES: tuple[str, ...] = (
    "Network",
    "Service",
    "Batch",
    "Interactive",
    "Unlock",
    "NetworkCleartext",
    "NewCredentials",
    "RemoteInteractive",
    "CachedInteractive",
)

AUTH_ORIENTATIONS: tuple[str, ...] = (
    "LogOn",
    "LogOff",
    "TGS",
    "TGT",
    "AuthMap",
    "ScreenLock",
    "ScreenUnlock",
)

OUTCOMES: tuple[str, ...] = ("Success", "Fail")

#: Seconds in the full LANL collection window (58 days).
COLLECTION_SECONDS: int = 58 * 24 * 3600
