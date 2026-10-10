"""DuckDB warehouse: connection management, DDL and run bookkeeping.

Why DuckDB and not Spark
------------------------
The full LANL release is ~12 GB gzipped, around 1.6 billion authentication
rows. That is large for a laptop and small for a cluster. DuckDB reads the
gzipped CSV directly, spills to disk when a hash aggregate does not fit in
memory, and needs no JVM, no cluster and no serialisation boundary.

Running Spark in local mode on this volume would spend most of its time on JVM
overhead and disk shuffle rather than useful work, and would invite the fair
question of why a distributed engine was chosen for a single-node problem. The
scale-out design is documented in ``docs/scale-out.md`` instead: what the
partitioning key would be, where the shuffles land, and which join becomes a
broadcast. Describing that accurately is a stronger signal than running a
cluster engine on one machine.
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import duckdb

from lmo.errors import LmoError
from lmo.schemas.normalized import (
    EVENT_COLUMNS,
    QUARANTINE_COLUMNS,
    create_table_sql,
)

#: Day 0 of the dataset clock. The real LANL data does not disclose calendar
#: dates, so any anchor is a convention; this one is a Monday, which makes
#: ``day_index % 7 IN (5, 6)`` mean "weekend" without an off-by-one.
DEFAULT_EPOCH = datetime(2015, 4, 6, tzinfo=timezone.utc)


def _connect_duckdb(display_path: Path, path: Path | str, *, read_only: bool):
    """Open DuckDB, turning a lock conflict into a message a person can act on."""
    try:
        return duckdb.connect(str(path), read_only=read_only)
    except duckdb.Error as exc:
        text = str(exc).lower()
        if any(
            token in text
            for token in (
                "lock",
                "already open",
                "conflicting",
                "cannot open",
                "can't open",
            )
        ):
            raise LmoError(
                f"the warehouse at {display_path} is locked by another process",
                "Stop the other 'lmo serve' or Python session using this file, "
                "then retry.",
            ) from exc
        raise


@dataclass
class RunStats:
    """Per-dataset accounting for one ingest run.

    Kept explicitly rather than inferred from table counts afterwards, because
    the number that matters operationally is ``rows_in - rows_out -
    rows_quarantined - rows_beyond_window - rows_duplicate``, and that
    difference must be zero. ``rows_beyond_window`` is the planned skip when
    ``--max-day`` is set. ``rows_duplicate`` is a row already in ``events``
    (same file and line hash) -- a second ingest of the same gzip must not
    double the warehouse. If other rows vanish, the pipeline cannot be trusted.
    """

    dataset: str
    rows_in: int = 0
    rows_out: int = 0
    rows_quarantined: int = 0
    rows_beyond_window: int = 0
    rows_duplicate: int = 0
    seconds: float = 0.0
    warnings: dict[str, int] = field(default_factory=dict)

    @property
    def reconciled(self) -> bool:
        return (
            self.rows_in
            == self.rows_out
            + self.rows_quarantined
            + self.rows_beyond_window
            + self.rows_duplicate
        )

    def as_dict(self) -> dict:
        return {
            "dataset": self.dataset,
            "rows_in": self.rows_in,
            "rows_out": self.rows_out,
            "rows_quarantined": self.rows_quarantined,
            "rows_beyond_window": self.rows_beyond_window,
            "rows_duplicate": self.rows_duplicate,
            "seconds": round(self.seconds, 3),
            "reconciled": self.reconciled,
            "warnings": self.warnings,
        }


class Warehouse:
    """A DuckDB database plus the project's tables and run metadata."""

    def __init__(
        self,
        path: Path | str = "data/warehouse/lmo.duckdb",
        *,
        memory_limit: str = "3GB",
        threads: int | None = None,
        read_only: bool = False,
    ) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            if read_only and not self.path.exists():
                raise LmoError(
                    f"there is no warehouse at {self.path}",
                    "Run 'lmo generate' and then 'lmo ingest' first -- the "
                    "warehouse is created by the ingest step.",
                )
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.con = _connect_duckdb(self.path, path, read_only=read_only)
        self.con.execute(f"SET memory_limit='{memory_limit}'")
        if threads is not None:
            self.con.execute(f"SET threads={threads}")
        self._default_threads = self.con.execute(
            "SELECT current_setting('threads')"
        ).fetchone()[0]
        if not read_only:
            self.create_tables()

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self.con.close()

    def __enter__(self) -> "Warehouse":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def sequential_read(self) -> Iterator[None]:
        """Force single-threaded execution for the duration of a raw read.

        Line numbers are assigned with ``row_number()`` over the CSV scan, which
        is only meaningful if rows arrive in file order. A single gzip member is
        not seekable so DuckDB reads it sequentially anyway, but pinning threads
        makes the guarantee explicit rather than incidental.

        Note that ``src_line_hash`` -- not ``src_line_no`` -- is the authoritative
        identity of a raw record. The line number is a locator for a human
        opening the file; the hash is what survives a re-read.
        """
        self.con.execute("SET threads=1")
        try:
            yield
        finally:
            self.con.execute(f"SET threads={self._default_threads}")

    # -- DDL ---------------------------------------------------------------

    def create_tables(self) -> None:
        self.con.execute(create_table_sql("events", EVENT_COLUMNS))
        self.con.execute(create_table_sql("quarantine", QUARANTINE_COLUMNS))
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS redteam_labels (
                time_sec BIGINT,
                user_uid VARCHAR,
                src_endpoint VARCHAR,
                dst_endpoint VARCHAR,
                label_uid VARCHAR
            )
            """
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_runs (
                run_id VARCHAR PRIMARY KEY,
                started_at TIMESTAMP,
                finished_at TIMESTAMP,
                source_dir VARCHAR,
                config_hash VARCHAR,
                schema_version VARCHAR,
                host VARCHAR,
                duckdb_version VARCHAR,
                stats_json VARCHAR,
                ok BOOLEAN
            )
            """
        )
        from lmo.writeback.schema import ensure_decision_tables

        ensure_decision_tables(self.con)

    def drop_all(self) -> None:
        for t in (
            "events", "quarantine", "redteam_labels", "ingest_runs", "decisions",
        ):
            self.con.execute(f"DROP TABLE IF EXISTS {t}")
        self.create_tables()

    # -- run bookkeeping ---------------------------------------------------

    @staticmethod
    def new_run_id() -> str:
        return f"run_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}_{uuid.uuid4().hex[:8]}"

    @staticmethod
    def config_hash(config: dict) -> str:
        blob = json.dumps(config, sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()[:16]

    def record_run(
        self,
        run_id: str,
        started_at: float,
        source_dir: Path,
        config: dict,
        stats: list[RunStats],
        schema_version: str,
    ) -> None:
        ok = all(s.reconciled for s in stats)
        self.con.execute(
            """
            INSERT OR REPLACE INTO ingest_runs VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            [
                run_id,
                datetime.fromtimestamp(started_at, tz=timezone.utc),
                datetime.now(timezone.utc),
                str(source_dir),
                self.config_hash(config),
                schema_version,
                platform.node(),
                duckdb.__version__,
                json.dumps([s.as_dict() for s in stats]),
                ok,
            ],
        )

    # -- convenience -------------------------------------------------------

    def sql(self, query: str, params: list | None = None):
        return self.con.execute(query, params or []).fetchall()

    def df(self, query: str, params: list | None = None):
        return self.con.execute(query).df()

    def count(self, table: str) -> int:
        return self.con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def timer() -> float:
    return time.perf_counter()
