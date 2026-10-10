"""Orchestration: run every raw file through normalisation as one unit.

The reconciliation contract
---------------------------
For every dataset, ``rows_in == rows_out + rows_quarantined +
rows_beyond_window + rows_duplicate`` must hold. If it does not, the run is
marked not-ok and the CLI exits non-zero. ``rows_beyond_window`` is zero
unless ``--max-day`` capped the ingest. ``rows_duplicate`` is zero unless
the same raw line was already in the warehouse.

This is the single most valuable check in the whole ingest layer. Silent row
loss in a security pipeline is not a data-quality nuisance; it is the difference
between "we saw nothing" and "we lost the thing that mattered", and those look
identical from the outside. Making the invariant explicit -- and failing loudly
on it -- is what lets a later claim like "we detected 7 of 9 red-team stages"
mean anything at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from lmo.errors import LmoError
from lmo.ingest.engine import DEFAULT_EPOCH, RunStats, Warehouse, timer
from lmo.ingest.normalize import ingest_dataset, ingest_labels
from lmo.schemas.normalized import SCHEMA_VERSION
from lmo.schemas.raw import EVENT_SCHEMAS, REDTEAM


@dataclass
class IngestReport:
    run_id: str
    source_dir: Path
    stats: list[RunStats]
    seconds: float
    ok: bool

    @property
    def total_in(self) -> int:
        return sum(s.rows_in for s in self.stats)

    @property
    def total_out(self) -> int:
        return sum(s.rows_out for s in self.stats)

    @property
    def total_quarantined(self) -> int:
        return sum(s.rows_quarantined for s in self.stats)

    @property
    def total_beyond(self) -> int:
        return sum(s.rows_beyond_window for s in self.stats)

    @property
    def total_duplicate(self) -> int:
        return sum(s.rows_duplicate for s in self.stats)

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "source_dir": str(self.source_dir),
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "totals": {
                "rows_in": self.total_in,
                "rows_out": self.total_out,
                "rows_quarantined": self.total_quarantined,
                "rows_beyond_window": self.total_beyond,
                "rows_duplicate": self.total_duplicate,
            },
            "datasets": [s.as_dict() for s in self.stats],
        }

    def render(self) -> str:
        lines = [
            f"run {self.run_id}   source={self.source_dir}",
            "",
            f"{'dataset':<10}{'in':>12}{'out':>12}{'quarantined':>14}"
            f"{'beyond':>10}{'dup':>10}{'sec':>9}  ok",
            "-" * 80,
        ]
        for s in self.stats:
            lines.append(
                f"{s.dataset:<10}{s.rows_in:>12,}{s.rows_out:>12,}"
                f"{s.rows_quarantined:>14,}{s.rows_beyond_window:>10,}"
                f"{s.rows_duplicate:>10,}{s.seconds:>9.2f}  "
                f"{'yes' if s.reconciled else 'NO'}"
            )
            for code, n in s.warnings.items():
                lines.append(f"{'':<10}warn {code}: {n:,}")
        lines += [
            "-" * 80,
            f"{'total':<10}{self.total_in:>12,}{self.total_out:>12,}"
            f"{self.total_quarantined:>14,}{self.total_beyond:>10,}"
            f"{self.total_duplicate:>10,}{self.seconds:>9.2f}  "
            f"{'yes' if self.ok else 'NO'}",
        ]
        if not self.ok:
            lines.append("")
            lines.append(
                "RECONCILIATION FAILED: rows disappeared between input and "
                "output. Do not build on this run."
            )
        return "\n".join(lines)


def run_ingest(
    wh: Warehouse,
    source_dir: Path,
    *,
    defensive: bool = True,
    epoch: datetime = DEFAULT_EPOCH,
    reset: bool = False,
    max_day: int | None = None,
) -> IngestReport:
    """Ingest every raw file found in ``source_dir``."""
    source_dir = Path(source_dir)
    if max_day is not None and max_day < 0:
        raise LmoError(
            f"--max-day must be >= 0 (got {max_day})",
            "Omit the flag to keep every day, or pass 0 to keep only day_index 0.",
        )

    # These two failures are checked before anything is touched, and they are
    # kept distinct from a reconciliation failure on purpose. An empty run used
    # to report "rows disappeared", which is not merely unhelpful -- it is
    # false, and it sends the reader looking for a bug in the pipeline when the
    # real problem is that they pointed it at the wrong folder.
    if not source_dir.is_dir():
        raise LmoError(
            f"no such directory: {source_dir}",
            "Check the path given to --source. To create a dataset first, run "
            "'lmo generate --preset small --out data/raw/synthetic'.",
        )

    present = [
        s for s in (*EVENT_SCHEMAS, REDTEAM) if (source_dir / s.filename).exists()
    ]
    if not present:
        expected = ", ".join(s.filename for s in (*EVENT_SCHEMAS, REDTEAM))
        raise LmoError(
            f"{source_dir} contains none of the expected files",
            f"Looked for: {expected}. Run 'lmo generate' to create them, or "
            f"point --source at the directory holding the LANL download.",
        )

    if reset:
        wh.drop_all()

    run_id = wh.new_run_id()
    t0 = timer()
    started = datetime.now(timezone.utc).timestamp()
    stats: list[RunStats] = []

    for schema in EVENT_SCHEMAS:
        path = source_dir / schema.filename
        if not path.exists():
            continue
        stats.append(
            ingest_dataset(
                wh, schema.name, path, run_id,
                defensive=defensive, epoch=epoch, max_day=max_day,
            )
        )

    label_path = source_dir / REDTEAM.filename
    if label_path.exists():
        stats.append(
            ingest_labels(
                wh, label_path, run_id, defensive=defensive, max_day=max_day,
            )
        )

    seconds = timer() - t0
    ok = all(s.reconciled for s in stats)

    wh.record_run(
        run_id=run_id,
        started_at=started,
        source_dir=source_dir,
        config={
            "defensive": defensive,
            "epoch": epoch.isoformat(),
            "max_day": max_day,
        },
        stats=stats,
        schema_version=SCHEMA_VERSION,
    )
    return IngestReport(run_id, source_dir, stats, seconds, ok)


# ---------------------------------------------------------------------------
# Post-ingest profile
# ---------------------------------------------------------------------------

def profile(wh: Warehouse) -> dict:
    """A compact picture of what landed, for eyeballing after a run.

    Every number here exists to answer a question the next part of the project
    will ask. ``top_destinations`` shows the skew that makes degree centrality
    useless; ``label_join_rate`` proves the ground truth actually joins onto the
    events (a label set that does not join is the quietest possible way to
    invalidate an entire evaluation).
    """
    q = wh.con.execute

    out: dict = {}
    out["events_total"] = q("SELECT count(*) FROM events").fetchone()[0]
    out["by_dataset"] = dict(
        q("SELECT src_dataset, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC")
        .fetchall()
    )
    out["quarantined"] = dict(
        q("SELECT reason_code, count(*) FROM quarantine GROUP BY 1").fetchall()
    )

    auth = "src_dataset = 'auth'"
    out["distinct_users"] = q(
        f"SELECT count(DISTINCT src_user_uid) FROM events WHERE {auth}"
    ).fetchone()[0]
    out["distinct_hosts"] = q(
        f"""SELECT count(*) FROM (
                SELECT src_endpoint AS h FROM events WHERE {auth}
                UNION SELECT dst_endpoint FROM events WHERE {auth})"""
    ).fetchone()[0]
    out["days"] = q(
        f"SELECT max(day_index) - min(day_index) + 1 FROM events WHERE {auth}"
    ).fetchone()[0]
    out["failure_rate"] = round(
        q(f"SELECT avg(CASE WHEN status_id = 2 THEN 1.0 ELSE 0 END) "
          f"FROM events WHERE {auth}").fetchone()[0] or 0.0, 5
    )

    # The skew that shapes every downstream join and every graph metric.
    top = q(
        f"""SELECT dst_endpoint, count(*) AS n FROM events WHERE {auth}
            GROUP BY 1 ORDER BY 2 DESC LIMIT 5"""
    ).fetchall()
    total_auth = q(f"SELECT count(*) FROM events WHERE {auth}").fetchone()[0] or 1
    out["top_destinations"] = [
        {"host": h, "events": n, "share": round(n / total_auth, 4)}
        for h, n in top
    ]

    n_labels = q("SELECT count(*) FROM redteam_labels").fetchone()[0]
    out["labels"] = n_labels
    if n_labels:
        joined = q(
            """
            SELECT count(*) FROM redteam_labels l
            WHERE EXISTS (
                SELECT 1 FROM events e
                WHERE e.src_dataset = 'auth'
                  AND e.time_sec      = l.time_sec
                  AND e.src_user_uid  = l.user_uid
                  AND e.src_endpoint  = l.src_endpoint
                  AND e.dst_endpoint  = l.dst_endpoint
            )
            """
        ).fetchone()[0]
        out["label_join_rate"] = round(joined / n_labels, 4)
        out["label_prevalence"] = f"1 in {int(total_auth / max(n_labels, 1)):,}"
    return out


def write_report(report: IngestReport, profile_data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"ingest": report.as_dict(), "profile": profile_data},
                   indent=2, default=str),
        encoding="utf-8",
    )
