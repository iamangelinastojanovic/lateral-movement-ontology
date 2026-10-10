"""Assert the invariants on a real ingest run, for CI.

The unit tests call ``main()`` in-process. This runs after the *installed*
``lmo`` command has produced a report, which is a different thing on Windows --
there the console script is an ``.exe`` shim generated at install time, and a
broken entry point or packaging mistake shows up only here.

Usage:  python scripts/ci_check.py data/reports/ci.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    report = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    ingest, profile = report["ingest"], report["profile"]

    failures: list[str] = []

    if not ingest["ok"]:
        failures.append("reconciliation failed: rows were lost during ingest")

    totals = ingest["totals"]
    if totals["rows_in"] != totals["rows_out"] + totals["rows_quarantined"]:
        failures.append(f"totals do not balance: {totals}")

    if totals["rows_out"] < 1000:
        failures.append(f"suspiciously few rows ingested: {totals['rows_out']}")

    # The invariant every later part depends on: the ground truth must actually
    # join onto the events. A rate below 1.0 makes every recall figure wrong.
    join_rate = profile.get("label_join_rate")
    if join_rate != 1.0:
        failures.append(f"label_join_rate is {join_rate}, expected exactly 1.0")

    if profile.get("labels", 0) < 1:
        failures.append("no red-team labels were loaded")

    if failures:
        print("CI CHECK FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(
        f"ci check ok: {totals['rows_in']:,} rows in, "
        f"{totals['rows_out']:,} out, "
        f"{totals['rows_quarantined']:,} quarantined, "
        f"label_join_rate={join_rate}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
