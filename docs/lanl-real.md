# Running against the real LANL 2015 release

**Decision for this checkout:** the full ~12 GB gzipped corpus was **not**
ingested here. There is no measured recall table from `auth.txt.gz` on this
machine, and none is invented below. What shipped is a runbook, a day-window
ingest (`lmo ingest --max-day`), and evaluation that does not require
`scenario.json` or four campaign stages.

If you have the files and the disk, follow this document and write *your*
numbers into the README Part 7 table. Do not retune detector weights on that
run so the synthetic seed-2/3 figures look closer.

## Where the files come from

Download from <https://csr.lanl.gov/data/cyber1/>:

| File | Role |
|------|------|
| `auth.txt.gz` | authentications (the large file) |
| `proc.txt.gz` | process starts |
| `flows.txt.gz` | network flows |
| `dns.txt.gz` | DNS lookups |
| `redteam.txt.gz` | labelled authentications (not a 4-stage campaign) |

Disk: treat `auth.txt.gz` as the size that matters; the rest are much smaller.
RAM: DuckDB will spill; start with `--memory 3GB` and raise if the machine
allows. `--fast-parse` is the practical mode at this volume.

## Commands (full corpus)

Use a dedicated warehouse path so you do not `--reset` someone else's demo
file.

```bash
lmo verify-schema --source /path/to/lanl
lmo ingest --source /path/to/lanl --reset --fast-parse --memory 8GB \
    --report data/reports/lanl-ingest.json
lmo profile
lmo build-graph
lmo detect
lmo evaluate --source /path/to/lanl --budget 25 --report data/reports/lanl-eval.json
```

`label_join_rate` in `lmo profile` must be `1.0`. If it is not, stop: some
labelled authentications are not in `events`, and every later recall figure
is fiction.

`--fast-parse` makes `src_line_no` an approximate locator. `src_line_hash`
is still the identity of the raw line (see `src/lmo/ingest/normalize.py`).

## Commands (laptop slice)

Ingest still *reads* each gzip; `--max-day N` drops projected rows with
`day_index > N` after parse. Day 0 is `(time_sec - 1) // 86400 == 0`. Labels
use the same formula so they cannot sit unmatched and poison `label_join_rate`.

Reconciliation is `rows_in == rows_out + rows_quarantined + rows_beyond_window`.

```bash
lmo ingest --source /path/to/lanl --reset --fast-parse --max-day 2 \
    --report data/reports/lanl-slice.json
lmo profile
lmo build-graph
lmo detect
lmo evaluate --source /path/to/lanl --budget 25
```

`--max-day` does not make a 12 GB gzip small on disk. It only keeps a prefix
of days in the warehouse. If even reading auth is impossible, slice the file
outside this tool and still run `verify-schema` on what you keep.

## What evaluate reports on LANL

The generator writes `scenario.json` with a four-stage campaign. The real
`redteam.txt.gz` does not. `lmo evaluate --source <lanl dir>` therefore uses
**event recall** (labelled authentications in the budget cut), not `k/4`
stage recall. Do not compare that column to the Part 3 synthetic tables.

A world generated with `--no-redteam` still has `scenario.json` and
`ground_truth: null`. That is `world_kind=clean` (every alert is an FP).
A directory with labels and no scenario is `world_kind=labelled`.

## If the warehouse is locked

`lmo serve` holds a writable DuckDB lock. A second `lmo ingest` or `serve`
should say the file is locked and tell you to stop the other process -- not
print a raw DuckDB traceback.
