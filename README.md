# Lateral Movement Ontology

A security ontology and investigation workflow over the LANL 2015 authentication
dataset, built to answer a question a SOC analyst actually has at 03:00:

> Someone's credentials are being used somewhere they shouldn't be. Which
> account, which hosts, in what order, and how do I know?

The interesting part of the problem is not detecting an anomalous login. It is
that every individual authentication in a lateral-movement campaign is, on its
own, completely legitimate: a valid credential, a normal protocol, a host the
account is allowed to reach. The signal lives in the *shape of the relationships
over time*, which is why this is modelled as an ontology of entities and edges
rather than as a table of events with a score column.

## Status

| Part | Scope | State |
|------|-------|-------|
| **1** | **Ingest, normalisation, quarantine, lineage** | **done** |
| **2** | **Ontology and investigation graph** | **done** |
| **3** | **Detection (rules, graph, baseline) + evaluation** | **done** |
| **4** | **API and analyst UI** | **done** |
| **5** | **Writeback, provenance UI, audit** | **done** |
| **6** | **Documentation, metrics, demo** | **done** |
| **7** | **Real LANL, day slice, honest measurement** | **done** — [`docs/lanl-real.md`](docs/lanl-real.md) |
| **8** | **Case pack and partitioned Parquet** | **done** |
| **9** | **Idempotent ingest, parquet import, verify-pack** | **done** |
| **10** | **Incidents (account + time gap)** | **done** — [`docs/part10-plan.md`](docs/part10-plan.md) |

## Quick start

```bash
pip install -e ".[dev]"

# 1. Build a synthetic world with a labelled intrusion in it
lmo generate --preset small --out data/raw/synthetic

# 2. Normalise it into the warehouse
lmo ingest --source data/raw/synthetic --reset --report data/reports/ingest.json

# 3. See what landed
lmo profile
lmo quarantine

# 4. Trace any event back to the exact raw line it came from
lmo lineage --event-uid <uid> --source data/raw/synthetic

# 5. Build the ontology on top of the events
lmo build-graph

# 6. Investigate
lmo show C00946                       # profile a host or an account
lmo timeline --user U00114@DOM1 --start 1000000 --end 1030000
lmo paths C00946 C00010 --start 1000000 --end 1030000 --max-hops 3
lmo corroborate --time 1019601 --src C00021 --dst C00010

# 7. Detect, then evaluate at a fixed alert budget
lmo detect
lmo alerts --band high --limit 20
lmo evaluate --source data/raw/synthetic --budget 25

# 8. Open the same answers in a browser (binds 127.0.0.1)
lmo serve --source data/raw/synthetic

# Or one walkthrough (tiny world, does not start the server)
lmo demo
```

A `small` run is about 314k authentication events over 21 days and takes roughly
seven seconds to generate and ingest. Detection over that world is about
seventeen seconds more.

### Using the real LANL data

Download `auth.txt.gz`, `proc.txt.gz`, `flows.txt.gz`, `dns.txt.gz` and
`redteam.txt.gz` from <https://csr.lanl.gov/data/cyber1/>, then follow
[`docs/lanl-real.md`](docs/lanl-real.md). Short form:

```bash
lmo verify-schema --source /path/to/lanl
lmo ingest --source /path/to/lanl --reset --fast-parse     # or --max-day N
```

The files are byte-compatible with the generator. Format is not the same as
runtime: the full gzip is ~12 GB, `--fast-parse` makes `src_line_no`
approximate (the hash is still authoritative), and evaluate on LANL is
**event recall**, not the four-stage table from Part 3. This checkout did
not ingest the full release; do not quote a LANL recall number that is not
in that runbook.

## Part 1: what was built and why

### A synthetic world that fights back

Developing detections directly against the real labelled data is a trap: you
tune until the known red-team events light up, and you cannot tell whether you
built a detector or a lookup table. The generator produces an independently
labelled second world to develop against.

Its design goal is to *deny a naive detector an easy win*. Benign traffic
deliberately includes every shape an attacker produces:

| Benign behaviour | Attack shape it mimics |
|---|---|
| Users touching a host for the first time (project change, new access) | "previously unseen user→host edge" |
| Admin maintenance sweeps across 8–22 hosts | lateral fan-out |
| Password-expiry failure runs | brute force |
| Night shift and service accounts | off-hours activity |
| A handful of servers taking 10–20% of all destinations | hub centrality |

The injected campaign correspondingly uses valid credentials, ordinary auth
types, and a recon stage that deliberately mixes hosts the victim legitimately
uses with hosts they never have — so no single field separates it.

At the `small` preset the positive class is **1 in ~9,200 events**. Any
evaluation in Part 3 that reports accuracy rather than recall at a fixed alert
budget will be meaningless at that imbalance, and the generator's manifest says
so explicitly.

### One event model, not four tables

All four sources normalise into a single event table shaped after OCSF, so a
question like "what happened around this host between 02:00 and 04:00" is one
scan rather than a four-way union rewritten by hand every time. Field names
follow OCSF so the vocabulary is one a SOC already speaks, and so a second
source (Sysmon, CloudTrail) could be added without a redesign.

The project does *not* claim OCSF conformance — the dataset is anonymised and
lacks most required fields. Claiming conformance it does not have would be
worse than not claiming it.

### Nothing disappears

Two invariants, both enforced in code and asserted in tests:

**Reconciliation.** For every dataset, `rows_in == rows_out + rows_quarantined`.
If it does not hold, the run is marked not-ok and the CLI exits non-zero. Silent
row loss in a security pipeline is not a data-quality nuisance — it is the
difference between "we saw nothing" and "we lost the thing that mattered", and
those look identical from the outside.

**Quarantine, not drop.** Malformed rows go to a `quarantine` table with a
reason code, the verbatim line and its file position. Reason codes rather than
free text, so a spike in one kind of breakage is a visible operational signal.

```
reason breakdown:
  WRONG_ARITY                  2
  BAD_TIME                     3
  EMPTY_KEY_FIELD              2
```

### Lineage is paid for at write time

Every normalised row carries `src_dataset`, `src_file`, `src_line_no`,
`src_line_hash`, `run_id` and `schema_version`. Provenance cannot be
reconstructed after the fact, so the cost is paid during ingest. Part 5 turns
this into a "show me the raw record" button; today it is already a CLI command:

```
$ lmo lineage --event-uid ced5ab34... --source data/raw/synthetic
event      ced5ab345301cdd3c2bb17bac90113a2
  when     2015-04-17 14:33:36
  who      U00436@DOM1
  path     C00829 -> C00829
  source   auth / auth.txt.gz line 314081
  hash     05a6f827c95e8d1fc3dcd82a0c5f7cf5
  run      run_20260911T135632_70e339c1
  raw      1002817,U00436@DOM1,U00436@DOM1,C00829,C00829,NTLM,Network,LogOn,Fail
```

Two parsing modes back this. The default reads each file line-by-line and splits
in SQL, which is slower but gives exact file line numbers for every row, good or
bad. `--fast-parse` uses native CSV parsing and marks line numbers approximate.
The slower mode is the default on purpose: a provenance link that is *usually*
right is worse than none, because it invites trust it has not earned.

### Labels are kept out of reach

Ground truth lives in its own `redteam_labels` table and is never joined into
`events` as a column. Anything a feature pipeline can read, it will eventually
learn, and the resulting metrics would be fiction. A test asserts that no column
on `events` reveals the label.

The complementary risk is a label set that does not join at all — the quietest
possible way to invalidate an entire evaluation. `lmo profile` reports
`label_join_rate`, and a test asserts it is exactly `1.0`.

## Part 2: the ontology

`events` answers "what happened". It cannot answer "has this account ever
reached this host before", "which hosts could someone have moved through between
02:00 and 04:00", or "who else touched the machine this alert is about" without
rescanning everything, every time. The ontology materialises what an analyst
pivots on: nodes with identity (accounts, machines, logon sessions) and edges
carrying **when the relationship was first and last observed**.

### Time ordering is what makes it lateral movement

`lmo paths` finds routes where each hop happens strictly *after* the last:

```
$ lmo paths C00946 C00010 --start 1000000 --end 1030000 --max-hops 3
1 hop(s), 0 min, seen 1x    C00946 -> C00010
    accounts: U00252@DOM1
2 hop(s), 90 min, seen 2x   C00946 -> C00021 -> C00010
    accounts: U00114@DOM1, U00556@DOM1

$ lmo paths C00946 C00010 ... --user U00114@DOM1
2 hop(s), 130 min, seen 1x  C00946 -> C00021 -> C00010
    accounts: U00114@DOM1
```

Plain connectivity — "is there a chain of authentications linking A to B" — is
nearly always yes in a real network and says nothing. A chain whose timestamps
strictly increase is a route somebody *could have walked*. The search runs over
individual authentications rather than aggregated edges, because an aggregate
edge has one first-seen timestamp and would allow traversals at times the hop
never happened; and only `LogOn` counts as a hop, since a `LogOff` ends a
session that already existed.

### Point in time, not hindsight

Anything that judges whether something is unusual takes an `as_of` and looks
only backwards. Counting over the whole collection and scoring a day-3 event
with it lets the model see the future; every metric built on that is inflated,
the code reads perfectly, and nothing in the output looks wrong. Part 3's
evaluation depends on that guard holding here, so it is structural rather than a
convention.

### Calibrating a heuristic that could not otherwise be checked

Sessions are reconstructed by pairing each `LogOff` with the most recent `LogOn`
before it. Two simpler pairings were tried first and both are wrong in ways that
look fine: "next event is a logoff" breaks on overlapping sessions (25-minute
median against a generated 120), and "k-th logon with k-th logoff" drifts as
soon as some logons never close (72-hour median). The one that ships degrades
gracefully — a missing logoff leaves its own session open instead of corrupting
its neighbours.

`duration_sec` is still a **lower bound**, and `ontology/schema.py` carries the
measured error per logon type. That calibration exists only because the
synthetic world has ground truth; on the real LANL data the same heuristic would
run with no way to know how wrong it was. It is a large part of what the
generator is for.

### Staleness is reported, not assumed

The graph is materialised, so it goes out of date when new events are ingested.
`graph_runs` records what it was built from and every query entry point refuses
to answer on a stale graph. A graph that answers confidently and wrongly is
worse than one that declines.

## Part 3: detection and evaluation

The interesting part of detecting lateral movement is that every individual
authentication in the campaign is, on its own, legitimate. Scoring events
therefore produces either noise or a lookup table. The unit here is
**(account, source host, hour)** — what an analyst actually triages, and what
Part 4 will render. A campaign spread over 30 events is one incident, not 30
alerts.

Three layers name the shapes, then a weighted sum combines them. Nothing under
`src/lmo/detect/` may mention the labels; a grep-test fails the suite if it
does. Every baseline is computed from `time_sec` strictly before the bucket,
the same rule `host_rarity_as_of` already enforced in Part 2.

### What gets measured

Accuracy and AUC are the wrong numbers. At one attacker event in ~10,000 a
detector that alerts on nothing is 99.99% accurate. The number a SOC lives by
is: given that we can triage N alerts a day, how much of the campaign do we
catch, and how soon?

**Stage recall**, not event recall: an alert covering 12 of 30 labelled events
is one campaign detected, not 40% recall. Time to detection is seconds from the
campaign's first event to the first true-positive alert that made the budget
cut. A detector that only fires on the objective has found the intrusion after
it succeeded.

Weights and the high/medium score cuts were chosen on **seed 1** (`data/raw/tune`).
The tables below are from **seed 2 and seed 3**. False-positive volume is from
a fourth world generated with `--no-redteam` (seed 4), where every alert is a
false positive by construction.

### Recall at a fixed alert budget

Headline numbers are the eval worlds. Tune (seed 1) is omitted from the table
on purpose: it is the world the cuts were read from.

**Seed 2 (`eval-a`)**

| Alert budget (per day) | Layered stage recall | Naive first-contact | Layered time to first true alert | Precision (layered) |
|---|---|---|---|---|
| 10 | 1/4 (recon) | 1/4 (recon) | 1,627 s | 0.005 |
| 25 | 2/4 (recon, lateral) | 1/4 (recon) | 1,627 s | 0.007 |
| 50 | 2/4 (recon, lateral) | 1/4 (recon) | 1,627 s | 0.004 |
| 100 | 3/4 (adds credential theft) | 1/4 (recon) | 291 s | 0.003 |

**Seed 3 (`eval-b`)**

| Alert budget (per day) | Layered stage recall | Naive first-contact | Layered time to first true alert | Precision (layered) |
|---|---|---|---|---|
| 10 | 1/4 (recon) | 1/4 (recon) | 146 s | 0.005 |
| 25 | 2/4 (recon, lateral) | 1/4 (recon) | 146 s | 0.007 |
| 50 | 2/4 (recon, lateral) | 1/4 (recon) | 146 s | 0.004 |
| 100 | 3/4 (adds credential theft) | 1/4 (recon) | 146 s | 0.002 |

At 25 alerts/day — the budget a small SOC can actually triage — the layered
detector catches two of four stages on both held-out worlds, and the naive
detector catches one. That is the comparison the project has to beat, and it
does, modestly. Precision at that budget is 0.7%: four true alerts in 550.
That is what 1-in-10,000 prevalence looks like, not a bug in the arithmetic.

Stage 4, the hop to the objective, does not appear in the top 100 alerts/day
on either eval world. A one-hop extension from an already-interesting host
scores below the admin-sweep fan-out that the generator puts in on purpose.
Raising `chain_extension` until it did would have been fitting seed 1. The
weight stayed at 3.0 and the miss is in the table.

### False positives on a quiet week

On the clean world (seed 4, no intrusion) the score cut that produced ~25
alerts/day on the tune world produces **26.3 alerts/day**. The budget is almost
entirely false positives, which is the cost of looking. The same cut is ~11
alerts/day at "high". Naive first-contact, with no score cut, fires **843
units/day**.

Budget ranking on a clean world always fills the budget, so it is not a
measurement. Volume at a *fixed score cut* is.

### Weights

A learned model is the obvious next step and the wrong one here: there is one
labelled campaign per world, so a tree fitted on it is a lookup table. The
weighted sum is the baseline a later model has to beat.

| Signal | Weight | Why |
|---|---|---|
| `chain_extension` | 3.0 | Ties stages together. Highest weight; left until the others worked so it could not paper over them. Still not enough to surface a one-hop objective against admin sweeps. |
| `identity_switch` | 2.4 | Credential-theft signature. Benign `runas`/service traffic is ~3%, so it is discriminative only next to other signals. Surfaces at 100 alerts/day, not at 25. |
| `new_edge_burst` | 2.2 | Several first-contact edges from one source in an hour. A single first contact is ordinary drift (~1.8%). |
| `new_source_host` | 1.6 | Stolen admin authenticating from the victim's machine. The account's own first-ever hour is suppressed, or day 0 drowns the ranking. |
| `fan_out` | 1.5 | This hour vs the account's own trailing 95th percentile, so admins who routinely sweep do not light up. |
| `fail_then_success` | 1.3 | Recon mixes failures into pairs it later succeeds on. Password-expiry bursts end the same way. |
| `ntlm_downgrade` | 1.1 | Recon uses NTLM against hosts whose trailing traffic is Kerberos. Misconfigured clients do this too. |
| `pair_rarity` | 1.1 | Inverse of how often this account reached this destination. Weak alone; useful as a multiplier on a burst. |
| `host_count_z` | 1.0 | This hour's distinct hosts against the account's trailing *daily* distribution. An hour busier than a typical day is the fan-out that matters. |
| `dst_popularity` | 0.8 | Inverse of how many accounts reached this destination. The name is popularity; the value is rarity. |
| `hub_avoidance` | 0.7 | Share of destinations that are endpoints. Lateral movement to servers scores *low* here, so the weight is small. |
| `failure_run` | 0.6 | Five failures from one source in ten minutes. The injected recon is too spread out to hit five on one pair. |
| `protocol_rarity` | 0.4 | Tried as a way to catch `NewCredentials` on a user who never uses it; mostly tracked `identity_switch`. Kept so the comparison stays visible. |
| `first_contact` | 0.35 | Binary presence of a first-time edge. The burst version carries the real weight. |
| `off_hours` | 0.15 | Against this account's own trailing 10th–90th percentile hours. The campaign runs in the afternoon, night shift exists, and a linear hour percentile wraps badly around midnight. Kept so the measurement is honest. |

High ≥ 7.68 and medium ≥ 7.24 are the scores of the 10th and 25th alert per
day on seed 1. They are not refit on seeds 2, 3 or 4.

### What was tried and did not work

**Scoring in Python, one `executemany` per alert.** ~40 ms per row in DuckDB,
150 seconds to write 3,800 alerts on the tiny world. Replaced with one
`INSERT SELECT`. The weights still live in a dataclass; the SQL normalisers
sit next to the Python ones so a cap change cannot apply to only one path.

**`fail_then_success` joining `events` to itself.** The authentication filter
lived in `WHERE`, after the join, so flows and DNS were hashed in. Tiny
appeared to hang. The auth slice is now materialised once as `detect_auth`
and every later pass reads that.

**Rarity with no burn-in.** On day 0 every pair is infinitely rare, every
source host is new, and the ranking is a list of first hours. Trailing
signals are zeroed until the account has three prior days. Without that
floor the campaign, which starts 55% of the way through the window, never
reaches the top.

**Stage mapping from `scenario.json` start timestamps.** The generator records
stage 4's start as the *last* objective event, and stage 3's start as the
same second as stage 2. Mapping by those clocks files the objective hop
under lateral movement. Identity is more stable: victim recon, the
`NewCredentials` switch, the stolen admin, then anything on the objective
host.

**Circular hour statistics for `off_hours`.** A night-shift account whose
hours are 22–06 looks, under a linear percentile, like it works 0–22, and
will not flag a noon login. The join was harder to test than the signal was
worth; the weight is 0.15 and the wrap is documented.

**Catching stage 4 by turning up `chain_extension`.** A one-hop extension
from a host that already looked interesting is exactly the objective, and
also exactly an admin stepping from a server they just touched. At weight
3.0 it does not enter the top 100 alerts/day. That is a finding, not a
knob left unturned.

## Part 4: API and analyst UI

The CLI already answers the 03:00 questions. Part 4 is those answers as JSON
and as a screen, not a second query language. Every `/api/*` handler calls
`list_alerts`, `explain_alert`, or a function in `ontology.query`. Ground
truth stays in `evaluate/`. A grep-test fails the suite if `redteam` appears
under `api/` or `web/`.

```bash
lmo serve --host 127.0.0.1 --port 8765
```

The process binds localhost on purpose. The warehouse may contain real
telemetry; this is not a public app. Part 4 opened the warehouse
**read-only**. Part 5 opens it writable so a judgement can be appended.
Investigation queries are unchanged; only `decisions` is written.

Hash routes so a refresh does not lose the alert:

- `#/` — queue, filter by band, 50 at a time
- `#/alert/{uid}` — score, non-zero contributions, contributing events with
  lineage, then timeline / neighbours / corroboration / time-ordered paths
- `#/entity/{key}` — the same profile `lmo show` prints

The detail view is not done if it cannot show `signals` and resolvable
`event_uid`s. An alert a person cannot explain is an alert they learn to
ignore, and a UI that hides the lineage is worse than the CLI because it
invites trust the pipeline has not earned.

Paths are rendered as a time-ordered list of hosts, the same way the CLI
does. A force-directed graph was the obvious drawing and the wrong one:
Part 2 spent a section explaining that connectivity is almost always yes,
and a library that ignores timestamps would show that useless answer in
gold.

DuckDB connections are not safe across FastAPI's thread pool. One
`threading.Lock` wraps every warehouse call. Two sequential GETs in the
suite exist specifically so that lock cannot deadlock the second request.

`LmoError` is mapped the same way the CLI prints it — a problem the reader
can fix — to 404 / 409 / 503 / 400 with `{"problem", "fix"}`. A missing
warehouse still exits 2 from `lmo serve` before uvicorn binds.

What was tried and discarded: serving static files from the process cwd
(breaks after `pip install`); putting labels on the queue as a "debug"
toggle (the UI would then teach the analyst to look at the answer key);
drawing the ontology as a graph (see above).

## Part 5: writeback, provenance, audit

A button that does not persist a judgement is a lie, which is why Part 4 had
none. Part 5 records `true_positive`, `false_positive`, or `inconclusive`
against an alert (and optionally one event). The table is **append-only**: a
second click inserts a row and points `supersedes` at the previous latest.
The audit log is that table, not a side file.

False positives leave the default queue (`view=open`). True positives stay,
with the action shown. Scores do not change. Evaluation still reads only
`redteam_labels` under `evaluate/`. Feeding clicks into `ScoreConfig` would
make recall measure a detector that had seen the campaign through a person
who may have seen the labels.

```bash
lmo decide --alert-uid <uid> --action false_positive --note "admin sweep" --analyst local
lmo audit
lmo serve --source data/raw/synthetic
```

Show-raw opens the gzip Part 1 stored a locator into, then **checks
`src_line_hash`**. If the line number drifted (`--fast-parse`), the hash is
still the identity of the record. If the file on disk is a different file,
the request refuses rather than showing the wrong line.

What was tried and discarded: updating the latest row in place (that
destroys the audit); hiding true positives from the open queue (confirmed
work still needs to be visible); putting judgements into detect features
(see above).

## Part 6: interview packet

The pipeline was already done. This part is what you can hand someone who has
five minutes.

- **Walkthrough:** `lmo demo` (default `tiny`) runs generate → ingest →
  graph → detect → evaluate at 25 alerts/day → explain the top row → records
  `inconclusive` → prints audit. It prints the `lmo serve` line and **does
  not start uvicorn**. The warehouse is `data/warehouse/demo.duckdb` so a
  demo cannot `--reset` the main file.
- **Shape:** [`docs/architecture.md`](docs/architecture.md)
- **How to reproduce Part 3 numbers:** [`docs/metrics.md`](docs/metrics.md)
  — it does not reprint the tables and did not re-run seeds 2 and 3.
- **Talking points:** [`docs/interview.md`](docs/interview.md)
- **`python -m lmo`:** `__main__.py` was missing. The console script worked;
  `python -m lmo` did not. CI now runs both `--help`.

`.\tasks.ps1 demo` calls `lmo demo --preset tiny`.

What was not done: a slide deck; a charting dependency for tables that
already exist in markdown; rewriting the 750-line beginner guide (it now
points at this README for Parts 2–6); treating the tiny demo's recall as
the headline figure.

## Part 7: real LANL, without pretending we ran 12 GB

The generator is byte-compatible with LANL. That never meant a laptop had
already measured the 1.6 billion-row release.

- **Runbook:** [`docs/lanl-real.md`](docs/lanl-real.md) — files, `verify-schema`,
  `--fast-parse` lineage, `--max-day`, evaluate without `scenario.json`.
- **What was measured here:** nothing on the public 12 GB corpus. No LANL
  recall table is printed in this README. The synthetic Part 3 numbers are
  unchanged and were not retuned.
- **Day window:** `lmo ingest --max-day N` keeps `day_index <= N` for events
  **and** labels. Reconciliation is
  `rows_in == rows_out + rows_quarantined + rows_beyond_window`. Tests cover
  that on a tiny world (`tests/test_lanl_slice.py`).
- **Evaluate:** a directory with labels and no `scenario.json` is
  `world_kind=labelled` and reports **event recall**. `--no-redteam` remains
  `clean` (false-positive volume). Do not put `k/4` stages on LANL.
- **Ops:** a locked DuckDB file raises `LmoError` instead of a traceback.
  CI records one `inconclusive` decision after detect. Package version is
  `0.5.0`. [`CONTRIBUTING.md`](CONTRIBUTING.md) is the clone/pytest note.

What was not done: Spark; ingesting the full LANL dump on this machine;
learning weights from LANL labels or from analyst decisions.

## Part 8: handoff without the warehouse

An analyst who has clicked through an alert still cannot email the warehouse.
Part 8 is a **case file** and a **day-partitioned Parquet dump**, not a second
detector and not Spark.

```bash
lmo pack --alert-uid <uid> --out data/reports/case.json
lmo export-parquet --out data/parquet/world
```

- **`lmo pack`** writes the same objects the UI shows: the alert, signal
  contributions, contributing events (with lineage hashes), and writeback
  history. It does not join `redteam_labels`. `GET /api/alerts/{uid}/pack`
  is the same payload; the alert page has **download case JSON**.
- **`lmo export-parquet`** writes `events/day_index=N/*.parquet` plus
  `alerts.parquet`. That is the Hive layout in
  [`docs/scale-out.md`](docs/scale-out.md), produced with DuckDB `COPY` on
  one node. Host-bucket sub-partitions are still paper: they do not change
  I/O until there is more than one machine.
- **`lmo demo`** now also writes `demo-case.json` next to the demo warehouse.

What was not done: Spark; public bind; learning from cases; force-directed
graphs.

## Part 9: a second ingest must not double the world

`--reset` is a full rebuild. A day of new gzip, or a Parquet dump from another
laptop, has to land without cloning every row already in `events`.

```bash
lmo ingest --source data/raw/day1          # first load
lmo ingest --source data/raw/day1          # same files: 0 inserted, dup counted
lmo export-parquet --out data/parquet/world
lmo --db data/warehouse/copy.duckdb import-parquet --source data/parquet/world
lmo verify-pack --in data/reports/case.json
```

- **Idempotent ingest:** skip `(src_dataset, src_file, src_line_hash)` already
  present. Reconciliation is
  `rows_in == rows_out + quarantined + beyond + duplicate`.
  The skip key is the hash, not `event_uid`, because `--fast-parse` makes
  `src_line_no` approximate.
- **`lmo import-parquet`:** load `events/` from Part 8. Skip known hashes.
  Do **not** import `alerts.parquet` -- alerts are a detect product; a copied
  queue on a stale graph would lie. Rebuild with `lmo build-graph` then
  `lmo detect`.
- **`lmo verify-pack`:** each packed event's `src_line_hash` must still match
  the warehouse. Tampering or a rebuilt uid fails closed (exit 2). Still no
  labels in the case file.

What was not done: a streaming engine; rewriting a single Hive partition in
place; importing analyst queues from parquet.

## Part 10: incidents, not twelve hourly cards

The detector's grain is still (account, source host, hour). A campaign is
several of those. Part 10 groups them when the **same account** keeps firing
and the next hour starts within `--gap-hours` (default 4). Different accounts
never merge. Changing `src_host` does not split the incident — that is the
lateral movement.

```bash
lmo incidents --gap-hours 4 --limit 20
lmo incidents --incident-uid <uid>
```

The UI has an **incidents** link (`#/incidents`). `GET /api/incidents` is the
same list. Scores do not change. Labels are not read. The view is computed
from the current `alerts` table, not stored as a second truth.

Brief: [`docs/part10-plan.md`](docs/part10-plan.md).

What was not done: incident-level writeback; packing a whole incident;
learning a gap from LANL labels.

## Why DuckDB and not Spark

The full LANL release is ~12 GB gzipped, around 1.6 billion authentication rows.
That is large for a laptop and small for a cluster. DuckDB reads the gzipped CSV
directly, spills to disk when an aggregate does not fit in memory, and needs no
JVM and no cluster.

Running Spark in local mode on this volume would spend most of its time on JVM
overhead and disk shuffle rather than useful work, and would invite the fair
question of why a distributed engine was chosen for a single-node problem.
[`docs/scale-out.md`](docs/scale-out.md) documents what would change at 100×
instead: the partitioning key, where the shuffles land, which join becomes a
broadcast, and the skew problem that one domain controller creates.

## Tests

```bash
pytest -q      # 184 passed, 1 skipped
```

The suite is not decoration. `test_epoch_anchor_puts_day_zero_on_a_monday`
caught a real defect during development: DuckDB's `/` on integers returns a
DOUBLE, and `CAST(... AS INTEGER)` *rounds* it, so every event after midday was
being filed under the following day. Roughly half of all rows had the wrong
`day_index`, and nothing else would have noticed until a time-of-day feature
produced nonsense three parts later.

`tests/test_errors.py` covers a second class of defect that no other check
catches: a command that still "works" but tells the reader something false.
Pointing `--source` at a mistyped path used to report *"rows disappeared between
input and output"* — the pipeline's most serious failure message — for the
entirely ordinary case of an empty directory. Nothing had been read, so nothing
could have been lost. Those cases now name the actual problem and say what to do
about it, and the tests assert both.

Two defects from a later audit pass are worth naming, because both were
*invisible while everything appeared to work*:

**The fast path made reconciliation vacuous.** `--fast-parse` used DuckDB's
`ignore_errors`, which discards unparseable lines before the scan returns — so
`rows_in` was already the post-drop count. Input and output agreed, both having
lost the same rows, and the run reported `ok`. That is precisely the failure the
invariant exists to catch, hiding inside the mode this README recommends for the
full 12 GB release. Rejects are now recovered through `store_rejects`, carrying
their true file line numbers, and both modes account for every line.

**The secondary telemetry did not corroborate anything.** `flows` and `dns` were
drawn from independent random host pairs while the code claimed they backed up
the authentication stream. Measured against the generated data, 0.7% of flows
shared a host pair with any authentication — chance alone. A configurable share
is now generated *from* the auth file (a network logon produces a flow between
those hosts seconds later, and usually a DNS lookup just before it), with the
remainder left as background traffic so corroboration discriminates rather than
being automatic.

**Two platform defects, both invisible on ASCII data.** Text files were opened
without an explicit `encoding`, which means the platform default — UTF-8 on
Linux, usually cp1252 on Windows. The LANL data is pure ASCII, where the two
agree, so this would have stayed hidden until the first non-ASCII byte and then
broken on only one operating system. Separately, the user array was a numpy
string array created at width 11 from `U00001@DOM1`; assigning the
machine-account form `C00115$@DOM1` into it **truncated silently**, so every
service account lost the last character of its domain and the dataset contained
a second domain that does not exist. Nothing downstream could have flagged it —
the value was well formed, just wrong.

Both are now asserted in tests, and CI runs the suite on Linux and Windows plus
a job with the locale forced to ASCII, so an encoding assumption fails loudly
instead of depending on who runs it.

Part 3 adds the two guards that keep the numbers above from being fiction: the
detect package is grepped for the label table's name, and every trailing
signal is asserted at two `as_of` points so a later day cannot change an
earlier score. CI now also runs `lmo detect` and `lmo evaluate` on the smoke
world, because a detector that only works in-process is not the detector the
console script will run.

Part 4 adds the same kind of guard for the UI: `api/` and `web/` are grepped
for the label table's name, missing alerts return a `fix`, and a stale graph
is 409 rather than a confident empty queue. Part 5 greps `writeback/` the
same way, and asserts that a false positive leaves the open queue without
touching scores.

## Layout

```
src/lmo/
  schemas/raw.py         LANL column layouts — the only place order is declared
  schemas/normalized.py  the unified event model and quarantine schema
  generate/synth.py      the synthetic world and its red-team campaign
  ingest/engine.py       DuckDB warehouse, run bookkeeping, reconciliation
  ingest/normalize.py    raw → normalised, quarantine, lineage
  ingest/pipeline.py     orchestration and post-ingest profile
  ontology/schema.py     entities, edges, and the session calibration table
  ontology/build.py      builds the graph from events; staleness tracking
  ontology/query.py      profiles, timeline, neighbours, paths, corroboration
  detect/                rules, graph signals, trailing baselines, scoring
  evaluate/              stage or event recall at a fixed alert budget
  api/                   FastAPI wrappers; lock around one warehouse
  writeback/             append-only analyst decisions; hash-checked raw lines
  handoff.py             case JSON, Hive Parquet, import, verify-pack (no labels)
  incidents.py           group hourly alerts for one account
  web/static/            one HTML page, hash routes, no framework
  cli.py                 generate / ingest / detect / evaluate / decide / pack / import-parquet / serve / demo
  errors.py              user-facing errors, printed without a traceback
scripts/ci_check.py      asserts the invariants on a real run, for CI
.github/workflows/       tests on Linux and Windows, plus an ASCII-locale job
tests/                   185 tests (one skip if DuckDB allows two writers)
docs/scale-out.md        what would change on 100× the data
docs/architecture.md     mermaid of ingest → graph → detect → UI
docs/metrics.md          how to reproduce the Part 3 tables
docs/interview.md        five-minute talking points
docs/part3-plan.md       the brief Part 3 was built from
docs/part4-plan.md       the brief Part 4 was built from
docs/part5-plan.md       the brief Part 5 was built from
docs/part6-plan.md       the brief Part 6 was built from
docs/part7-plan.md       the brief Part 7 was built from
docs/part10-plan.md      the brief Part 10 was built from
docs/lanl-real.md        how to run the public LANL files (honest about scale)
CONTRIBUTING.md          clone, pytest, label-isolation rules
```
