# What would change at 100×

The full LANL release is ~1.6 billion authentication rows in ~12 GB gzipped.
DuckDB on one machine handles that. This document describes what the design
would look like if the same pipeline had to serve an estate producing that
volume *per day* rather than per 58 days — roughly 100× — because being able to
describe that accurately is more useful than running a cluster engine on a
single-node problem.

## Where the work actually is

Profiling the ingest, the time splits roughly:

| Stage | Cost | Scales how |
|---|---|---|
| gzip decompression | high | linear, single-threaded per file, not seekable |
| line splitting and validation | high | linear, embarrassingly parallel |
| projection into the event model | moderate | linear, embarrassingly parallel |
| the entity/edge aggregations Part 2 needs | moderate | **shuffle-bound** |

Only the last one has a distributed-systems problem in it. The first three are a
throughput question, and the honest answer at 100× is "run more of them", not
"use a different engine".

## Partitioning

`day_index` is the natural partition key, and it is why the column is
materialised at ingest rather than derived at query time.

- Every detection in Part 3 is windowed — a baseline over the trailing 30 days,
  a fan-out count within an hour. Day partitioning turns those into a scan of a
  bounded set of files.
- Re-ingesting a corrected day rewrites one partition instead of the table.
- It matches how the data arrives.

Within a day, sub-partitioning by `hash(src_endpoint) % N` keeps host-local
aggregations node-local. Partitioning by *user* instead would be the intuitive
choice and the wrong one: the per-user distribution is far more skewed than the
per-host one, because service accounts authenticate orders of magnitude more
often than people.

The physical layout would be Parquet:

```
events/day_index=0/host_bucket=00/part-*.parquet
```

Parquet rather than CSV for the obvious reason — the detections read six or
seven of the forty-two columns, and column pruning alone removes most of the I/O.

Part 8's `lmo export-parquet` writes the `day_index` half of this layout on
one machine (`COPY ... PARTITION_BY (day_index)`). It does not salt hot keys
or split by `host_bucket`; those are still the 100× problem.

## The shuffle, and the skew

The expensive operation in Part 2 is building the user→host edge table with
first-seen and last-seen timestamps and counts:

```sql
SELECT src_user_uid, dst_endpoint,
       min(time_sec), max(time_sec), count(*)
FROM events WHERE class_uid = 3002
GROUP BY 1, 2
```

Distributed, that is a hash shuffle on `(src_user_uid, dst_endpoint)`. It is also
where this dataset's defining problem shows up: **one domain controller is the
destination of a large share of all authentications**. In the synthetic `small`
world the top host takes ~10% of destinations; in the real data the concentration
is worse. A hash partition on the destination sends that host's rows to one
reducer, which then runs for as long as the whole job.

Three ways to handle it, in the order worth trying:

1. **Two-phase aggregation.** Pre-aggregate per input partition, then combine.
   `count`, `min` and `max` are all associative, so the reducer receives one row
   per (user, host) per partition instead of every event. This alone usually
   fixes it, and needs no knowledge of which host is hot.
2. **Salting the hot keys.** Identify hosts above a share threshold, append a
   random salt to their key for the first pass, strip it and re-aggregate. Costs
   a second pass; only worth it if phase one is still skewed.
3. **Separating the hub hosts entirely.** Handle the top-N destinations in their
   own job. This is the most work and the most control, and is what you would do
   if the hot set were stable and small — which, for domain controllers, it is.

## Which joins become broadcasts

Part 3's baseline detections join events against reference tables that stay
small no matter how much telemetry arrives:

- host inventory (role, criticality, owner) — thousands of rows
- account inventory (type, privilege level) — tens of thousands
- the "known benign fan-out" allowlist built from admin maintenance windows

All three are broadcast joins: replicate the small side to every node, no shuffle.
The rule of thumb is whether the small side fits comfortably in per-executor
memory; all of these do by three orders of magnitude.

The join that is *not* a broadcast is events-to-events — correlating an
authentication with a network flow between the same pair of hosts in the same
second. That is a genuine large-to-large join, and the way to make it cheap is
to co-partition both sources on `(day_index, host_bucket)` at write time so the
join is node-local. Doing that is the reason `flows` and `auth` share the same
endpoint column names in the normalised model.

## Streaming

The batch design above answers "what happened". A production deployment also
needs "what is happening", and the two have genuinely different shapes.

Detections split cleanly:

- **Stateless, per-event** rules (NTLM to a host this account has never used)
  port to streaming directly, given a keyed state store holding each account's
  seen-host set.
- **Windowed aggregates** (fan-out within an hour) map onto a sliding window,
  with the usual watermark question: how late can an event arrive before it is
  dropped, and what does dropping it mean for recall. In security telemetry,
  late data is not rare — an endpoint that was offline uploads hours of logs at
  once — so the watermark has to be generous and the detection has to tolerate
  re-firing.
- **Trailing baselines** (30-day rarity of a user/host/auth-type triple) do not
  belong in the stream at all. They are computed in batch and published to the
  stream as a slowly-changing lookup.

That last split is the design point worth stating plainly: the streaming path
should not recompute history. It consumes a model the batch path produced. The
alternative — a stream that maintains 30 days of per-triple state — is possible
and is almost always the wrong trade.

Part 9 is the batch stand-in for "the next file arrived": a second
`lmo ingest` without `--reset` inserts only unseen line hashes, and
`lmo import-parquet` does the same for a Hive dump. That is not a watermarked
stream. It is the invariant a stream would still need.

## What stays the same

The reconciliation invariant, the quarantine table and the lineage columns are
not single-node conveniences. At 100× they matter more, not less: the number of
malformed rows grows with volume, and "which of the 900 files did this row come
from" becomes a question you cannot answer by opening the file yourself.
