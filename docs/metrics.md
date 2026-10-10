# Metrics — how to reproduce, not a second table

The numbers an interviewer should quote are in the README, Part 3. They were
measured on **held-out seeds 2 and 3**, with weights chosen on seed 1. This
file does not repeat those tables and does not invent a new run.

## What "good" means here

Accuracy is the wrong number. At one attacker event in ~10,000, a detector
that fires on nothing is 99.99% accurate. The SOC number is: given N alerts
per day, how many campaign **stages** appear in the budget cut, and how soon.

Reproduce that, on a machine that can spare a few minutes for `small`:

```bash
lmo generate --preset small --seed 2 --out data/raw/eval-a
lmo ingest --source data/raw/eval-a --reset
lmo build-graph
lmo detect
lmo evaluate --source data/raw/eval-a --budget 25
lmo sweep --source data/raw/eval-a --budgets 10,25,50,100
```

Clean-world false-positive volume (every alert is an FP by construction):

```bash
lmo generate --preset small --seed 4 --no-redteam --out data/raw/clean
# ingest, build-graph, detect, then the clean-volume block of evaluate
# if you point evaluate at a world with no scenario labels it will say so
```

`tiny` is for development and for `lmo demo`. Its recall is not the headline
figure. Do not compare a tiny demo to the seed-2 table and call it a
regression.

`--no-redteam` still writes `scenario.json` with `ground_truth` set to null.
Point `lmo evaluate --source` at that directory: `world_kind` is `clean` and
the band-volume block is the false-positive cost. A LANL download has labels
and no scenario; that path is **event recall**, documented in
[`docs/lanl-real.md`](lanl-real.md). Do not print `k/4` stages for it.

Part 6 did **not** re-run seeds 2 and 3. If those numbers ever change, change
the README from a new eval, not from this file.

This file does **not** contain LANL production recall. That corpus was not
run in the Part 7 checkout that added `--max-day`. If you measure it, put the
table in README Part 7 and leave these synthetic instructions alone.
