"""Command line interface.

    lmo generate --preset small --out data/raw/synthetic
    lmo ingest   --source data/raw/synthetic --reset
    lmo profile
    lmo quarantine --limit 20
    lmo verify-schema --source /path/to/real/lanl
    lmo lineage --event-uid <uid>
    lmo detect / alerts / explain / evaluate / decide / audit / pack / serve / demo
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path

from lmo.detect.run import (
    explain_alert,
    render_alert_table,
    render_explain,
    run_detect,
)
from lmo.errors import LmoError
from lmo.evaluate.metrics import DEFAULT_BUDGETS, evaluate, sweep
from lmo.evaluate.report import render_eval, write_report as write_eval_report
from lmo.generate.synth import GeneratorConfig, generate
from lmo.handoff import (
    export_parquet,
    import_parquet,
    load_case,
    pack_case,
    verify_pack,
    write_case,
)
from lmo.incidents import (
    get_incident,
    list_incidents,
    render_incident,
    render_incident_table,
)
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import profile, run_ingest, write_report
from lmo.ontology import query as oq
from lmo.ontology.build import build_graph, drop_graph, graph_is_stale
from lmo.schemas.raw import ALL_SCHEMAS, get_schema

DEFAULT_DB = "data/warehouse/lmo.duckdb"
DEFAULT_RAW = "data/raw/synthetic"


# ---------------------------------------------------------------------------


def cmd_generate(args: argparse.Namespace) -> int:
    cfg = GeneratorConfig.preset(args.preset, seed=args.seed)
    if args.days:
        cfg.n_days = args.days
    if not args.redteam:
        cfg.inject_redteam = False

    out = Path(args.out)
    print(f"generating preset={args.preset} seed={cfg.seed} -> {out}")
    manifest = generate(cfg, out)

    c = manifest["counts"]
    print(f"  auth   {c['auth']:>12,}  ({c['auth_redteam']:,} labelled)")
    for k in ("proc", "flows", "dns"):
        print(f"  {k:<7}{c[k]:>12,}")
    gt = manifest["ground_truth"]
    if gt:
        print(
            f"\n  campaign: {gt['victim_user']} on {gt['beachhead']}"
            f" -> stole {gt['stolen_admin']} -> objective {gt['objective']}"
        )
        print(f"  prevalence: {manifest['class_balance']['redteam_fraction']:.2e}")
    print(f"\n  manifest: {out / 'scenario.json'}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    with Warehouse(args.db, memory_limit=args.memory) as wh:
        report = run_ingest(
            wh,
            Path(args.source),
            defensive=not args.fast_parse,
            reset=args.reset,
            max_day=args.max_day,
        )
        print(report.render())
        prof = profile(wh)
        if args.report:
            write_report(report, prof, Path(args.report))
            print(f"\nreport written to {args.report}")
        return 0 if report.ok else 1


def cmd_profile(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        print(json.dumps(profile(wh), indent=2, default=str))
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        rows = wh.con.execute(
            """
            SELECT reason_code, count(*) AS n
            FROM quarantine GROUP BY 1 ORDER BY 2 DESC
            """
        ).fetchall()
        if not rows:
            print("quarantine is empty -- every raw row normalised cleanly.")
            return 0
        print("reason breakdown:")
        for code, n in rows:
            print(f"  {code:<20}{n:>10,}")
        print("\nsamples:")
        for r in wh.con.execute(
            """
            SELECT src_dataset, src_line_no, reason_code, reason_detail, raw_line
            FROM quarantine LIMIT ?
            """,
            [args.limit],
        ).fetchall():
            print(f"  [{r[0]}:{r[1]}] {r[2]} -- {r[3]}")
            print(f"      {r[4][:160]}")
    return 0


def cmd_verify_schema(args: argparse.Namespace) -> int:
    """Check the declared column layout against real files before a full run.

    Cheap insurance: the layouts in ``schemas/raw.py`` are transcribed from the
    dataset documentation, and a single transposed column would corrupt every
    downstream conclusion while leaving the pipeline apparently healthy.
    """
    source = Path(args.source)
    if not source.is_dir():
        raise LmoError(
            f"no such directory: {source}",
            "Point --source at the folder holding the LANL .txt.gz files.",
        )

    failures = 0
    checked = 0
    for name, schema in ALL_SCHEMAS.items():
        path = source / schema.filename
        if not path.exists():
            print(f"  {name:<10} SKIP   {schema.filename} not found")
            continue
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            line = fh.readline().rstrip("\n")
        if not line:
            print(f"  {name:<10} FAIL   {schema.filename} is empty")
            failures += 1
            continue
        checked += 1
        got = len(line.split(","))
        ok = got == schema.arity
        failures += not ok
        print(f"  {name:<10} {'OK  ' if ok else 'FAIL'}   "
              f"expected {schema.arity} fields, first line has {got}")
        print(f"             declared: {','.join(schema.columns)}")
        print(f"             actual:   {line[:120]}")
        print(f"             example:  {schema.example}")

    if not checked and not failures:
        raise LmoError(
            f"{source} contains none of the expected files",
            "Looked for: " + ", ".join(s.filename for s in ALL_SCHEMAS.values()),
        )
    if failures:
        print(f"\n{failures} dataset(s) do not match. Fix src/lmo/schemas/raw.py "
              f"-- it is the only place column order is declared.")
    return 1 if failures else 0


def cmd_lineage(args: argparse.Namespace) -> int:
    """Resolve a normalised event back to the raw line it came from."""
    from lmo.writeback.store import resolve_raw_line

    with Warehouse(args.db, read_only=True) as wh:
        if not args.source:
            row = wh.con.execute(
                """
                SELECT src_dataset, src_file, src_line_no, src_line_hash,
                       run_id, event_time, src_user_uid, src_endpoint, dst_endpoint
                FROM events WHERE event_uid = ?
                """,
                [args.event_uid],
            ).fetchone()
            if not row:
                raise LmoError(
                    f"no event with uid {args.event_uid!r}",
                    "Copy the id from an alert's contributing events.",
                )
            print(f"event      {args.event_uid}")
            print(f"  when     {row[5]}")
            print(f"  who      {row[6]}")
            print(f"  path     {row[7]} -> {row[8]}")
            print(f"  source   {row[0]} / {row[1]} line {row[2]}")
            print(f"  hash     {row[3]}")
            print(f"  run      {row[4]}")
            print("  raw      (pass --source to open the gzip and check the hash)")
            return 0
        got = resolve_raw_line(wh, args.event_uid, args.source)
        print(f"event      {got['event_uid']}")
        print(f"  source   {got['src_dataset']} / {got['src_file']} "
              f"line {got['src_line_no']}")
        print(f"  hash     {got['src_line_hash']}")
        if not got["locator_ok"]:
            print("  note     line number drifted; found by hash")
        print(f"  raw      {got['raw']}")
    return 0


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Ontology (Part 2)
# ---------------------------------------------------------------------------


def cmd_build_graph(args: argparse.Namespace) -> int:
    with Warehouse(args.db, memory_limit=args.memory) as wh:
        if args.reset:
            drop_graph(wh)
        report = build_graph(wh)
        print(report.render())
        if args.report:
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(
                json.dumps(report.as_dict(), indent=2), encoding="utf-8"
            )
            print(f"\nreport written to {args.report}")
    return 0


def cmd_graph_status(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        stale, detail = graph_is_stale(wh)
        print("STALE" if stale else "fresh", "--", detail)
        if not stale:
            for table in ("entity_user", "entity_host", "entity_session",
                          "edge_user_host", "edge_host_host"):
                print(f"  {table:<18}{wh.count(table):>12,}")
    return 1 if stale else 0


def cmd_show(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        prof = (oq.user_profile(wh, args.entity) if "@" in args.entity
                else oq.host_profile(wh, args.entity))
        print(prof.render())
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        rows = oq.timeline(wh, user=args.user, host=args.host,
                           start_sec=args.start, end_sec=args.end,
                           limit=args.limit)
        if not rows:
            print("nothing in this window")
            return 0
        print(f"{'time':<20}{'account':<16}{'from':<10}{'to':<10}"
              f"{'type':<18}{'what':<8}{'result'}")
        print("-" * 96)
        for r in rows:
            print(f"{str(r['event_time']):<20}{r['src_user_uid'] or '':<16}"
                  f"{r['src_endpoint'] or '':<10}{r['dst_endpoint'] or '':<10}"
                  f"{r['logon_type'] or '':<18}{r['activity_name'] or '':<8}"
                  f"{r['status'] or ''}")
        print(f"\n{len(rows)} event(s)")
    return 0


def cmd_neighbours(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        rows = oq.neighbours(wh, args.host, start_sec=args.start,
                             end_sec=args.end, limit=args.limit)
        if not rows:
            print("no neighbours in this window")
            return 0
        print(f"{'dir':<6}{'host':<12}{'events':>9}{'accounts':>10}  first seen")
        print("-" * 60)
        for r in rows:
            print(f"{r['direction']:<6}{r['other']:<12}{r['events']:>9,}"
                  f"{r['accounts']:>10,}  {r['first_seen']}")
    return 0


def cmd_paths(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        paths = oq.paths_between(wh, args.src, args.dst, start_sec=args.start,
                                 end_sec=args.end, max_hops=args.max_hops,
                                 user=args.user, limit=args.limit)
        print(oq.render_paths(paths))
    return 0


def cmd_corroborate(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        out = oq.corroborate(wh, time_sec=args.time, src_host=args.src,
                             dst_host=args.dst, window=args.window)
        print(json.dumps(out, indent=2, default=str))
    return 0 if out["corroborated"] else 1


def cmd_new_edges(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        rows = oq.first_time_edges(wh, start_sec=args.start, end_sec=args.end,
                                   limit=args.limit)
        print(f"{'first seen':<20}{'account':<16}{'role':<9}"
              f"{'host':<10}{'host role':<10}{'events':>8}")
        print("-" * 76)
        for r in rows:
            print(f"{str(r['first_seen']):<20}{r['user_uid']:<16}"
                  f"{r['account_role']:<9}{r['dst_host']:<10}"
                  f"{r['host_role']:<10}{r['n_total']:>8,}")
        print(f"\n{len(rows)} first-time account->host pair(s) in this window")
        print("Not a detection: benign drift produces most of these. "
              "Part 3 combines it with other signals.")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    with Warehouse(args.db, memory_limit=args.memory) as wh:
        report = run_detect(
            wh, start_day=args.start_day, end_day=args.end_day,
        )
        print(report.render())
        if args.report:
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(
                json.dumps(report.as_dict(), indent=2), encoding="utf-8"
            )
            print(f"\nreport written to {args.report}")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    from lmo.writeback.store import list_queue

    with Warehouse(args.db, read_only=True) as wh:
        rows = list_queue(
            wh, band=args.band, day=args.day, limit=args.limit,
            view=args.view,
        )
        print(render_alert_table(rows))
    return 0


def cmd_incidents(args: argparse.Namespace) -> int:
    gap_sec = int(args.gap_hours * 3600)
    with Warehouse(args.db, read_only=True) as wh:
        if args.incident_uid:
            print(render_incident(get_incident(
                wh, args.incident_uid, gap_sec=gap_sec,
            )))
            return 0
        rows = list_incidents(wh, gap_sec=gap_sec, limit=args.limit)
        print(render_incident_table(rows))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        print(render_explain(explain_alert(wh, args.alert_uid)))
    return 0


def _budgets_from_args(args: argparse.Namespace) -> list[int]:
    if getattr(args, "budget", None) is not None:
        return [args.budget]
    raw = getattr(args, "budgets", None)
    if raw:
        return [int(x.strip()) for x in raw.split(",") if x.strip()]
    return list(DEFAULT_BUDGETS)


def cmd_evaluate(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        report = evaluate(
            wh, Path(args.source), budgets=_budgets_from_args(args),
        )
        print(render_eval(report))
        if args.report:
            write_eval_report(report, Path(args.report))
            print(f"\nreport written to {args.report}")
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        report = sweep(
            wh, Path(args.source), budgets=_budgets_from_args(args),
        )
        print(render_eval(report))
        if args.report:
            write_eval_report(report, Path(args.report))
            print(f"\nreport written to {args.report}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from lmo.api.app import create_app

    # Probe before uvicorn binds: a missing warehouse is a user error, not a
    # crash inside the server process.
    Warehouse(args.db, read_only=True).close()
    app = create_app(args.db, source=args.source)
    extra = f"  source={args.source}" if args.source else ""
    print(
        f"serving {args.db} at http://{args.host}:{args.port}/{extra}",
        flush=True,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    from lmo.writeback.store import record_decision

    with Warehouse(args.db) as wh:
        row = record_decision(
            wh,
            alert_uid=args.alert_uid,
            action=args.action,
            note=args.note or "",
            analyst=args.analyst,
            event_uid=args.event_uid,
        )
        print(
            f"{row['decision_id']}  {row['action']}  alert={row['alert_uid']}"
        )
        if row["note"]:
            print(f"  {row['note']}")
    return 0


def cmd_pack(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        path = write_case(pack_case(wh, args.alert_uid), Path(args.out))
        print(f"wrote case {args.alert_uid} -> {path}")
    return 0


def cmd_export_parquet(args: argparse.Namespace) -> int:
    with Warehouse(args.db, read_only=True) as wh:
        info = export_parquet(wh, Path(args.out))
        print(
            f"parquet  events={info['n_events']:,}  "
            f"alerts={info['n_alerts']:,}  "
            f"files={info['n_parquet_files']:,}  out={info['out']}"
        )
    return 0


def cmd_import_parquet(args: argparse.Namespace) -> int:
    with Warehouse(args.db) as wh:
        info = import_parquet(wh, Path(args.source))
        print(
            f"import-parquet  rows={info['n_parquet_rows']:,}  "
            f"inserted={info['n_inserted']:,}  "
            f"duplicate={info['n_duplicate']:,}"
        )
    return 0


def cmd_verify_pack(args: argparse.Namespace) -> int:
    case = load_case(Path(args.case_path))
    with Warehouse(args.db, read_only=True) as wh:
        report = verify_pack(wh, case)
    print(
        f"verify-pack  alert={report['alert_uid']}  "
        f"{report['n_ok']}/{report['n_events']} events match"
    )
    if report["missing"]:
        print(f"  missing in warehouse: {len(report['missing'])}")
    if report["hash_mismatch"]:
        print(f"  hash mismatch: {len(report['hash_mismatch'])}")
    return 0 if report["ok"] else 2


def cmd_audit(args: argparse.Namespace) -> int:
    from lmo.writeback.store import list_audit

    with Warehouse(args.db, read_only=True) as wh:
        rows = list_audit(wh, limit=args.limit)
        if not rows:
            print("no decisions recorded")
            return 0
        print(
            f"{'when':<22}{'action':<18}{'analyst':<12} alert"
        )
        print("-" * 80)
        for r in rows:
            print(
                f"{str(r['created_at']):<22}{r['action']:<18}"
                f"{r['analyst']:<12} {r['alert_uid']}"
            )
            if r["note"]:
                print(f"  {r['note']}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Walk generate -> detect -> one judgement. Does not start the server."""
    from lmo.writeback.store import list_audit, list_queue, record_decision

    raw = Path(args.out)
    db = Path(args.warehouse)
    cfg = GeneratorConfig.preset(args.preset, seed=args.seed)
    if args.days:
        cfg.n_days = args.days

    print("== generate ==")
    generate(cfg, raw)

    with Warehouse(db) as wh:
        print("\n== ingest ==")
        report = run_ingest(wh, raw, reset=True)
        print(report.render())
        if not report.ok:
            return 1
        print("\n== build-graph ==")
        print(build_graph(wh).render())
        print("\n== detect ==")
        print(run_detect(wh).render())
        print("\n== evaluate (budget 25 / day) ==")
        print(render_eval(evaluate(wh, raw, budgets=[25])))
        print("\n== queue (view=all, top 3) ==")
        rows = list_queue(wh, limit=3, view="all")
        print(render_alert_table(rows))
        print("\n== incidents (same account, 4h gap) ==")
        print(render_incident_table(list_incidents(wh, limit=3)))
        if not rows:
            print("no alerts - nothing to explain or record")
            return 0
        uid = rows[0]["alert_uid"]
        print("\n== explain (top row) ==")
        print(render_explain(explain_alert(wh, uid)))
        print("\n== writeback (inconclusive - not a staged true_positive) ==")
        rec = record_decision(
            wh,
            alert_uid=uid,
            action="inconclusive",
            note="demo walkthrough; not a detection claim",
            analyst="demo",
        )
        print(f"{rec['decision_id']}  {rec['action']}")
        print("\n== audit ==")
        for r in list_audit(wh, limit=5):
            print(f"  {r['action']:<18} {r['alert_uid']}  {r['note']}")
        print("\n== pack (case JSON, no labels) ==")
        case_path = db.with_name("demo-case.json")
        write_case(pack_case(wh, uid), case_path)
        print(f"  {case_path}")
        checked = verify_pack(wh, load_case(case_path))
        print(f"  verify-pack {checked['n_ok']}/{checked['n_events']} ok")

    print(
        "\n== UI (not started) ==\n"
        f"  lmo --db {db} serve --source {raw}\n"
        "Tiny is for this walkthrough. Headline recall is README Part 3, "
        "seeds 2 and 3, not this world."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lmo",
        description="Lateral Movement Ontology -- ingest, graph, detect, evaluate",
    )
    p.add_argument("--db", default=DEFAULT_DB, help="DuckDB warehouse path")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="write a synthetic LANL-format dataset")
    g.add_argument("--preset", default="small",
                   choices=["tiny", "small", "medium", "large"])
    g.add_argument("--out", default=DEFAULT_RAW)
    g.add_argument("--seed", type=int, default=None)
    g.add_argument("--days", type=int, default=None)
    g.add_argument("--no-redteam", dest="redteam", action="store_false",
                   help="generate a clean world with no intrusion")
    g.set_defaults(func=cmd_generate, redteam=True)

    i = sub.add_parser("ingest", help="normalise raw files into the warehouse")
    i.add_argument("--source", default=DEFAULT_RAW)
    i.add_argument("--reset", action="store_true", help="drop tables first")
    i.add_argument("--fast-parse", action="store_true",
                   help="native CSV parsing; src_line_no becomes approximate")
    i.add_argument("--memory", default="3GB")
    i.add_argument("--report", default=None, help="write a JSON run report here")
    i.add_argument(
        "--max-day",
        type=int,
        default=None,
        help="keep events and labels with day_index <= N (0-based); omit for all days",
    )
    i.set_defaults(func=cmd_ingest)

    pr = sub.add_parser("profile", help="describe what is in the warehouse")
    pr.set_defaults(func=cmd_profile)

    q = sub.add_parser("quarantine", help="inspect rejected rows")
    q.add_argument("--limit", type=int, default=10)
    q.set_defaults(func=cmd_quarantine)

    v = sub.add_parser("verify-schema",
                       help="check declared columns against real files")
    v.add_argument("--source", required=True)
    v.set_defaults(func=cmd_verify_schema)

    bg = sub.add_parser("build-graph", help="build the ontology from events")
    bg.add_argument("--reset", action="store_true", help="drop graph tables first")
    bg.add_argument("--memory", default="3GB")
    bg.add_argument("--report", default=None)
    bg.set_defaults(func=cmd_build_graph)

    gs = sub.add_parser("graph-status", help="is the ontology current?")
    gs.set_defaults(func=cmd_graph_status)

    sh = sub.add_parser("show", help="profile one account or host")
    sh.add_argument("entity", help="'U00123@DOM1' or 'C00123'")
    sh.set_defaults(func=cmd_show)

    tl = sub.add_parser("timeline", help="events around an account or host")
    tl.add_argument("--user", default=None)
    tl.add_argument("--host", default=None)
    tl.add_argument("--start", type=int, required=True, help="dataset seconds")
    tl.add_argument("--end", type=int, required=True)
    tl.add_argument("--limit", type=int, default=oq.DEFAULT_LIMIT)
    tl.set_defaults(func=cmd_timeline)

    nb = sub.add_parser("neighbours", help="hosts one hop from this one")
    nb.add_argument("host")
    nb.add_argument("--start", type=int, required=True)
    nb.add_argument("--end", type=int, required=True)
    nb.add_argument("--limit", type=int, default=oq.DEFAULT_LIMIT)
    nb.set_defaults(func=cmd_neighbours)

    pt = sub.add_parser(
        "paths", help="time-ordered routes from one host to another")
    pt.add_argument("src")
    pt.add_argument("dst")
    pt.add_argument("--start", type=int, required=True)
    pt.add_argument("--end", type=int, required=True)
    pt.add_argument("--max-hops", type=int, default=oq.DEFAULT_MAX_HOPS)
    pt.add_argument("--user", default=None, help="restrict to one account")
    pt.add_argument("--limit", type=int, default=50)
    pt.set_defaults(func=cmd_paths)

    co = sub.add_parser(
        "corroborate", help="did flows or DNS agree with this authentication?")
    co.add_argument("--time", type=int, required=True)
    co.add_argument("--src", required=True)
    co.add_argument("--dst", required=True)
    co.add_argument("--window", type=int, default=oq.CORROBORATION_WINDOW)
    co.set_defaults(func=cmd_corroborate)

    ne = sub.add_parser(
        "new-edges", help="account->host pairs seen for the first time")
    ne.add_argument("--start", type=int, required=True)
    ne.add_argument("--end", type=int, required=True)
    ne.add_argument("--limit", type=int, default=oq.DEFAULT_LIMIT)
    ne.set_defaults(func=cmd_new_edges)

    dt = sub.add_parser("detect", help="score (account, source host, hour) units")
    dt.add_argument("--start-day", type=int, default=None)
    dt.add_argument("--end-day", type=int, default=None)
    dt.add_argument("--memory", default="3GB")
    dt.add_argument("--report", default=None)
    dt.set_defaults(func=cmd_detect)

    al = sub.add_parser("alerts", help="list scored alerts")
    al.add_argument("--band", default=None, choices=["high", "medium", "low"])
    al.add_argument("--day", type=int, default=None)
    al.add_argument("--limit", type=int, default=50)
    al.add_argument(
        "--view", default="open",
        choices=["open", "all", "confirmed", "dismissed"],
        help="open hides false positives (default)",
    )
    al.set_defaults(func=cmd_alerts)

    inc = sub.add_parser(
        "incidents",
        help="group hourly alerts for the same account within a time gap",
    )
    inc.add_argument("--gap-hours", type=float, default=4.0,
                     help="merge if the next hour starts within this many hours")
    inc.add_argument("--limit", type=int, default=20)
    inc.add_argument("--incident-uid", default=None)
    inc.set_defaults(func=cmd_incidents)

    ex = sub.add_parser(
        "explain", help="signals, contributing events, and lineage for one alert")
    ex.add_argument("--alert-uid", required=True)
    ex.set_defaults(func=cmd_explain)

    ev = sub.add_parser(
        "evaluate",
        help="stage recall at a fixed alert budget (labels never enter detect)",
    )
    ev.add_argument("--source", required=True,
                    help="raw directory (scenario.json or a LANL download)")
    ev.add_argument("--budget", type=int, default=None,
                    help="single budget per day; default is 10,25,50,100")
    ev.add_argument("--report", default=None)
    ev.set_defaults(func=cmd_evaluate)

    sw = sub.add_parser(
        "sweep", help="recall against alerts-per-day, layered vs naive")
    sw.add_argument("--source", required=True)
    sw.add_argument("--budgets", default="10,25,50,100")
    sw.add_argument("--report", default=None)
    sw.set_defaults(func=cmd_sweep)

    sv = sub.add_parser(
        "serve",
        help="API and analyst UI over a detected warehouse (writes decisions)",
    )
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument(
        "--source", default=None,
        help="raw directory, so the UI can open a hash-checked line",
    )
    sv.set_defaults(func=cmd_serve)

    de = sub.add_parser("decide", help="record an analyst judgement on an alert")
    de.add_argument("--alert-uid", required=True)
    de.add_argument(
        "--action", required=True,
        choices=["true_positive", "false_positive", "inconclusive"],
    )
    de.add_argument("--note", default="")
    de.add_argument("--analyst", default="local")
    de.add_argument("--event-uid", default=None)
    de.set_defaults(func=cmd_decide)

    au = sub.add_parser("audit", help="list recorded analyst judgements")
    au.add_argument("--limit", type=int, default=50)
    au.set_defaults(func=cmd_audit)

    pk = sub.add_parser(
        "pack",
        help="write one alert as a JSON case file (no labels)",
    )
    pk.add_argument("--alert-uid", required=True)
    pk.add_argument("--out", required=True, help="JSON path to write")
    pk.set_defaults(func=cmd_pack)

    xp = sub.add_parser(
        "export-parquet",
        help="write events partitioned by day_index (Hive layout, no Spark)",
    )
    xp.add_argument("--out", required=True, help="output directory")
    xp.set_defaults(func=cmd_export_parquet)

    ip = sub.add_parser(
        "import-parquet",
        help="load events from export-parquet; skip hashes already in the warehouse",
    )
    ip.add_argument("--source", required=True, help="directory export-parquet wrote")
    ip.set_defaults(func=cmd_import_parquet)

    vp = sub.add_parser(
        "verify-pack",
        help="check a case JSON against warehouse line hashes",
    )
    vp.add_argument(
        "--in",
        dest="case_path",
        required=True,
        help="JSON path from 'lmo pack --out'",
    )
    vp.set_defaults(func=cmd_verify_pack)

    dm = sub.add_parser(
        "demo",
        help="generate, ingest, graph, detect, evaluate, one inconclusive",
    )
    dm.add_argument("--preset", default="tiny",
                    choices=["tiny", "small", "medium", "large"])
    dm.add_argument("--out", default="data/raw/demo")
    dm.add_argument(
        "--warehouse", default="data/warehouse/demo.duckdb",
        help="DuckDB path; not the default lmo.duckdb, so a demo cannot wipe it",
    )
    dm.add_argument("--seed", type=int, default=7)
    dm.add_argument("--days", type=int, default=None)
    dm.set_defaults(func=cmd_demo)

    ln = sub.add_parser("lineage", help="trace an event back to its raw line")
    ln.add_argument("--event-uid", required=True)
    ln.add_argument("--source", default=None,
                    help="raw directory, to print the original line")
    ln.set_defaults(func=cmd_lineage)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except LmoError as exc:
        # Printed as a plain message, not a traceback: this is something the
        # reader typed, not something that broke inside the program. Genuine
        # defects still raise through and still print a traceback, which is what
        # keeps a traceback worth reading.
        print(f"error: {exc.problem}", file=sys.stderr)
        if exc.fix:
            print(f"       {exc.fix}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
