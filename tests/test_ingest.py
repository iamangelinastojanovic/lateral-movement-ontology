"""Normalisation, quarantine, reconciliation and lineage."""

from __future__ import annotations

import gzip
import shutil

import pytest

from helpers import append_gz
from lmo.ingest.engine import Warehouse
from lmo.ingest.normalize import ingest_dataset
from lmo.ingest.pipeline import profile, run_ingest
from lmo.schemas.normalized import ReasonCode


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_full_ingest_reconciles(warehouse, tiny_dataset):
    report = run_ingest(warehouse, tiny_dataset)
    assert report.ok
    for s in report.stats:
        assert s.reconciled, f"{s.dataset} lost rows"
    assert report.total_in == (
        report.total_out
        + report.total_quarantined
        + report.total_beyond
        + report.total_duplicate
    )
    assert report.total_out > 0


def test_labels_join_onto_events(warehouse, tiny_dataset):
    """The single most important invariant in Part 1.

    Everything Part 3 reports about detection quality is computed through this
    join. A join rate below 1.0 means some red-team activity is unreachable from
    the event table, and every recall figure would be quietly wrong.
    """
    run_ingest(warehouse, tiny_dataset)
    prof = profile(warehouse)
    assert prof["labels"] > 0
    assert prof["label_join_rate"] == 1.0


def test_run_is_recorded(warehouse, tiny_dataset):
    report = run_ingest(warehouse, tiny_dataset)
    rows = warehouse.sql(
        "SELECT run_id, ok, schema_version FROM ingest_runs WHERE run_id = ?",
        [report.run_id],
    )
    assert len(rows) == 1
    assert rows[0][1] is True


def test_reset_clears_previous_events(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    first = warehouse.count("events")
    run_ingest(warehouse, tiny_dataset, reset=True)
    assert warehouse.count("events") == first


def test_ingesting_twice_without_reset_is_idempotent(warehouse, tiny_dataset):
    """A second pass over the same gzip used to clone every event.

    Detection then scored two copies of the same hour. Skipping by line hash
    keeps reconciliation honest and leaves the warehouse the same size.
    """
    run_ingest(warehouse, tiny_dataset)
    first = warehouse.count("events")
    second = run_ingest(warehouse, tiny_dataset)
    assert warehouse.count("events") == first
    assert second.ok
    assert second.total_out == 0
    assert second.total_duplicate > 0


# ---------------------------------------------------------------------------
# Normalisation correctness
# ---------------------------------------------------------------------------


def test_user_is_split_into_name_and_domain(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    rows = warehouse.sql(
        """
        SELECT src_user_uid, src_user_name, src_user_domain
        FROM events WHERE src_dataset = 'auth' AND src_user_domain IS NOT NULL
        LIMIT 5
        """
    )
    assert rows
    for uid, name, domain in rows:
        assert uid == f"{name}@{domain}"


def test_derived_time_columns_agree_with_time_sec(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    bad = warehouse.sql(
        """
        SELECT count(*) FROM events
        WHERE day_index   <> ((time_sec - 1) // 86400)
           OR hour_of_day <> (((time_sec - 1) % 86400) // 3600)
           OR event_time  <> (SELECT min(event_time) FROM events)
                             + INTERVAL (time_sec - (SELECT min(time_sec) FROM events)) SECOND
        """
    )[0][0]
    assert bad == 0


def test_epoch_anchor_puts_day_zero_on_a_monday(warehouse, tiny_dataset):
    """``is_weekend`` is computed from day_index, so the anchor must be a Monday."""
    run_ingest(warehouse, tiny_dataset)
    mismatched = warehouse.sql(
        """
        SELECT count(*) FROM events
        WHERE is_weekend <> (dayofweek(event_time) IN (0, 6))
        """
    )[0][0]
    assert mismatched == 0


def test_status_is_mapped_to_ocsf_ids(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    rows = dict(warehouse.sql(
        """
        SELECT status, any_value(status_id) FROM events
        WHERE src_dataset = 'auth' AND status IS NOT NULL GROUP BY 1
        """
    ))
    assert rows.get("Success") == 1
    assert rows.get("Fail") == 2


def test_self_auth_flag(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    wrong = warehouse.sql(
        """
        SELECT count(*) FROM events
        WHERE src_dataset = 'auth'
          AND is_self_auth <> (src_endpoint = dst_endpoint)
        """
    )[0][0]
    assert wrong == 0


def test_question_mark_becomes_null_not_a_host(warehouse, tmp_path):
    """'?' means 'not recorded'. Left as a string it becomes a phantom host
    sitting at the centre of the graph, connected to everything."""
    raw = tmp_path / "auth.txt.gz"
    with gzip.open(raw, "wt", newline="\n", encoding="utf-8") as fh:
        fh.write("5,U1@DOM1,U1@DOM1,C1,C2,?,Network,LogOn,Success\n")
    run_id = warehouse.new_run_id()
    ingest_dataset(warehouse, "auth", raw, run_id)

    assert warehouse.sql("SELECT count(*) FROM events WHERE auth_protocol = '?'")[0][0] == 0
    assert warehouse.sql("SELECT auth_protocol FROM events")[0][0] is None
    assert warehouse.sql(
        "SELECT count(*) FROM events WHERE src_endpoint = '?' OR dst_endpoint = '?'"
    )[0][0] == 0


def test_machine_and_anonymous_accounts_are_flagged(warehouse, tmp_path):
    raw = tmp_path / "auth.txt.gz"
    with gzip.open(raw, "wt", newline="\n", encoding="utf-8") as fh:
        fh.write("1,C99$@DOM1,C99$@DOM1,C99,C1,Kerberos,Service,LogOn,Success\n")
        fh.write("2,ANONYMOUS LOGON@C5,ANONYMOUS LOGON@C5,C5,C6,NTLM,Network,LogOn,Success\n")
    ingest_dataset(warehouse, "auth", raw, warehouse.new_run_id())
    rows = warehouse.sql(
        "SELECT is_machine_account, is_anonymous FROM events ORDER BY time_sec"
    )
    assert rows[0] == (True, False)
    assert rows[1] == (False, True)


def test_labels_never_leak_into_the_event_table(warehouse, tiny_dataset):
    """No column on ``events`` may reveal whether a row is red-team activity.

    If one did, any model trained downstream would learn it and every metric
    would be fiction.
    """
    run_ingest(warehouse, tiny_dataset)
    columns = {r[1] for r in warehouse.sql("PRAGMA table_info('events')")}
    for forbidden in ("label", "is_redteam", "malicious", "ground_truth"):
        assert not any(forbidden in c.lower() for c in columns)
    assert warehouse.sql(
        "SELECT count(*) FROM events WHERE src_dataset = 'redteam'"
    )[0][0] == 0


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------


@pytest.fixture
def dirty_dataset(tiny_dataset, tmp_path):
    """A copy of the tiny world with deliberately broken rows appended."""
    dst = tmp_path / "dirty"
    shutil.copytree(tiny_dataset, dst)
    append_gz(
        dst / "auth.txt.gz",
        [
            "900,U1@DOM1,U1@DOM1,C1",                                    # short
            "901,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success,X",  # long
            "notatime,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
            "-5,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",   # negative
            "99999999999,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
            "902,U1@DOM1,U1@DOM1,,C2,Kerberos,Network,LogOn,Success",    # no src host
            "903,?,?,C1,C2,Kerberos,Network,LogOn,Success",              # no user
        ],
    )
    return dst


def test_bad_rows_are_quarantined_not_dropped(warehouse, dirty_dataset):
    report = run_ingest(warehouse, dirty_dataset)
    assert report.ok, "reconciliation must still hold with dirty input"
    assert report.total_quarantined == 7


def test_quarantine_reasons_are_specific(warehouse, dirty_dataset):
    run_ingest(warehouse, dirty_dataset)
    reasons = dict(warehouse.sql(
        "SELECT reason_code, count(*) FROM quarantine GROUP BY 1"
    ))
    assert reasons.get(ReasonCode.WRONG_ARITY) == 2
    assert reasons.get(ReasonCode.BAD_TIME) == 3
    assert reasons.get(ReasonCode.EMPTY_KEY_FIELD) == 2


def test_quarantine_keeps_the_verbatim_line(warehouse, dirty_dataset):
    run_ingest(warehouse, dirty_dataset)
    row = warehouse.sql(
        "SELECT raw_line FROM quarantine WHERE reason_code = ? LIMIT 1",
        [ReasonCode.WRONG_ARITY],
    )[0][0]
    assert row.startswith("900,") or row.startswith("901,")


# ---------------------------------------------------------------------------
# Lineage
# ---------------------------------------------------------------------------


def test_every_event_carries_full_lineage(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    incomplete = warehouse.sql(
        """
        SELECT count(*) FROM events
        WHERE src_dataset IS NULL OR src_file IS NULL
           OR src_line_no IS NULL OR src_line_hash IS NULL
           OR run_id IS NULL OR schema_version IS NULL
        """
    )[0][0]
    assert incomplete == 0


def test_line_numbers_resolve_to_the_original_line(warehouse, tiny_dataset):
    """Walk the lineage backwards the way the Part 5 UI button will."""
    run_ingest(warehouse, tiny_dataset)
    samples = warehouse.sql(
        """
        SELECT src_file, src_line_no, src_line_hash, src_endpoint, dst_endpoint
        FROM events WHERE src_dataset = 'auth'
        ORDER BY event_uid LIMIT 25
        """
    )
    with gzip.open(tiny_dataset / "auth.txt.gz", "rt", encoding="utf-8") as fh:
        lines = [ln.rstrip("\n") for ln in fh]

    import hashlib

    for _, line_no, line_hash, src, dst in samples:
        raw = lines[line_no - 1]
        assert hashlib.md5(raw.encode()).hexdigest() == line_hash
        fields = raw.split(",")
        assert fields[3] == src and fields[4] == dst


def test_event_uid_is_stable_across_runs(warehouse, tiny_dataset):
    """Re-ingesting the same file must produce the same ids.

    Part 5 lets an analyst attach a decision to an event. If ids churned on
    every run, those decisions would detach from what they were about.
    """
    run_ingest(warehouse, tiny_dataset)
    first = {r[0] for r in warehouse.sql(
        "SELECT event_uid FROM events ORDER BY event_uid LIMIT 500"
    )}
    run_ingest(warehouse, tiny_dataset, reset=True)
    second = {r[0] for r in warehouse.sql(
        "SELECT event_uid FROM events ORDER BY event_uid LIMIT 500"
    )}
    assert first == second


def test_event_uid_is_unique(warehouse, tiny_dataset):
    run_ingest(warehouse, tiny_dataset)
    total, distinct = warehouse.sql(
        "SELECT count(*), count(DISTINCT event_uid) FROM events"
    )[0]
    assert total == distinct


# ---------------------------------------------------------------------------
# Parse modes
# ---------------------------------------------------------------------------


def test_fast_parse_does_not_silently_drop_malformed_rows(dirty_dataset):
    """The fast path used to make reconciliation vacuous.

    DuckDB's ``ignore_errors`` discards unparseable lines before the scan
    returns, so ``rows_in`` was already the post-drop count. Input and output
    then agreed -- both having lost the same rows -- and the run was reported as
    reconciled. That is the exact failure the invariant exists to catch, hidden
    inside the mode the README recommends for the full 12 GB dataset.

    Both modes must now account for every line in the file.
    """
    with Warehouse(":memory:") as slow, Warehouse(":memory:") as fast:
        a = run_ingest(slow, dirty_dataset, defensive=True)
        b = run_ingest(fast, dirty_dataset, defensive=False)

    assert a.ok and b.ok
    assert a.total_in == b.total_in, "the two modes disagree on the line count"
    assert a.total_quarantined == b.total_quarantined == 7
    assert b.total_in == (
        b.total_out + b.total_quarantined + b.total_beyond + b.total_duplicate
    )


def test_fast_parse_quarantine_keeps_true_line_numbers(dirty_dataset):
    """Rejects come back from DuckDB with real file positions, not ordinals."""
    with Warehouse(":memory:") as wh:
        run_ingest(wh, dirty_dataset, defensive=False)
        rows = wh.sql(
            """
            SELECT src_line_no, raw_line FROM quarantine
            WHERE src_dataset = 'auth' ORDER BY src_line_no
            """
        )
    assert rows
    for line_no, raw in rows:
        assert line_no > 0
        assert raw.strip(), "the offending line must be preserved verbatim"


def test_fast_parse_produces_the_same_events(tiny_dataset):
    """The fast path may weaken line numbers, but must not change the data."""
    with Warehouse(":memory:") as a, Warehouse(":memory:") as b:
        run_ingest(a, tiny_dataset, defensive=True)
        run_ingest(b, tiny_dataset, defensive=False)

        def fingerprint(wh):
            return wh.sql(
                """
                SELECT src_dataset, count(*), sum(time_sec),
                       count(DISTINCT src_endpoint), count(DISTINCT dst_endpoint)
                FROM events GROUP BY 1 ORDER BY 1
                """
            )

        assert fingerprint(a) == fingerprint(b)


# ---------------------------------------------------------------------------
# Text encoding
# ---------------------------------------------------------------------------


def test_non_ascii_values_survive_a_round_trip(warehouse, tmp_path):
    """Guards every text file operation against the platform's default encoding.

    ``gzip.open(path, "rt")`` without an explicit ``encoding`` uses whatever the
    operating system prefers: UTF-8 on Linux, usually cp1252 on Windows. The
    project ran clean for weeks because the LANL data is pure ASCII, where the
    two agree -- the difference only appears on the first non-ASCII byte, and
    then only on one platform. That is the worst shape a defect can have: it
    cannot be reproduced by whoever did not hit it.

    This test puts a non-ASCII account name through the whole path -- gzip
    write, DuckDB read, normalisation, read back -- so the assumption is checked
    rather than merely held.
    """
    user = "Uček@DOM1"
    raw = tmp_path / "auth.txt.gz"
    with gzip.open(raw, "wt", newline="\n", encoding="utf-8") as fh:
        fh.write(f"1,{user},{user},C1,C2,Kerberos,Network,LogOn,Success\n")

    ingest_dataset(warehouse, "auth", raw, warehouse.new_run_id())

    got = warehouse.sql("SELECT src_user_uid, src_user_name FROM events")
    assert got == [(user, "Uček")]

    # DuckDB read the file above. The lineage command reads it again through
    # Python's gzip, which is the call that actually carries the platform
    # default -- so it has to be exercised too, and by content rather than by
    # "did it raise": cp1252 does not raise on UTF-8 bytes, it silently returns
    # the wrong characters.
    with gzip.open(raw, "rt", encoding="utf-8") as fh:
        assert user in fh.readline()


def test_scenario_manifest_round_trips_as_utf8(tmp_path):
    """The manifest is written as UTF-8, so it must be read back as UTF-8.

    Writing with an explicit encoding and reading with the platform default is
    the same bug wearing a different hat.
    """
    import json

    from lmo.generate.synth import GeneratorConfig, generate

    generate(GeneratorConfig.preset("tiny", seed=3), tmp_path)
    manifest = json.loads(
        (tmp_path / "scenario.json").read_text(encoding="utf-8")
    )
    assert manifest["counts"]["auth"] > 0


def test_lineage_command_reads_non_ascii_raw_lines(tmp_path, capsys):
    """``lmo lineage`` prints the original line by reading the file in Python.

    That read carries the platform's default encoding. On Windows (cp1252) a
    UTF-8 byte does not raise -- it decodes to the wrong character -- so the
    assertion has to be on the text, not on the absence of an exception.
    """
    from lmo.cli import main

    user = "Uček@DOM1"
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    with gzip.open(raw_dir / "auth.txt.gz", "wt", newline="\n",
                   encoding="utf-8") as fh:
        fh.write(f"1,{user},{user},C1,C2,Kerberos,Network,LogOn,Success\n")

    db = tmp_path / "w.duckdb"
    assert main(["--db", str(db), "ingest", "--source", str(raw_dir),
                 "--reset"]) == 0
    capsys.readouterr()

    with Warehouse(db, read_only=True) as wh:
        uid = wh.sql("SELECT event_uid FROM events")[0][0]

    assert main(["--db", str(db), "lineage", "--event-uid", uid,
                 "--source", str(raw_dir)]) == 0
    out = capsys.readouterr().out
    assert user in out, "the raw line came back mangled by the default encoding"
