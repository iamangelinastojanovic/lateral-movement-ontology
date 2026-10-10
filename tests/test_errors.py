"""Failure modes a person actually hits, and what they are told about them.

Each of these started as a real defect found by running the commands in the
wrong order or with the wrong arguments -- the way someone using this for the
first time would. They are tests rather than fixed-and-forgotten because a bad
error message is invisible to every other kind of check: the program still
"works", it just lies to whoever is reading it.
"""

from __future__ import annotations

import gzip

import pytest

from lmo.cli import main
from lmo.errors import LmoError
from lmo.generate.synth import P_PEER_TOTAL, GeneratorConfig, generate
from lmo.ingest.engine import Warehouse
from lmo.ingest.pipeline import run_ingest


# ---------------------------------------------------------------------------
# Warehouse
# ---------------------------------------------------------------------------


def test_opening_a_missing_warehouse_read_only_explains_itself(tmp_path):
    """'lmo profile' before 'lmo ingest' used to print a DuckDB traceback."""
    with pytest.raises(LmoError) as exc:
        Warehouse(tmp_path / "nothing.duckdb", read_only=True)
    assert "no warehouse" in exc.value.problem
    assert "lmo ingest" in exc.value.fix


def test_creating_a_warehouse_for_writing_still_works(tmp_path):
    """The check above must not break the normal case of creating one."""
    with Warehouse(tmp_path / "new.duckdb") as wh:
        assert wh.count("events") == 0


def test_a_locked_warehouse_explains_itself(tmp_path):
    """A second writer used to dump a DuckDB IOError traceback."""
    path = tmp_path / "locked.duckdb"
    first = Warehouse(path)
    second = None
    try:
        try:
            second = Warehouse(path)
        except LmoError as exc:
            assert "locked" in exc.problem.lower()
            assert "serve" in (exc.fix or "").lower()
            return
        pytest.skip("this DuckDB build allows two writers in one process")
    finally:
        if second is not None:
            second.close()
        first.close()


# ---------------------------------------------------------------------------
# Ingest source directory
# ---------------------------------------------------------------------------


def test_missing_source_directory_is_not_reported_as_lost_rows(warehouse, tmp_path):
    """The important half of this test is what the message must NOT say.

    An empty run used to report "rows disappeared between input and output",
    which sent the reader hunting a pipeline bug when they had simply mistyped a
    path. Reconciliation is about rows that were read and then lost; nothing was
    read here.
    """
    with pytest.raises(LmoError) as exc:
        run_ingest(warehouse, tmp_path / "does-not-exist")
    assert "no such directory" in exc.value.problem
    assert "disappear" not in str(exc.value).lower()


def test_empty_source_directory_lists_what_was_expected(warehouse, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(LmoError) as exc:
        run_ingest(warehouse, empty)
    assert "none of the expected files" in exc.value.problem
    assert "auth.txt.gz" in exc.value.fix


def test_a_directory_with_only_some_files_still_ingests(warehouse, tmp_path):
    """Partial input is legitimate -- auth alone is enough to work with."""
    partial = tmp_path / "partial"
    partial.mkdir()
    with gzip.open(partial / "auth.txt.gz", "wt", newline="\n",
                   encoding="utf-8") as fh:
        fh.write("1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n")
    report = run_ingest(warehouse, partial)
    assert report.ok
    assert report.total_out == 1


# ---------------------------------------------------------------------------
# Generator configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, value, expected_phrase",
    [
        ("n_days", 0, "n_days"),
        ("n_users", 0, "n_users"),
        ("n_servers", 0, "n_servers"),
        ("n_servers", 500, "room for workstations"),
        ("p_new_host_drift", 0.4, "p_new_host_drift"),
        ("p_failure", 1.5, "p_failure"),
        ("mean_events_per_user_day", 0, "mean_events_per_user_day"),
        ("n_crown_jewels", 999, "n_crown_jewels"),
        ("admin_maintenance_hosts", (20, 5), "increasing"),
        ("redteam_start_day", 99, "collection window"),
    ],
)
def test_bad_settings_name_the_setting(field, value, expected_phrase, tmp_path):
    """numpy's "low >= high" names an internal variable, not the knob turned."""
    cfg = GeneratorConfig.preset("tiny")
    setattr(cfg, field, value)
    with pytest.raises(LmoError) as exc:
        generate(cfg, tmp_path)
    assert expected_phrase in str(exc.value)


def test_drift_limit_matches_the_share_it_is_carved_from(tmp_path):
    """The bound is documented as a constant, so it cannot silently drift."""
    cfg = GeneratorConfig.preset("tiny")
    cfg.p_new_host_drift = P_PEER_TOTAL
    with pytest.raises(LmoError):
        generate(cfg, tmp_path)

    cfg.p_new_host_drift = P_PEER_TOTAL - 0.001
    generate(cfg, tmp_path)  # must not raise


def test_every_preset_is_valid():
    for name in ("tiny", "small", "medium", "large"):
        GeneratorConfig.preset(name).validate()


# ---------------------------------------------------------------------------
# CLI exit codes and output
# ---------------------------------------------------------------------------


def test_cli_reports_user_errors_without_a_traceback(tmp_path, capsys):
    code = main(["--db", str(tmp_path / "none.duckdb"), "profile"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.err.startswith("error: ")
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_cli_verify_schema_rejects_a_missing_directory(tmp_path, capsys):
    code = main(["verify-schema", "--source", str(tmp_path / "nope")])
    assert code == 2
    assert "no such directory" in capsys.readouterr().err


def test_cli_verify_schema_accepts_generated_data(tiny_dataset, capsys):
    code = main(["verify-schema", "--source", str(tiny_dataset)])
    out = capsys.readouterr().out
    assert code == 0
    assert "FAIL" not in out
    assert out.count("OK") == 5


def test_cli_happy_path_end_to_end(tmp_path, capsys):
    """generate -> ingest -> profile, through the CLI the way a user runs it."""
    raw = tmp_path / "raw"
    db = tmp_path / "w.duckdb"

    assert main(["generate", "--preset", "tiny", "--out", str(raw),
                 "--seed", "77"]) == 0
    assert main(["--db", str(db), "ingest", "--source", str(raw),
                 "--reset"]) == 0
    assert main(["--db", str(db), "profile"]) == 0

    out = capsys.readouterr().out
    assert "campaign:" in out
    assert '"label_join_rate": 1.0' in out


def test_cli_quarantine_on_a_clean_run_says_so(tmp_path, capsys):
    raw = tmp_path / "raw"
    db = tmp_path / "w.duckdb"
    main(["generate", "--preset", "tiny", "--out", str(raw)])
    main(["--db", str(db), "ingest", "--source", str(raw), "--reset"])
    capsys.readouterr()

    assert main(["--db", str(db), "quarantine"]) == 0
    assert "quarantine is empty" in capsys.readouterr().out
