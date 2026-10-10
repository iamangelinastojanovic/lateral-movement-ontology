"""Interview packet: python -m lmo, demo walkthrough, architecture doc."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from lmo.cli import main

DOCS = Path(__file__).resolve().parents[1] / "docs"


def test_python_module_help_mentions_demo():
    proc = subprocess.run(
        [sys.executable, "-m", "lmo", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "demo" in proc.stdout


def test_demo_tiny_walkthrough(tmp_path, capsys):
    raw = tmp_path / "raw"
    db = tmp_path / "w.duckdb"
    code = main([
        "demo",
        "--preset", "tiny",
        "--out", str(raw),
        "--warehouse", str(db),
        "--seed", "7",
    ])
    assert code == 0
    out = capsys.readouterr().out
    assert "== generate ==" in out
    assert "== detect ==" in out
    assert "== evaluate (budget 25 / day) ==" in out
    assert "== audit ==" in out
    assert "== pack (case JSON, no labels) ==" in out
    assert "== incidents (same account, 4h gap) ==" in out
    assert "verify-pack" in out
    assert "inconclusive" in out
    assert "demo walkthrough; not a detection claim" in out
    assert "UI (not started)" in out
    assert db.exists()
    assert db.with_name("demo-case.json").exists()


def test_architecture_doc_has_mermaid_flowchart():
    text = (DOCS / "architecture.md").read_text(encoding="utf-8")
    assert "```mermaid" in text
    assert "flowchart" in text
    assert "evaluate" in text.lower()
    assert "redteam_labels" in text
