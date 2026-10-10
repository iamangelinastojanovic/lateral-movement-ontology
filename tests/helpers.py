"""Shared helpers for the test suite.

These live here rather than in ``conftest.py`` on purpose. ``conftest.py`` is a
file pytest loads by itself, for fixtures and hooks; importing functions *from*
it is a well-known trap, because whether ``from conftest import ...`` resolves
depends on how pytest was invoked and on whether ``tests/`` is a package. It
worked under one developer's ``PYTHONPATH`` and broke for everyone else --
which is the whole reason this module exists.

Fixtures stay in ``conftest.py``. Plain functions live here and are imported
normally.
"""

from __future__ import annotations

import gzip
import shutil
from pathlib import Path


def read_gz(path: Path) -> list[str]:
    """Read a gzipped text file into a list of lines, blank lines dropped.

    The explicit ``encoding`` is not decoration: without it Python uses the
    platform default -- UTF-8 on Linux, usually cp1252 on Windows -- and the
    same file reads differently on the two.
    """
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip()]


def append_gz(path: Path, lines: list[str]) -> None:
    """Append raw lines to a gzipped file by rewriting it.

    Used to bolt deliberately malformed rows onto a generated dataset, so the
    quarantine path can be tested against input the generator would never
    produce.
    """
    existing = read_gz(path)
    with gzip.open(path, "wt", newline="\n", encoding="utf-8") as fh:
        fh.write("\n".join(existing + lines) + "\n")


def with_extra_auth(src: Path, dest: Path, line: str | None = None) -> Path:
    """Copy a dataset and add one authentication the original files do not have.

    Second ingest of the *same* gzip is now a no-op (line-hash skip). Staleness
    tests need a genuinely new row, not a clone of the warehouse.
    """
    shutil.copytree(src, dest)
    extra = line or (
        "3,U99999@DOM1,U99999@DOM1,C99999,C00001,Kerberos,Network,LogOn,Success"
    )
    append_gz(dest / "auth.txt.gz", [extra])
    return dest
