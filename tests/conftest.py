"""Fixtures shared across the test suite.

Only fixtures belong here -- pytest loads this file on its own. Plain helper
functions live in ``helpers.py`` and are imported normally; see the note at the
top of that module for why the distinction matters.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lmo.generate.synth import GeneratorConfig, generate
from lmo.ingest.engine import Warehouse


@pytest.fixture(scope="session")
def tiny_dataset(tmp_path_factory) -> Path:
    """A small generated world, shared across the session.

    Session-scoped because generating it is the slowest thing in the suite and
    nothing mutates it -- the tests that need dirty input copy it first.
    """
    out = tmp_path_factory.mktemp("raw")
    cfg = GeneratorConfig.preset("tiny", seed=1234)
    generate(cfg, out)
    return out


@pytest.fixture
def warehouse() -> Warehouse:
    """An empty in-memory warehouse, torn down after each test."""
    wh = Warehouse(":memory:")
    yield wh
    wh.close()
