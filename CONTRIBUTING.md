# Contributing

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -q
```

Do not delete or "clean" `.venv` by hand. Do not `--reset` a warehouse you
did not create; tests use `tmp_path` / `:memory:`.

`redteam` labels may be read only under `src/lmo/evaluate/`.
`detect/`, `api/`, `web/`, `writeback/`, `handoff.py`, and `incidents.py` must
not mention that table.

CLI `--help` text must stay ASCII (Windows cp1252).

Analyst decisions are not labels and must not change `ScoreConfig`.

Part 3 synthetic recall numbers are held-out seeds 2 and 3. Do not retune
weights on LANL or on a tiny demo to make those tables move.

The real LANL runbook is [`docs/lanl-real.md`](docs/lanl-real.md).
