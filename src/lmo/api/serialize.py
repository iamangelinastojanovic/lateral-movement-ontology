"""Turn warehouse rows into JSON the UI can render.

DuckDB returns datetime objects and list columns. FastAPI's default encoder
does not know about either, and a 500 from a successful query is the kind of
failure that looks like the detector broke.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

from lmo.ontology.query import Profile


def jsonable(obj):
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, Profile):
        return {
            "kind": obj.kind,
            "key": obj.key,
            "attributes": jsonable(obj.attributes),
            "relationships": jsonable(obj.relationships),
        }
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(x) for x in obj]
    if hasattr(obj, "item"):
        try:
            return jsonable(obj.item())
        except (ValueError, AttributeError):
            pass
    return str(obj)


def parse_signals(raw) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): v for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def alert_payload(row: dict) -> dict:
    out = jsonable(row)
    out["signals"] = parse_signals(row.get("signals_json"))
    return out
