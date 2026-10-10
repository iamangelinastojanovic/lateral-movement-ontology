"""HTTP entry points. Investigation wraps existing functions; writeback is new."""

from __future__ import annotations

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field

from lmo.api.serialize import alert_payload, jsonable
from lmo.detect.run import explain_alert
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse
from lmo.ontology import query as oq
from lmo.ontology.build import graph_is_stale
from lmo.handoff import pack_case
from lmo.incidents import get_incident, list_incidents
from lmo.writeback.store import (
    decisions_for_entity,
    list_audit,
    list_history,
    list_queue,
    record_decision,
    resolve_raw_line,
)

MAX_LIMIT = 500


def _locked(request: Request, fn, *args, **kwargs):
    with request.app.state.lock:
        return fn(request.app.state.wh, *args, **kwargs)


def _clamp_limit(limit: int, default: int = 50) -> int:
    if limit < 1:
        raise LmoError("limit must be at least 1", "Pass a positive limit.")
    return min(limit, MAX_LIMIT) if limit else default


def _health(wh: Warehouse) -> dict:
    stale, detail = graph_is_stale(wh)
    tables = {
        r[0]
        for r in wh.con.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
    }
    n_events = wh.count("events") if "events" in tables else 0
    n_alerts = wh.count("alerts") if "alerts" in tables else 0
    n_decisions = wh.count("decisions") if "decisions" in tables else 0
    return {
        "ok": (not stale) and n_alerts > 0,
        "graph_stale": stale,
        "graph_detail": detail,
        "n_alerts": n_alerts,
        "n_events": n_events,
        "n_decisions": n_decisions,
    }


class DecisionIn(BaseModel):
    action: str
    note: str = ""
    analyst: str = "local"
    event_uid: str | None = Field(default=None)


def _queue_payload(row: dict) -> dict:
    dec = row.get("decision")
    body = alert_payload({k: v for k, v in row.items() if k != "decision"})
    body["decision"] = jsonable(dec)
    return body


def register_routes(app: FastAPI) -> None:
    @app.get("/api/health")
    def health(request: Request) -> dict:
        return _locked(request, _health)

    @app.get("/api/alerts")
    def alerts(
        request: Request,
        band: str | None = None,
        day: int | None = None,
        limit: int = 50,
        offset: int = 0,
        view: str = "open",
    ) -> list[dict]:
        rows = _locked(
            request,
            list_queue,
            band=band,
            day=day,
            limit=_clamp_limit(limit),
            offset=offset,
            view=view,
        )
        return [_queue_payload(r) for r in rows]

    @app.get("/api/incidents")
    def incidents(
        request: Request,
        gap_hours: float = 4.0,
        limit: int = 50,
    ) -> list[dict]:
        gap_sec = int(gap_hours * 3600)
        return jsonable(
            _locked(
                request,
                list_incidents,
                gap_sec=gap_sec,
                limit=_clamp_limit(limit),
            )
        )

    @app.get("/api/incidents/{uid}")
    def incident_detail(
        request: Request,
        uid: str,
        gap_hours: float = 4.0,
    ) -> dict:
        gap_sec = int(gap_hours * 3600)
        return jsonable(
            _locked(request, get_incident, uid, gap_sec=gap_sec)
        )

    @app.get("/api/alerts/{uid}")
    def alert_detail(request: Request, uid: str) -> dict:
        def _load(wh):
            payload = explain_alert(wh, uid)
            payload["history"] = list_history(wh, uid)
            payload["decision"] = (
                payload["history"][0] if payload["history"] else None
            )
            return payload

        payload = _locked(request, _load)
        return {
            "alert": alert_payload(payload["alert"]),
            "signals": jsonable(payload["signals"]),
            "events": jsonable(payload["events"]),
            "decision": jsonable(payload["decision"]),
            "history": jsonable(payload["history"]),
        }

    @app.post("/api/alerts/{uid}/decisions")
    def post_decision(request: Request, uid: str, body: DecisionIn) -> dict:
        return jsonable(
            _locked(
                request,
                record_decision,
                alert_uid=uid,
                action=body.action,
                note=body.note,
                analyst=body.analyst,
                event_uid=body.event_uid,
            )
        )

    @app.get("/api/alerts/{uid}/pack")
    def alert_pack(request: Request, uid: str) -> dict:
        return jsonable(_locked(request, pack_case, uid))

    @app.get("/api/alerts/{uid}/decisions")
    def get_decisions(request: Request, uid: str) -> list[dict]:
        return jsonable(_locked(request, list_history, uid))

    @app.get("/api/audit")
    def audit(request: Request, limit: int = 50) -> list[dict]:
        return jsonable(_locked(request, list_audit, limit=_clamp_limit(limit)))

    @app.get("/api/events/{uid}/raw")
    def event_raw(request: Request, uid: str) -> dict:
        source = request.app.state.source
        if source is None:
            raise LmoError(
                "no raw source directory is configured",
                "Restart with 'lmo serve --source <dir>'.",
            )
        return jsonable(_locked(request, resolve_raw_line, uid, source))

    @app.get("/api/entities/{key:path}")
    def entity(request: Request, key: str) -> dict:
        def _load(wh):
            profile = (
                oq.user_profile(wh, key) if "@" in key else oq.host_profile(wh, key)
            )
            return {
                "kind": profile.kind,
                "key": profile.key,
                "attributes": profile.attributes,
                "relationships": profile.relationships,
                "decisions": decisions_for_entity(wh, key),
            }

        return jsonable(_locked(request, _load))

    @app.get("/api/timeline")
    def timeline(
        request: Request,
        start: int,
        end: int,
        user: str | None = None,
        host: str | None = None,
        limit: int = oq.DEFAULT_LIMIT,
    ) -> list[dict]:
        return jsonable(
            _locked(
                request,
                oq.timeline,
                user=user,
                host=host,
                start_sec=start,
                end_sec=end,
                limit=_clamp_limit(limit, oq.DEFAULT_LIMIT),
            )
        )

    @app.get("/api/neighbours")
    def neighbours(
        request: Request,
        host: str,
        start: int,
        end: int,
        limit: int = oq.DEFAULT_LIMIT,
    ) -> list[dict]:
        return jsonable(
            _locked(
                request,
                oq.neighbours,
                host,
                start_sec=start,
                end_sec=end,
                limit=_clamp_limit(limit, oq.DEFAULT_LIMIT),
            )
        )

    @app.get("/api/paths")
    def paths(
        request: Request,
        src: str,
        dst: str,
        start: int,
        end: int,
        max_hops: int = oq.DEFAULT_MAX_HOPS,
        user: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        return jsonable(
            _locked(
                request,
                oq.paths_between,
                src,
                dst,
                start_sec=start,
                end_sec=end,
                max_hops=max_hops,
                user=user,
                limit=_clamp_limit(limit, 50),
            )
        )

    @app.get("/api/corroborate")
    def corroborate(
        request: Request,
        time: int,
        src: str,
        dst: str,
        window: int = oq.CORROBORATION_WINDOW,
    ) -> dict:
        return jsonable(
            _locked(
                request,
                oq.corroborate,
                time_sec=time,
                src_host=src,
                dst_host=dst,
                window=window,
            )
        )
