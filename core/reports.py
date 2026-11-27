"""CSV / JSON security report export."""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from utils.helpers import iso
from utils.paths import reports_dir

REPORT_KINDS = ("alerts", "connections", "privacy", "dns", "full")


def _alert_rows(db, since):
    rows = []
    for a in db.alerts(since=since, limit=100000):
        rows.append({
            "event_timestamp": iso(a["ts"]), "type": "alert", "category": a["category"],
            "title": a["title"], "process": a["process_name"], "pid": a["pid"], "executable": a["exe"],
            "destination": a["destination"], "observed_activity": a["what"],
            "risk_classification": a["severity"], "risk_score": a["score"],
            "why_flagged": a["why"], "supporting_evidence": " | ".join(a["evidence"]),
            "uncertainty": a["uncertainty"], "recommendations": " | ".join(a["recommendations"]),
            "occurrences": a["count"]})
    return rows


def _conn_rows(db, since):
    rows = []
    for c in db.search_connections(since=since, limit=1_000_000):
        rows.append({
            "event_timestamp": iso(c["first_seen"]), "type": "connection",
            "process": c["process_name"], "pid": c["pid"], "executable": c["exe"],
            "protocol": c["proto"], "direction": c["direction"],
            "local": f"{c['laddr']}:{c['lport']}", "destination": f"{c['raddr']}:{c['rport']}",
            "destination_class": c["dest_class"], "domain": c["domain"], "state": c["state"],
            "last_seen": iso(c["last_seen"]), "closed_at": iso(c["closed_at"]),
            "bytes_out": c["bytes_out"], "bytes_in": c["bytes_in"],
            "measurement_source": c["measure_source"] or "none",
            "risk_classification": c["risk_level"], "risk_score": c["risk_score"]})
    return rows


def _privacy_rows(db, since):
    rows = []
    for e in db.query_dicts("SELECT * FROM privacy_events WHERE ts>=? ORDER BY ts DESC", (since,)):
        rows.append({
            "event_timestamp": iso(e["ts"]), "type": "privacy", "capability": e["capability"],
            "event": e["event_type"], "application": e["display_name"], "app_identity": e["app_id"],
            "app_kind": e["app_kind"], "scope": e["scope"], "access_start": iso(e["start_ts"]),
            "access_stop": iso(e["stop_ts"]), "duration_sec": e["duration"],
            "permission": e["permission"], "pids": e["pids"],
            "supporting_evidence": "Windows CapabilityAccessManager ConsentStore timestamps"})
    return rows


def _dns_rows(db, since):
    rows = []
    for d in db.query_dicts("SELECT * FROM dns_queries WHERE ts>=? ORDER BY ts DESC", (since,)):
        rows.append({"event_timestamp": iso(d["ts"]), "type": "dns", "name": d["name"], "qtype": d["qtype"],
                     "answers": d["answers"], "pid": d["pid"], "source": d["source"],
                     "indicators": d["indicators"]})
    return rows


BUILDERS = {"alerts": _alert_rows, "connections": _conn_rows, "privacy": _privacy_rows, "dns": _dns_rows}


def export_report(db, kind: str, fmt: str, since: float = 0, path: str | Path | None = None) -> Path:
    if kind not in REPORT_KINDS:
        raise ValueError(f"unknown report kind {kind}")
    if fmt not in ("csv", "json"):
        raise ValueError("format must be csv or json")
    db.flush()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = Path(path) if path else reports_dir() / f"netsentinel-{kind}-{stamp}.{fmt}"
    if kind == "full":
        data = {k: fn(db, since) for k, fn in BUILDERS.items()}
        if fmt == "json":
            path.write_text(json.dumps({"generated": iso(time.time()), "tool": "NetSentinel",
                                        "note": "Contains metadata only: no packet payloads, audio, video, passwords or cookies.",
                                        **data}, indent=2), encoding="utf-8")
        else:
            rows = [r for v in data.values() for r in v]
            _write_csv(path, rows)
        return path
    rows = BUILDERS[kind](db, since)
    if fmt == "json":
        path.write_text(json.dumps({"generated": iso(time.time()), "kind": kind, "records": rows}, indent=2),
                        encoding="utf-8")
    else:
        _write_csv(path, rows)
    return path


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields: list[str] = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:   # BOM so Excel opens UTF-8 correctly
        w = csv.DictWriter(f, fieldnames=fields or ["empty"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
