"""SQLite persistence.

Writes are serialised through one background writer thread (batched transactions),
so monitoring threads never block on disk I/O. Reads use a separate connection;
WAL mode lets readers and the writer work concurrently.
"""
from __future__ import annotations

import json
import logging
import queue
import socket
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from database.models import MIGRATIONS, RETENTION_COLUMNS, SCHEMA_VERSION
from utils.paths import database_path

log = logging.getLogger(__name__)
_STOP = object()


class DatabaseManager:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path or database_path())
        self._q: "queue.Queue" = queue.Queue(maxsize=50000)
        self._read_lock = threading.Lock()
        self.dropped = 0
        self.write_errors = 0
        init = sqlite3.connect(self.path)
        self._configure(init)
        self.migrate(init)
        init.close()
        self._reader = sqlite3.connect(self.path, check_same_thread=False)
        self._reader.row_factory = sqlite3.Row
        self._configure(self._reader)
        self._writer_thread = threading.Thread(target=self._writer, name="db-writer", daemon=True)
        self._writer_thread.start()
        self.session_id: Optional[int] = None

    @staticmethod
    def _configure(con: sqlite3.Connection) -> None:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=5000")

    # ------------------------------------------------------- migrations
    @staticmethod
    def migrate(con: sqlite3.Connection) -> int:
        con.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = con.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current = row[0] or 0
        for version, sql in MIGRATIONS:
            if version <= current:
                continue
            log.info("Applying database migration %d", version)
            try:
                con.executescript("BEGIN;" + sql + f"INSERT INTO schema_version VALUES ({version});COMMIT;")
            except sqlite3.Error:
                con.rollback()
                raise
        return SCHEMA_VERSION

    def schema_version(self) -> int:
        return self.query("SELECT MAX(version) AS v FROM schema_version")[0]["v"]

    # ----------------------------------------------------------- writer
    def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        try:
            self._q.put_nowait((sql, tuple(params)))
        except queue.Full:
            self.dropped += 1

    def _writer(self) -> None:
        con = sqlite3.connect(self.path)
        self._configure(con)
        while True:
            item = self._q.get()
            if item is _STOP:
                break
            batch = [item]
            deadline = time.time() + 0.25
            while len(batch) < 2000 and time.time() < deadline:
                try:
                    nxt = self._q.get(timeout=0.05)
                except queue.Empty:
                    continue
                if nxt is _STOP:
                    self._flush(con, batch)
                    con.close()
                    return
                batch.append(nxt)
            self._flush(con, batch)
        con.close()

    def _flush(self, con, batch) -> None:
        markers = [sql for sql, _p in batch if isinstance(sql, threading.Event)]
        batch = [b for b in batch if not isinstance(b[0], threading.Event)]
        try:
            self._commit(con, batch)
        finally:
            for ev in markers:   # signal only after the commit is durable/visible
                ev.set()

    def _commit(self, con, batch) -> None:
        try:
            with con:
                for sql, params in batch:
                    if callable(sql):
                        sql(con)
                    else:
                        con.execute(sql, params)
        except sqlite3.Error as e:
            self.write_errors += 1
            log.error("DB batch failed (%s); retrying statements individually", e)
            for sql, params in batch:
                try:
                    with con:
                        sql(con) if callable(sql) else con.execute(sql, params)
                except sqlite3.Error as e2:
                    log.error("DB statement dropped: %s", e2)

    def flush(self, timeout: float = 5.0) -> None:
        """Block until queued writes are committed (used by tests/shutdown)."""
        ev = threading.Event()
        self._q.put((ev, ()))
        ev.wait(timeout)

    def close(self) -> None:
        if self.session_id:
            self.end_session()
        self.flush()
        self._q.put(_STOP)
        self._writer_thread.join(timeout=5)
        with self._read_lock:
            self._reader.close()

    # ------------------------------------------------------------- reads
    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._read_lock:
            return self._reader.execute(sql, tuple(params)).fetchall()

    def query_dicts(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        return [dict(r) for r in self.query(sql, params)]

    # ---------------------------------------------------------- sessions
    def start_session(self, is_admin: bool, capabilities: dict) -> int:
        con = sqlite3.connect(self.path)
        with con:
            cur = con.execute("INSERT INTO sessions(started_at, host, is_admin, capabilities) VALUES (?,?,?,?)",
                              (time.time(), socket.gethostname(), int(is_admin), json.dumps(capabilities)))
            self.session_id = cur.lastrowid
        con.close()
        return self.session_id

    def end_session(self) -> None:
        self.execute("UPDATE sessions SET ended_at=? WHERE id=?", (time.time(), self.session_id))

    # ---------------------------------------------------------- records
    def upsert_process(self, p) -> None:
        self.execute("""INSERT INTO processes(session_id,pid,create_time,name,exe,username,ppid,parent_name,
                        sig_status,publisher,sig_type,suspicious_dir,first_seen,last_seen)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(session_id,pid,create_time) DO UPDATE SET last_seen=excluded.last_seen,
                        sig_status=excluded.sig_status, publisher=excluded.publisher, sig_type=excluded.sig_type""",
                     (self.session_id, p.pid, p.create_time, p.name, p.exe, p.username, p.ppid, p.parent_name,
                      p.sig_status, p.publisher, p.sig_type, p.suspicious_dir, p.first_seen, p.last_seen))

    def insert_connection(self, c) -> None:
        self.execute("""INSERT OR REPLACE INTO connections(uid,session_id,pid,process_name,exe,proto,family,laddr,lport,
                        raddr,rport,state,direction,dest_class,domain,repeat_count,first_seen,last_seen,closed_at,
                        bytes_out,bytes_in,measure_source,risk_score,risk_level)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (c.uid, self.session_id, c.pid, c.process_name, c.exe, c.proto, c.family, c.laddr, c.lport,
                      c.raddr, c.rport, c.state, c.direction, c.dest_class, c.domain, c.repeat_count,
                      c.first_seen, c.last_seen, c.closed_at, c.bytes_out, c.bytes_in, c.measure_source,
                      c.risk_score, c.risk_level))

    def update_connection(self, c) -> None:
        self.execute("""UPDATE connections SET state=?, last_seen=?, closed_at=?, bytes_out=?, bytes_in=?,
                        measure_source=?, risk_score=?, risk_level=?, domain=?, exe=?, process_name=? WHERE uid=?""",
                     (c.state, c.last_seen, c.closed_at, c.bytes_out, c.bytes_in, c.measure_source,
                      c.risk_score, c.risk_level, c.domain, c.exe, c.process_name, c.uid))

    def add_traffic_rows(self, rows: list[tuple]) -> None:
        for hour, exe, raddr, proto, out_b, in_b, src in rows:
            self.execute("""INSERT INTO traffic_stats(hour_ts,exe,raddr,proto,bytes_out,bytes_in,source)
                            VALUES (?,?,?,?,?,?,?) ON CONFLICT(hour_ts,exe,raddr,proto) DO UPDATE SET
                            bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in,
                            source=excluded.source""", (hour, exe, raddr, proto, out_b, in_b, src))

    def add_interface_bytes(self, ts: float, sent: int, recv: int) -> None:
        if not (sent or recv):
            return
        h = int(ts // 3600) * 3600
        self.execute("""INSERT INTO interface_stats(hour_ts,bytes_sent,bytes_recv) VALUES (?,?,?)
                        ON CONFLICT(hour_ts) DO UPDATE SET bytes_sent=bytes_sent+excluded.bytes_sent,
                        bytes_recv=bytes_recv+excluded.bytes_recv""", (h, sent, recv))

    def insert_dns(self, o) -> None:
        self.execute("INSERT INTO dns_queries(ts,name,qtype,answers,pid,process_name,source,indicators) VALUES (?,?,?,?,?,?,?,?)",
                     (o.ts, o.name, o.qtype, json.dumps(o.answers), o.pid, o.process_name, o.source,
                      json.dumps(o.indicators)))

    def upsert_destination(self, ip: str, ts: float, dest_class: str, rdns: str = "", domains: list | None = None,
                           app: str = "", owner: str = "", country: str = "", asn: str = "") -> None:
        def op(con):
            row = con.execute("SELECT domains, apps, rdns, owner, country, asn FROM destinations WHERE ip=?", (ip,)).fetchone()
            if row is None:
                con.execute("INSERT INTO destinations(ip,first_seen,last_seen,dest_class,rdns,domains,owner,country,asn,apps) VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (ip, ts, ts, dest_class, rdns, json.dumps(sorted(set(domains or []))), owner, country, asn,
                             json.dumps([app] if app else [])))
            else:
                doms = set(json.loads(row[0] or "[]")) | set(domains or [])
                apps = set(json.loads(row[1] or "[]")) | ({app} if app else set())
                con.execute("UPDATE destinations SET last_seen=?, domains=?, apps=?, rdns=?, owner=?, country=?, asn=? WHERE ip=?",
                            (ts, json.dumps(sorted(doms)), json.dumps(sorted(apps)[:50]), rdns or row[2],
                             owner or row[3], country or row[4], asn or row[5], ip))
        self.execute(op)

    def destination_seen_before(self, ip: str) -> bool:
        return bool(self.query("SELECT 1 FROM destinations WHERE ip=? LIMIT 1", (ip,)))

    def insert_privacy_event(self, e) -> None:
        self.execute("""INSERT INTO privacy_events(ts,capability,event_type,app_id,app_kind,display_name,scope,
                        start_ts,stop_ts,duration,permission,pids,observed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (e.ts, e.capability, e.event_type, e.app_id, e.app_kind, e.display_name, e.scope,
                      e.start_ts, e.stop_ts, e.duration, e.permission, json.dumps(e.pids), e.observed))

    def upsert_alert(self, a) -> None:
        self.execute("""INSERT INTO alerts(id,ts,severity,score,category,title,process_name,pid,exe,destination,what,why,
                        evidence,uncertainty,recommendations,factors,dedup_key,count,acknowledged)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(id) DO UPDATE SET count=excluded.count, severity=excluded.severity,
                        score=excluded.score, acknowledged=excluded.acknowledged""",
                     (a.id, a.ts, a.severity, a.score, a.category, a.title, a.process_name, a.pid, a.exe,
                      a.destination, a.what, a.why, json.dumps(a.evidence), a.uncertainty,
                      json.dumps(a.recommendations), json.dumps(a.factors), a.dedup_key, a.count,
                      int(a.acknowledged)))

    def put_ti(self, r) -> None:
        self.execute("INSERT OR REPLACE INTO threat_intel(indicator,provider,ts,verdict,score,detail,owner,country) VALUES (?,?,?,?,?,?,?,?)",
                     (r.indicator, r.provider, r.ts, r.verdict, r.score, r.detail, r.owner, r.country))

    def get_ti(self, indicator: str, max_age: float) -> list:
        from core.threat_intelligence import TIResult
        rows = self.query("SELECT * FROM threat_intel WHERE indicator=? AND ts>=?", (indicator, time.time() - max_age))
        return [TIResult(r["provider"], r["indicator"], r["verdict"], r["score"], r["detail"], r["ts"],
                         r["owner"] or "", r["country"] or "") for r in rows]

    def add_firewall_rule(self, name, exe, ip, direction) -> None:
        self.execute("INSERT OR REPLACE INTO firewall_rules(name,created_at,exe,remote_ip,direction,active) VALUES (?,?,?,?,?,1)",
                     (name, time.time(), exe, ip, direction))

    def remove_firewall_rule(self, name) -> None:
        self.execute("UPDATE firewall_rules SET active=0, removed_at=? WHERE name=?", (time.time(), name))

    # ----------------------------------------------------------- queries
    def search_connections(self, text: str = "", since: float = 0, until: float | None = None,
                           min_level: str | None = None, limit: int = 2000) -> list[dict]:
        sql = "SELECT * FROM connections WHERE first_seen >= ?"
        params: list = [since]
        if until:
            sql += " AND first_seen <= ?"
            params.append(until)
        if text:
            like = f"%{text}%"
            sql += " AND (process_name LIKE ? OR exe LIKE ? OR raddr LIKE ? OR domain LIKE ? OR CAST(rport AS TEXT)=?)"
            params += [like, like, like, like, text]
        if min_level:
            from core.risk_engine import LEVELS
            lv = LEVELS[LEVELS.index(min_level):]
            sql += f" AND risk_level IN ({','.join('?' * len(lv))})"
            params += lv
        sql += " ORDER BY first_seen DESC LIMIT ?"
        params.append(limit)
        return self.query_dicts(sql, params)

    def alerts(self, severities: list[str] | None = None, since: float = 0, limit: int = 1000) -> list[dict]:
        sql = "SELECT * FROM alerts WHERE ts >= ?"
        params: list = [since]
        if severities:
            sql += f" AND severity IN ({','.join('?' * len(severities))})"
            params += severities
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self.query_dicts(sql, params)
        for r in rows:
            for k in ("evidence", "recommendations", "factors"):
                r[k] = json.loads(r[k] or "[]")
        return rows

    def hourly_traffic(self, since: float) -> list[dict]:
        return self.query_dicts("SELECT hour_ts, SUM(bytes_out) AS bytes_out, SUM(bytes_in) AS bytes_in "
                                "FROM traffic_stats WHERE hour_ts >= ? GROUP BY hour_ts ORDER BY hour_ts", (since,))

    def hourly_interface(self, since: float) -> list[dict]:
        return self.query_dicts("SELECT hour_ts, bytes_sent, bytes_recv FROM interface_stats WHERE hour_ts >= ? "
                                "ORDER BY hour_ts", (since,))

    def daily_traffic(self, since: float) -> list[dict]:
        return self.query_dicts("SELECT (hour_ts/86400)*86400 AS day_ts, SUM(bytes_sent) AS bytes_sent, "
                                "SUM(bytes_recv) AS bytes_recv FROM interface_stats WHERE hour_ts >= ? "
                                "GROUP BY day_ts ORDER BY day_ts", (since,))

    # ---------------------------------------------------------- retention
    def cleanup(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400

        def op(con):
            for table, col in RETENTION_COLUMNS.items():
                con.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
        self.execute(op)
        self.execute(lambda con: con.execute("PRAGMA optimize"))

    def vacuum(self) -> None:
        self.flush()
        con = sqlite3.connect(self.path)
        con.execute("VACUUM")
        con.close()

    def stats(self) -> dict:
        out = {}
        for t in RETENTION_COLUMNS:
            out[t] = self.query(f"SELECT COUNT(*) AS n FROM {t}")[0]["n"]
        try:
            out["size_bytes"] = Path(self.path).stat().st_size
        except OSError:
            out["size_bytes"] = 0
        return out
