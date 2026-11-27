"""SQLite schema and ordered migrations. Never stores payloads, audio, video,
passwords, cookies or command lines."""

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL, ended_at REAL,
    host TEXT, is_admin INTEGER, capabilities TEXT);

CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER, pid INTEGER, create_time REAL, name TEXT, exe TEXT,
    username TEXT, ppid INTEGER, parent_name TEXT, sig_status TEXT, publisher TEXT,
    sig_type TEXT, suspicious_dir TEXT, first_seen REAL, last_seen REAL,
    UNIQUE(session_id, pid, create_time));

CREATE TABLE IF NOT EXISTS connections (
    uid TEXT PRIMARY KEY, session_id INTEGER, pid INTEGER, process_name TEXT, exe TEXT,
    proto TEXT, family INTEGER, laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER,
    state TEXT, direction TEXT, dest_class TEXT, domain TEXT, repeat_count INTEGER,
    first_seen REAL, last_seen REAL, closed_at REAL,
    bytes_out INTEGER, bytes_in INTEGER, measure_source TEXT,
    risk_score INTEGER, risk_level TEXT);
CREATE INDEX IF NOT EXISTS ix_conn_time ON connections(first_seen);
CREATE INDEX IF NOT EXISTS ix_conn_raddr ON connections(raddr);
CREATE INDEX IF NOT EXISTS ix_conn_exe ON connections(exe);

CREATE TABLE IF NOT EXISTS traffic_stats (
    hour_ts INTEGER, exe TEXT, raddr TEXT, proto TEXT,
    bytes_out INTEGER DEFAULT 0, bytes_in INTEGER DEFAULT 0, source TEXT,
    PRIMARY KEY (hour_ts, exe, raddr, proto));

CREATE TABLE IF NOT EXISTS interface_stats (
    hour_ts INTEGER PRIMARY KEY, bytes_sent INTEGER DEFAULT 0, bytes_recv INTEGER DEFAULT 0);

CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, name TEXT, qtype TEXT, answers TEXT,
    pid INTEGER, process_name TEXT, source TEXT, indicators TEXT);
CREATE INDEX IF NOT EXISTS ix_dns_time ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS ix_dns_name ON dns_queries(name);

CREATE TABLE IF NOT EXISTS destinations (
    ip TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, dest_class TEXT,
    rdns TEXT, domains TEXT, owner TEXT, country TEXT, asn TEXT, apps TEXT);

CREATE TABLE IF NOT EXISTS privacy_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, capability TEXT, event_type TEXT,
    app_id TEXT, app_kind TEXT, display_name TEXT, scope TEXT, start_ts REAL, stop_ts REAL,
    duration REAL, permission TEXT, pids TEXT, observed TEXT);
CREATE INDEX IF NOT EXISTS ix_priv_time ON privacy_events(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts REAL, severity TEXT, score INTEGER, category TEXT, title TEXT,
    process_name TEXT, pid INTEGER, exe TEXT, destination TEXT, what TEXT, why TEXT,
    evidence TEXT, uncertainty TEXT, recommendations TEXT, factors TEXT,
    dedup_key TEXT, count INTEGER DEFAULT 1, acknowledged INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_alert_time ON alerts(ts);

CREATE TABLE IF NOT EXISTS threat_intel (
    indicator TEXT, provider TEXT, ts REAL, verdict TEXT, score REAL, detail TEXT,
    owner TEXT, country TEXT, PRIMARY KEY (indicator, provider));

CREATE TABLE IF NOT EXISTS firewall_rules (
    name TEXT PRIMARY KEY, created_at REAL, exe TEXT, remote_ip TEXT, direction TEXT,
    active INTEGER DEFAULT 1, removed_at REAL);
"""),
    (2, """
ALTER TABLE alerts ADD COLUMN notes TEXT;
CREATE INDEX IF NOT EXISTS ix_alert_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS ix_conn_level ON connections(risk_level);
"""),
]

SCHEMA_VERSION = MIGRATIONS[-1][0]

# table -> timestamp column used by retention cleanup
RETENTION_COLUMNS = {
    "connections": "first_seen", "dns_queries": "ts", "privacy_events": "ts", "alerts": "ts",
    "processes": "last_seen", "sessions": "started_at", "traffic_stats": "hour_ts",
    "interface_stats": "hour_ts", "destinations": "last_seen", "threat_intel": "ts",
}
