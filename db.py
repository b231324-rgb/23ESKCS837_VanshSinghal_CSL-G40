"""SQLite persistence layer: every attacker action is one row in `events`."""
import csv
import io
import sqlite3
import threading
import time
from collections import Counter

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    service TEXT NOT NULL,          -- ssh | http
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    event_type TEXT NOT NULL,       -- connect | client_info | auth_attempt | command | http_request | disconnect
    username TEXT,
    password TEXT,
    command TEXT,
    detail TEXT,
    tags TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    success INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
"""

CSV_COLUMNS = ["id", "ts", "service", "src_ip", "src_port", "event_type", "username",
               "password", "command", "detail", "tags", "severity", "success"]


class EventStore:
    def __init__(self, path, max_len=256):
        self.path = path
        self.max_len = max_len
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _clip(self, value):
        """Attacker-controlled data is truncated so one request cannot bloat the DB."""
        if value is None:
            return None
        return str(value)[: self.max_len]

    # ------------------------------------------------------------- writes
    def add_event(self, service, src_ip, src_port, event_type, username=None, password=None,
                  command=None, detail=None, tags="", severity="info", success=0, ts=None):
        ts = ts if ts is not None else time.time()
        with self._lock, self._conn() as c:
            cur = c.execute(
                "INSERT INTO events (ts,service,src_ip,src_port,event_type,username,password,"
                "command,detail,tags,severity,success) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, service, src_ip, src_port, event_type, self._clip(username),
                 self._clip(password), self._clip(command), self._clip(detail),
                 tags, severity, int(success)))
            return cur.lastrowid

    def add_alert(self, src_ip, rule, severity, message, ts=None):
        ts = ts if ts is not None else time.time()
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO alerts (ts,src_ip,rule,severity,message) VALUES (?,?,?,?,?)",
                      (ts, src_ip, rule, severity, self._clip(message)))

    # -------------------------------------------------------------- reads
    def _one(self, sql, args=()):
        with self._conn() as c:
            return c.execute(sql, args).fetchone()[0]

    def _rows(self, sql, args=()):
        with self._conn() as c:
            return [tuple(r) for r in c.execute(sql, args).fetchall()]

    def summary(self):
        return {
            "events": self._one("SELECT COUNT(*) FROM events"),
            "unique_ips": self._one("SELECT COUNT(DISTINCT src_ip) FROM events"),
            "auth_attempts": self._one("SELECT COUNT(*) FROM events WHERE event_type='auth_attempt'"),
            "successful_logins": self._one(
                "SELECT COUNT(*) FROM events WHERE event_type='auth_attempt' AND success=1"),
            "commands": self._one("SELECT COUNT(*) FROM events WHERE event_type='command'"),
            "alerts": self._one("SELECT COUNT(*) FROM alerts"),
        }

    def by_service(self):
        return self._rows("SELECT service, COUNT(*) FROM events GROUP BY service ORDER BY 2 DESC")

    def top_ips(self, n=8):
        return self._rows("SELECT src_ip, COUNT(*) FROM events GROUP BY src_ip ORDER BY 2 DESC LIMIT ?", (n,))

    def top_field(self, field, n=10):
        if field not in ("username", "password"):
            raise ValueError("bad field")
        return self._rows(
            f"SELECT {field}, COUNT(*) FROM events WHERE event_type='auth_attempt' AND {field} IS NOT NULL "
            f"AND {field}!='' GROUP BY {field} ORDER BY 2 DESC, 1 LIMIT ?", (n,))

    def top_commands(self, n=10):
        return self._rows("SELECT command, COUNT(*) FROM events WHERE event_type='command' "
                          "GROUP BY command ORDER BY 2 DESC LIMIT ?", (n,))

    def tag_counts(self):
        counter = Counter()
        for (tags,) in self._rows("SELECT tags FROM events WHERE tags IS NOT NULL AND tags!=''"):
            counter.update(t for t in tags.split(",") if t)
        return counter.most_common()

    def severity_counts(self):
        return self._rows("SELECT severity, COUNT(*) FROM events GROUP BY severity")

    def recent_events(self, n=15):
        return self._rows("SELECT ts,service,src_ip,event_type,username,password,command,detail,tags,severity "
                          "FROM events WHERE event_type!='disconnect' ORDER BY id DESC LIMIT ?", (n,))

    def recent_alerts(self, n=12):
        return self._rows("SELECT ts,src_ip,rule,severity,message FROM alerts ORDER BY id DESC LIMIT ?", (n,))

    def timeline(self, max_buckets=24):
        """Events per time bucket; bucket width adapts to the observed time span."""
        lo, hi = self._rows("SELECT MIN(ts), MAX(ts) FROM events")[0]
        if lo is None:
            return [], 60
        span = max(hi - lo, 1)
        width = next((w for w in (5, 10, 30, 60, 300, 900, 3600, 21600) if span / w <= max_buckets), 86400)
        rows = dict(self._rows("SELECT CAST(ts/? AS INTEGER), COUNT(*) FROM events GROUP BY 1", (width,)))
        first, last = int(lo // width), int(hi // width)
        out = []
        for b in range(first, last + 1):
            label = time.strftime("%H:%M:%S" if width < 60 else "%H:%M", time.localtime(b * width))
            out.append((label, rows.get(b, 0)))
        return out, width

    def export_csv(self):
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_COLUMNS)
        for row in self._rows("SELECT " + ",".join(CSV_COLUMNS) + " FROM events ORDER BY id"):
            # neutralise spreadsheet formula injection from attacker-controlled cells
            writer.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in row])
        return buf.getvalue()
