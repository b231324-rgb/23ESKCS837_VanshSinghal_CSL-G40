"""Attack dashboard: server-side rendered HTML with inline SVG charts (no JavaScript, no CDN).

Everything an attacker typed is HTML-escaped before display (stored-XSS defence) and a strict
Content-Security-Policy is sent, because the dashboard shows hostile input by design.
"""
import json
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SEV_COLOR = {"info": "#64748b", "low": "#0ea5e9", "medium": "#f59e0b", "high": "#ef4444", "critical": "#7f1d1d"}
PALETTE = ["#2563eb", "#16a34a", "#f59e0b", "#ef4444", "#7c3aed", "#0891b2", "#db2777", "#65a30d"]

CSS = """
body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f1f5f9;color:#0f172a}
.top{background:#0f172a;color:#fff;padding:14px 24px}.top h1{margin:0;font-size:22px}
.top span{font-size:12px;color:#94a3b8}
.wrap{padding:16px 20px}
.card{display:inline-block;vertical-align:top;background:#fff;border-radius:6px;padding:12px 14px;
margin:0 8px 12px 0;box-shadow:0 1px 3px #cbd5e1;box-sizing:border-box}
.stat{width:15.5%;text-align:center}.stat b{display:block;font-size:28px}.stat i{font-style:normal;font-size:12px;color:#64748b}
h3{margin:0 0 8px;font-size:14px;color:#334155}
table{border-collapse:collapse;width:100%;font-size:12px}th{text-align:left;color:#64748b;border-bottom:1px solid #e2e8f0;padding:3px 4px}
td{padding:3px 4px;border-bottom:1px solid #f1f5f9;word-break:break-all}
.badge{color:#fff;border-radius:3px;padding:1px 6px;font-size:11px}
code{font-family:Consolas,'Courier New',monospace;font-size:11px}
"""


def svg_vbars(items, w=520, h=210, color="#2563eb"):
    if not items:
        return "<p>No data yet.</p>"
    maxv = max(v for _, v in items) or 1
    pad_l, pad_b, pad_t = 30, 34, 16
    plot_w, plot_h = w - pad_l - 8, h - pad_b - pad_t
    bw = plot_w / len(items)
    parts = [f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">',
             f'<line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{w - 8}" y2="{pad_t + plot_h}" stroke="#94a3b8"/>',
             f'<text x="2" y="{pad_t + 4}" font-size="10" fill="#64748b">{maxv}</text>',
             f'<text x="2" y="{pad_t + plot_h}" font-size="10" fill="#64748b">0</text>']
    step = max(1, len(items) // 8)
    for i, (label, v) in enumerate(items):
        bh = plot_h * v / maxv
        x, y = pad_l + i * bw + bw * 0.12, pad_t + plot_h - bh
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw * 0.76:.1f}" height="{bh:.1f}" fill="{color}"/>')
        if v and len(items) <= 14:
            parts.append(f'<text x="{x + bw * 0.38:.1f}" y="{y - 3:.1f}" font-size="9" text-anchor="middle" fill="#334155">{v}</text>')
        if i % step == 0:
            parts.append(f'<text x="{x + bw * 0.38:.1f}" y="{h - 18}" font-size="9" text-anchor="middle" fill="#475569">{escape(str(label)[:9])}</text>')
    return "".join(parts) + "</svg>"


def svg_hbars(items, w=330, row=22, color="#16a34a", label_w=120):
    if not items:
        return "<p>No data yet.</p>"
    maxv = max(v for _, v in items) or 1
    h = row * len(items) + 4
    parts = [f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">']
    for i, (label, v) in enumerate(items):
        y = i * row + 2
        bw = (w - label_w - 40) * v / maxv
        parts.append(f'<text x="0" y="{y + 14}" font-size="11" fill="#334155">{escape(str(label)[:20])}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 3}" width="{max(bw, 1):.1f}" height="{row - 8}" fill="{color}"/>')
        parts.append(f'<text x="{label_w + bw + 4:.1f}" y="{y + 14}" font-size="11" fill="#334155">{v}</text>')
    return "".join(parts) + "</svg>"


def svg_donut(items, size=170):
    """Simple pie/donut for severity distribution."""
    import math
    total = sum(v for _, v in items)
    if not total:
        return "<p>No data yet.</p>"
    cx = cy = size / 2
    r = size / 2 - 6
    parts, angle = [f'<svg width="{size + 130}" height="{size}" xmlns="http://www.w3.org/2000/svg">'], -math.pi / 2
    for i, (label, v) in enumerate(items):
        frac = v / total
        a2 = angle + 2 * math.pi * frac
        x1, y1, x2, y2 = cx + r * math.cos(angle), cy + r * math.sin(angle), cx + r * math.cos(a2), cy + r * math.sin(a2)
        large = 1 if frac > 0.5 else 0
        col = SEV_COLOR.get(label, PALETTE[i % len(PALETTE)])
        if frac >= 0.9999:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{col}"/>')
        else:
            parts.append(f'<path d="M{cx},{cy} L{x1:.1f},{y1:.1f} A{r},{r} 0 {large} 1 {x2:.1f},{y2:.1f} Z" fill="{col}"/>')
        parts.append(f'<rect x="{size + 8}" y="{14 + i * 20}" width="10" height="10" fill="{col}"/>')
        parts.append(f'<text x="{size + 24}" y="{23 + i * 20}" font-size="11" fill="#334155">{escape(label)} ({v})</text>')
        angle = a2
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r * 0.48}" fill="#fff"/>')
    return "".join(parts) + "</svg>"


def badge(sev):
    return f'<span class="badge" style="background:{SEV_COLOR.get(sev, "#64748b")}">{escape(sev)}</span>'


def fmt_time(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


def table(headers, rows):
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>" if rows else "<p>No data yet.</p>"


def render_page(store, refresh=5):
    s = store.summary()
    timeline, width = store.timeline()
    sev_order = ["info", "low", "medium", "high", "critical"]
    sev = sorted(store.severity_counts(), key=lambda r: sev_order.index(r[0]) if r[0] in sev_order else 9)
    stats = [("Total events", s["events"]), ("Unique attackers", s["unique_ips"]), ("Login attempts", s["auth_attempts"]),
             ("Shells obtained", s["successful_logins"]), ("Commands typed", s["commands"]), ("IDS alerts", s["alerts"])]
    cards = "".join(f'<div class="card stat"><b>{v}</b><i>{escape(k)}</i></div>' for k, v in stats)

    alerts = table(["Time", "Source IP", "Rule", "Severity", "Message"],
                   [[fmt_time(t), escape(ip), f"<b>{escape(rule)}</b>", badge(sv), escape(msg or "")]
                    for t, ip, rule, sv, msg in store.recent_alerts()])
    events = table(["Time", "Svc", "Source IP", "Type", "Details", "Sev"],
                   [[fmt_time(t), escape(svc), escape(ip), escape(et),
                     "<code>" + escape(" ".join(x for x in (
                         f"{u}/{p}" if et == "auth_attempt" else (cmd or d or "") for u, p, cmd, d in [(u, p, cmd, d)]) if x)[:90]) + "</code>",
                     badge(sv)]
                    for t, svc, ip, et, u, p, cmd, d, tg, sv in store.recent_events()])
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="{refresh}">
<title>Honeypot Attack Dashboard</title><style>{CSS}</style></head><body>
<div class="top"><h1>Low-Interaction Honeypot &mdash; Attack Dashboard</h1>
<span>CSL-G40 &middot; SSH + HTTP decoys &middot; auto-refresh {refresh}s &middot; {escape(time.strftime('%d %b %Y %H:%M:%S'))}
&middot; <a style="color:#93c5fd" href="/export.csv">export CSV</a></span></div>
<div class="wrap">{cards}<br>
<div class="card" style="width:49%"><h3>Attack timeline (events per {width}s)</h3>{svg_vbars(timeline, w=560, color="#2563eb")}</div>
<div class="card" style="width:23%"><h3>Events by service</h3>{svg_vbars(store.by_service(), w=250, h=210, color="#16a34a")}</div>
<div class="card" style="width:23%"><h3>Severity distribution</h3>{svg_donut(sev, size=150)}</div><br>
<div class="card" style="width:32%"><h3>Top attacker IPs</h3>{svg_hbars(store.top_ips(), w=360, color="#ef4444")}</div>
<div class="card" style="width:32%"><h3>Attack categories (IDS tags)</h3>{svg_hbars(store.tag_counts()[:8], w=360, color="#7c3aed", label_w=130)}</div>
<div class="card" style="width:32%"><h3>Top commands typed</h3>{svg_hbars(store.top_commands(8), w=360, color="#f59e0b", label_w=150)}</div><br>
<div class="card" style="width:32%"><h3>Top usernames tried</h3>{svg_hbars(store.top_field("username", 8), w=360, color="#0891b2")}</div>
<div class="card" style="width:32%"><h3>Top passwords tried</h3>{svg_hbars(store.top_field("password", 8), w=360, color="#db2777")}</div><br>
<div class="card" style="width:97%"><h3>Latest IDS alerts</h3>{alerts}</div><br>
<div class="card" style="width:97%"><h3>Live event feed</h3>{events}</div>
</div></body></html>"""
    return page


class Dashboard:
    def __init__(self, cfg, store):
        self.cfg, self.store = cfg, store
        self.port = cfg.dash_port

    def _make_handler(dash):
        store = dash.store

        class Handler(BaseHTTPRequestHandler):
            server_version = "HoneypotDashboard"
            sys_version = ""

            def log_message(self, *a):
                pass

            def version_string(self):
                return "HoneypotDashboard"

            def _send(self, status, body, ctype):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path).path
                if path in ("/", "/index.html"):
                    self._send(200, render_page(store), "text/html; charset=utf-8")
                elif path == "/api/summary":
                    self._send(200, json.dumps({"summary": store.summary(), "top_ips": store.top_ips(),
                                                "tags": store.tag_counts()}), "application/json")
                elif path == "/export.csv":
                    self._send(200, store.export_csv(), "text/csv; charset=utf-8")
                else:
                    self._send(404, "Not found", "text/plain")

        return Handler

    def start(self):
        self.server = ThreadingHTTPServer((self.cfg.dash_host, self.cfg.dash_port), self._make_handler())
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True, name="dashboard").start()
        print(f"[dash] dashboard at http://{self.cfg.dash_host}:{self.port}/", flush=True)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
