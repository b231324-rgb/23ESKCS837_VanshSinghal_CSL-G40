"""Low-interaction HTTP honeypot: a fake "Acme Corp admin console" that never authenticates anyone.

Every request is logged and analysed by the Detector; the login form records the credentials tried.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

LOGIN_PAGE = """<!DOCTYPE html><html><head><title>Acme Corp - Admin Console</title>
<style>body{{font-family:Arial,sans-serif;background:#eef1f5}}.box{{width:320px;margin:90px auto;background:#fff;
padding:28px;border-radius:6px;box-shadow:0 1px 6px #aaa}}input{{width:100%;padding:8px;margin:6px 0 12px;box-sizing:border-box}}
button{{background:#1d4ed8;color:#fff;border:0;padding:9px 16px;width:100%}}.err{{color:#b91c1c;font-size:13px}}</style></head>
<body><div class="box"><h2>Acme Corp</h2><p>Administration Console</p>{error}
<form method="POST" action="/login"><label>Username</label><input name="username">
<label>Password</label><input type="password" name="password"><button type="submit">Sign in</button></form></div></body></html>"""
WP_PAGE = "<html><head><title>Log In &lt; Acme Blog</title></head><body><h1>WordPress</h1>" \
          "<form method='POST' action='/wp-login.php'><input name='log'><input type='password' name='pwd'>" \
          "<input type='submit' value='Log In'></form></body></html>"
PMA_PAGE = "<html><head><title>phpMyAdmin</title></head><body><h1>Welcome to phpMyAdmin</h1>" \
           "<form method='POST' action='/phpmyadmin/index.php'><input name='pma_username'>" \
           "<input type='password' name='pma_password'><input type='submit' value='Go'></form></body></html>"
FAKE_ENV = "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_USER=honeypot_dummy\nDB_PASSWORD=not-a-real-password\n"
ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /phpmyadmin\n"

# POST field names that carry credentials -> (username field, password field)
CRED_FIELDS = [("username", "password"), ("log", "pwd"), ("pma_username", "pma_password"),
               ("user", "pass"), ("email", "password")]


class HTTPHoneypot:
    def __init__(self, cfg, store, det):
        self.cfg, self.store, self.det = cfg, store, det
        self.port = cfg.http_port

    def _make_handler(hp):
        cfg, store, det = hp.cfg, hp.store, hp.det

        class Handler(BaseHTTPRequestHandler):
            server_version = cfg.http_server_header
            sys_version = ""
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):   # silence default stderr access log
                pass

            def version_string(self):       # exact camouflage banner, no trailing space
                return cfg.http_server_header

            def _send(self, status, body, ctype="text/html; charset=utf-8"):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            def _handle(self):
                ip, port = self.client_address[0], self.client_address[1]
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                body = self.rfile.read(min(length, cfg.max_http_body)).decode("utf-8", "ignore") if length else ""
                ua = self.headers.get("User-Agent", "")
                target = self.path
                path = urlsplit(target).path
                tags, sev = det.analyze_http(ip, target, body, ua)
                store.add_event("http", ip, port, "http_request", tags=",".join(tags), severity=sev,
                                detail=f"{self.command} {target} | UA: {ua}")
                print(f"[http] {ip}:{port} {self.command} {target[:70]} {tags}", flush=True)

                if self.command == "POST":
                    form = parse_qs(body)
                    for ufield, pfield in CRED_FIELDS:
                        if ufield in form or pfield in form:
                            user = form.get(ufield, [""])[0]
                            pwd = form.get(pfield, [""])[0]
                            store.add_event("http", ip, port, "auth_attempt", username=user, password=pwd,
                                            detail=f"POST {path}", tags=",".join(tags), severity="low")
                            det.on_auth_attempt(ip, "http", user, False)
                            print(f"[http] {ip} credentials tried {user!r}/{pwd!r}", flush=True)
                            break
                    return self._send(200, LOGIN_PAGE.format(error='<p class="err">Invalid username or password.</p>'))

                if path in ("/", "/index.html", "/admin", "/admin/", "/login", "/administrator"):
                    return self._send(200, LOGIN_PAGE.format(error=""))
                if path.startswith("/wp-login.php") or path.startswith("/wp-admin"):
                    return self._send(200, WP_PAGE)
                if path.startswith("/phpmyadmin"):
                    return self._send(200, PMA_PAGE)
                if path == "/robots.txt":
                    return self._send(200, ROBOTS, "text/plain")
                if path == "/.env":
                    return self._send(200, FAKE_ENV, "text/plain")
                return self._send(404, "<html><body><h1>Not Found</h1><p>The requested URL was not found "
                                       "on this server.</p></body></html>")

            do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = _handle

        return Handler

    def start(self):
        self.server = ThreadingHTTPServer((self.cfg.host, self.cfg.http_port), self._make_handler())
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True, name="http-honeypot").start()
        print(f"[http] fake web server listening on {self.cfg.host}:{self.port}", flush=True)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
