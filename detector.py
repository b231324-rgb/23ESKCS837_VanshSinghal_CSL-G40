"""Rule-based intrusion detection (links to Experiment 7 - Intrusion Detection System).

The detector is *signature + threshold* based:
  * signatures  : regular expressions over shell commands and HTTP requests
  * thresholds  : sliding-window counters per source IP (brute force, user enumeration)
Every hit becomes a tag on the event and, if severe enough, a row in the `alerts` table.
"""
import re
import threading
import time
from collections import defaultdict, deque
from urllib.parse import unquote_plus

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ------------------------------------------------------------------ shell commands
CMD_RULES = [  # (tag, regex)
    ("recon", r"\b(uname|whoami|id|ifconfig|netstat|uptime|hostname|lscpu|ps|ss)\b|ip\s+a\b|/etc/(passwd|shadow|issue)|/proc/"),
    ("download", r"\b(wget|curl|tftp|ftpget|scp)\b"),
    ("execution", r"chmod\s+\+?[0-7x]+|\bsh\s+-c\b|\./\S+|\bperl\b|\bpython\d?\b"),
    ("persistence", r"crontab|authorized_keys|useradd|adduser|rc\.local|systemctl\s+enable"),
    ("destructive", r"rm\s+-rf|mkfs|dd\s+if="),
    ("cryptominer", r"xmrig|minerd|stratum\+tcp|cpuminer"),
    ("botnet", r"busybox|mirai|/dev/tcp/|nc\s+-e|bash\s+-i"),
]
CMD_SEVERITY = {"recon": "low", "download": "high", "execution": "high", "persistence": "critical",
                "destructive": "high", "cryptominer": "high", "botnet": "critical"}
CMD_RULE_NAME = {"download": "MALWARE-DOWNLOAD", "execution": "PAYLOAD-EXECUTION",
                 "persistence": "PERSISTENCE-ATTEMPT", "destructive": "DESTRUCTIVE-COMMAND",
                 "cryptominer": "CRYPTOMINER-ACTIVITY", "botnet": "BOTNET-BEHAVIOUR"}

# ------------------------------------------------------------------ web requests
HTTP_RULES = [
    ("sqli", r"(\bunion\b.+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1|;\s*drop\s+table|sleep\s*\(|benchmark\s*\(|information_schema|--\s*$)"),
    ("xss", r"<\s*script|javascript:|onerror\s*=|onload\s*="),
    ("traversal", r"\.\./|\.\.\\|%2e%2e|/etc/passwd|win\.ini"),
    ("cmd-injection", r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b"),
]
HTTP_SEVERITY = {"sqli": "high", "xss": "medium", "traversal": "high", "cmd-injection": "critical",
                 "scanner": "medium", "path-probe": "low", "automated-client": "low"}
HTTP_RULE_NAME = {"sqli": "WEB-SQL-INJECTION", "xss": "WEB-XSS", "traversal": "WEB-PATH-TRAVERSAL",
                  "cmd-injection": "WEB-COMMAND-INJECTION", "scanner": "SCANNER-USER-AGENT",
                  "path-probe": "SENSITIVE-PATH-PROBE"}
SCANNER_UA = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|dirb\b|wpscan|nessus|acunetix|hydra|nuclei", re.I)
AUTOMATED_UA = re.compile(r"python-requests|go-http-client|libwww|okhttp|scrapy", re.I)
SENSITIVE_PATH = re.compile(r"^/(\.env|\.git|\.aws|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|pma|admin|"
                            r"administrator|manager/html|cgi-bin|server-status|config\.php|backup|actuator)", re.I)

_CMD_COMPILED = [(t, re.compile(p, re.I)) for t, p in CMD_RULES]
_HTTP_COMPILED = [(t, re.compile(p, re.I)) for t, p in HTTP_RULES]


def max_severity(tags, table):
    return max((table.get(t, "info") for t in tags), key=lambda s: SEV_ORDER[s], default="info")


def classify_command(cmd):
    return [t for t, rx in _CMD_COMPILED if rx.search(cmd)]


def classify_http(path_and_query, body, user_agent):
    decoded = unquote_plus(path_and_query + " " + body)
    tags = [t for t, rx in _HTTP_COMPILED if rx.search(decoded)]
    if SCANNER_UA.search(user_agent or ""):
        tags.append("scanner")
    elif AUTOMATED_UA.search(user_agent or ""):
        tags.append("automated-client")
    if SENSITIVE_PATH.search(unquote_plus(path_and_query.split("?")[0])):
        tags.append("path-probe")
    return tags


class Detector:
    def __init__(self, store, cfg):
        self.store, self.cfg = store, cfg
        self._lock = threading.Lock()
        self._fails = defaultdict(deque)      # ip -> deque[(ts, service)]
        self._users = defaultdict(deque)      # ip -> deque[(ts, username)]
        self._recon = defaultdict(int)        # ip -> recon command count
        self._last_alert = {}                 # (ip, rule) -> ts

    # -- helpers
    def _alert(self, ip, rule, severity, message):
        now = time.time()
        with self._lock:
            if now - self._last_alert.get((ip, rule), 0) < self.cfg.alert_cooldown:
                return False
            self._last_alert[(ip, rule)] = now
        self.store.add_alert(ip, rule, severity, message)
        print(f"[ALERT/{severity.upper()}] {rule} from {ip}: {message}", flush=True)
        return True

    @staticmethod
    def _trim(dq, now, window):
        while dq and now - dq[0][0] > window:
            dq.popleft()

    # -- authentication events (ssh + http login form)
    def on_auth_attempt(self, ip, service, username, success):
        now, win = time.time(), self.cfg.bf_window
        with self._lock:
            users = self._users[ip]
            users.append((now, username))
            self._trim(users, now, win)
            distinct = len({u for _, u in users})
            fails = self._fails[ip]
            if not success:
                fails.append((now, service))
            self._trim(fails, now, win)
            n_fail = len(fails)
        if success:
            self._alert(ip, "SUCCESSFUL-LOGIN", "high",
                        f"{service.upper()} login accepted for '{username}' - attacker reached fake shell")
        if n_fail >= self.cfg.bf_threshold:
            self._alert(ip, f"{service.upper()}-BRUTE-FORCE", "high",
                        f"{n_fail} failed logins within {win}s")
        if distinct >= self.cfg.enum_threshold:
            self._alert(ip, "USER-ENUMERATION", "medium", f"{distinct} different usernames within {win}s")

    # -- shell commands
    def analyze_command(self, ip, command):
        tags = classify_command(command)
        for t in tags:
            if t == "recon":
                with self._lock:
                    self._recon[ip] += 1
                    count = self._recon[ip]
                if count == 3:
                    self._alert(ip, "RECON-COMMANDS", "medium", "3+ reconnaissance commands executed")
            elif t in CMD_RULE_NAME:
                self._alert(ip, CMD_RULE_NAME[t], CMD_SEVERITY[t], f"command: {command[:80]}")
        return tags, max_severity(tags, CMD_SEVERITY)

    # -- web requests
    def analyze_http(self, ip, request_target, body, user_agent):
        tags = classify_http(request_target, body, user_agent)
        for t in tags:
            if t in HTTP_RULE_NAME and SEV_ORDER[HTTP_SEVERITY[t]] >= SEV_ORDER["medium"]:
                self._alert(ip, HTTP_RULE_NAME[t], HTTP_SEVERITY[t], f"request: {request_target[:80]}")
        return tags, max_severity(tags, HTTP_SEVERITY)
