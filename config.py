"""Central configuration for the Low-Interaction Honeypot (CSL-G40)."""
import os
from dataclasses import dataclass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@dataclass
class Config:
    # --- network (loopback by default so nothing is exposed by accident) ---
    host: str = "127.0.0.1"
    ssh_port: int = 2222
    http_port: int = 8080
    dash_host: str = "127.0.0.1"
    dash_port: int = 5000
    # --- storage ---
    db_path: str = os.path.join(BASE_DIR, "data", "honeypot.db")
    host_key_path: str = os.path.join(BASE_DIR, "data", "host_key.pem")
    # --- service camouflage ---
    ssh_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    http_server_header: str = "Apache/2.4.41 (Ubuntu)"
    hostname: str = "srv-prod-01"
    # Passwords the fake SSH server "accepts" so attackers reach the fake shell.
    weak_passwords: tuple = ("123456", "password", "admin", "root", "toor", "12345",
                             "qwerty", "letmein", "1234", "raspberry", "ubuntu")
    # --- resource limits (a honeypot must not be a DoS target itself) ---
    max_ssh_connections: int = 50
    ssh_session_timeout: int = 180      # seconds
    max_commands: int = 100             # per SSH session
    max_field_len: int = 256            # stored characters per attacker-supplied field
    max_http_body: int = 4096           # bytes read from a POST body
    # --- detection thresholds ---
    bf_threshold: int = 5               # failed logins ...
    bf_window: int = 60                 # ... within this many seconds => brute force
    enum_threshold: int = 3             # distinct usernames within the window
    alert_cooldown: int = 120           # do not repeat (ip, rule) alert within this time
