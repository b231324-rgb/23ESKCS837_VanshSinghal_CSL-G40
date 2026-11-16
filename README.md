# Low-Interaction Honeypot with Attack Dashboard  (CSL-G40)

Cyber Security Lab (7CS4-22) mini project - Exp 7: Intrusion Detection System.
Author: Vansh Singhal (23ESKCS837), SKIT Jaipur.

A fake SSH service and a fake web admin console that log every connection, credential and command,
a rule-based detector that raises IDS alerts, and a live web dashboard.

## Quick start
    pip install -r requirements.txt
    python honeypot.py                      # SSH :2222, HTTP :8080, dashboard http://127.0.0.1:5000
    python simulate_attacks.py              # (second terminal) loopback-only test attacks
    python -m unittest discover -s tests -v # automated tests

Try it manually:  ssh -p 2222 root@127.0.0.1  (password `toor` opens the fake shell) and browse http://127.0.0.1:8080/

## Files
| File | Purpose |
|---|---|
| honeypot.py | launcher (starts SSH, HTTP, dashboard) |
| ssh_honeypot.py | Paramiko-based fake SSH server + canned-reply shell |
| http_honeypot.py | fake "Acme Corp" admin console, WordPress/phpMyAdmin lures |
| detector.py | signature + threshold IDS rules, alert generation |
| db.py | SQLite event store, statistics queries, CSV export |
| dashboard.py | SVG-based dashboard with CSP and output escaping |
| simulate_attacks.py | test attacker (refuses non-loopback targets) |
| tests/test_honeypot.py | unit and integration tests |

## Safety / ethics
* Decoys bind to 127.0.0.1 by default. Use `--host` only inside your own VM or isolated lab network.
* Nothing typed by an attacker is ever executed; the shell returns canned text.
* Only dummy credentials are used. Never run this on the college network or a live server.
