#!/usr/bin/env python3
"""Launcher: starts the fake SSH service, fake HTTP service and the attack dashboard.

LAB USE ONLY - run inside your own VM / isolated network. Never expose real credentials.
"""
import argparse
import os
import signal
import threading

from config import Config
from dashboard import Dashboard
from db import EventStore
from detector import Detector
from http_honeypot import HTTPHoneypot
from ssh_honeypot import SSHHoneypot


def build(cfg):
    os.makedirs(os.path.dirname(cfg.db_path), exist_ok=True)
    store = EventStore(cfg.db_path, cfg.max_field_len)
    det = Detector(store, cfg)
    return store, det, SSHHoneypot(cfg, store, det), HTTPHoneypot(cfg, store, det), Dashboard(cfg, store)


def main():
    ap = argparse.ArgumentParser(description="Low-Interaction Honeypot with Attack Dashboard (CSL-G40)")
    ap.add_argument("--host", default="127.0.0.1", help="bind address for decoys (default loopback; use a VM IP or 0.0.0.0 in your lab only)")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--dash-port", type=int, default=5000)
    ap.add_argument("--db", default=None, help="SQLite database path")
    args = ap.parse_args()

    cfg = Config(host=args.host, ssh_port=args.ssh_port, http_port=args.http_port, dash_port=args.dash_port)
    if args.db:
        cfg.db_path = args.db
    store, det, ssh, http, dash = build(cfg)
    for svc in (ssh, http, dash):
        svc.start()
    print("Honeypot running. Press Ctrl+C to stop.", flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    stop.wait()
    for svc in (ssh, http, dash):
        svc.stop()
    print("Stopped.")


if __name__ == "__main__":
    main()
