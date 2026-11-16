"""Low-interaction SSH honeypot.

It speaks the real SSH protocol (via Paramiko) so scanners and bots complete the handshake and try
credentials, but it NEVER executes anything: the "shell" is a table of canned replies.
Logged: connections, client version, every username/password tried, every command typed.
"""
import logging
import os
import re
import socket
import threading
import time

import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # keep console readable

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n")
FAKE_PS = ("  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  412 ?        00:00:00 sshd\n"
           "  633 ?        00:00:01 apache2\n  901 pts/0    00:00:00 bash\n  927 pts/0    00:00:00 ps\n")
FAKE_IFCONFIG = ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                 "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
                 "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n")


def load_or_create_host_key(path):
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


def fake_command(cfg, user, segment):
    """Return (output_text, should_exit) for one simple command. Nothing is ever executed."""
    parts = segment.strip().split()
    if not parts:
        return "", False
    if parts[0] == "sudo" and len(parts) > 1:
        parts = parts[1:]
    cmd, args = parts[0], parts[1:]
    if cmd in ("exit", "logout", "quit"):
        return "logout\n", True
    if cmd == "whoami":
        return user + "\n", False
    if cmd == "id":
        return ("uid=0(root) gid=0(root) groups=0(root)\n" if user == "root"
                else f"uid=1000({user}) gid=1000({user}) groups=1000({user})\n"), False
    if cmd == "pwd":
        return ("/root\n" if user == "root" else f"/home/{user}\n"), False
    if cmd == "hostname":
        return cfg.hostname + "\n", False
    if cmd == "uname":
        if args and args[0] in ("-a", "-r", "-s", "-m"):
            return (f"Linux {cfg.hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 "
                    "x86_64 x86_64 x86_64 GNU/Linux\n"), False
        return "Linux\n", False
    if cmd == "uptime":
        return " 10:42:17 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n", False
    if cmd == "ls":
        if any(a.startswith("-") and "l" in a for a in args):
            return ("total 12\n-rw-r--r-- 1 root root 1024 Oct  2 09:11 backup.tar.gz\n"
                    "-rw-r--r-- 1 root root  220 Oct  2 09:11 notes.txt\n"), False
        return "backup.tar.gz  notes.txt\n", False
    if cmd == "cat" and args:
        if args[0] == "/etc/passwd":
            return FAKE_PASSWD, False
        if args[0] == "/etc/shadow":
            return "cat: /etc/shadow: Permission denied\n", False
        return f"cat: {args[0]}: No such file or directory\n", False
    if cmd in ("ifconfig",) or (cmd == "ip" and args[:1] in (["a"], ["addr"])):
        return FAKE_IFCONFIG, False
    if cmd == "ps":
        return FAKE_PS, False
    if cmd in ("wget", "curl", "tftp", "ftpget"):
        return f"{cmd}: unable to resolve host address\n", False
    if cmd == "echo":
        return " ".join(args) + "\n", False
    if cmd in ("cd", "chmod", "chown", "mkdir", "touch", "export", "clear", "history", "nohup", "rm", "kill"):
        return "", False
    return f"bash: {cmd}: command not found\n", False


def run_fake_command_line(cfg, user, line):
    out, leave = [], False
    for seg in re.split(r";|&&|\|\|", line):
        text, quit_ = fake_command(cfg, user, seg)
        out.append(text)
        leave = leave or quit_
    return "".join(out), leave


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, hp, ip, port):
        self.hp, self.ip, self.port = hp, ip, port
        self.username = None
        self.shell_event = threading.Event()
        self.exec_command = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        ok = password in self.hp.cfg.weak_passwords
        tags = "weak-credential-accepted" if ok else ""
        self.hp.store.add_event("ssh", self.ip, self.port, "auth_attempt", username=username,
                                password=password, success=ok, tags=tags,
                                severity="high" if ok else "low",
                                detail="ACCEPTED (fake shell)" if ok else "rejected")
        self.hp.det.on_auth_attempt(self.ip, "ssh", username, ok)
        print(f"[ssh] {self.ip}:{self.port} login {username!r}/{password!r} -> {'ACCEPT' if ok else 'reject'}", flush=True)
        if ok:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        time.sleep(0.05)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", "ignore")
        self.shell_event.set()
        return True


class SSHHoneypot:
    def __init__(self, cfg, store, det):
        self.cfg, self.store, self.det = cfg, store, det
        self.host_key = load_or_create_host_key(cfg.host_key_path)
        self.running = False
        self.sem = threading.BoundedSemaphore(cfg.max_ssh_connections)
        self.port = cfg.ssh_port

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.cfg.host, self.cfg.ssh_port))
        self.sock.listen(100)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True, name="ssh-accept").start()
        print(f"[ssh] fake SSH listening on {self.cfg.host}:{self.port}", flush=True)

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.sem.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    def _log(self, ip, port, etype, **kw):
        return self.store.add_event("ssh", ip, port, etype, **kw)

    def _handle(self, client, addr):
        ip, port = addr[0], addr[1]
        started = time.time()
        transport = None
        self._log(ip, port, "connect", detail="TCP connection accepted")
        try:
            transport = paramiko.Transport(client)
            transport.local_version = self.cfg.ssh_banner
            transport.add_server_key(self.host_key)
            server = FakeSSHServer(self, ip, port)
            transport.start_server(server=server)
            self._log(ip, port, "client_info", detail="client banner: " + str(transport.remote_version))
            chan = transport.accept(30)
            if chan is None or not server.shell_event.wait(10):
                return
            chan.settimeout(self.cfg.ssh_session_timeout)
            if server.exec_command is not None:
                self._run_exec(chan, server)
            else:
                self._run_shell(chan, server, ip, port)
        except (paramiko.SSHException, EOFError, OSError, socket.timeout):
            self._log(ip, port, "client_info", tags="scanner", severity="low",
                      detail="handshake incomplete (banner grab / port scan)")
        finally:
            self._log(ip, port, "disconnect", detail=f"session lasted {time.time() - started:.1f}s")
            try:
                if transport:
                    transport.close()
                client.close()
            except OSError:
                pass
            self.sem.release()

    def _record_command(self, ip, port, user, line, via):
        tags, sev = self.det.analyze_command(ip, line)
        self._log(ip, port, "command", username=user, command=line, detail=via,
                  tags=",".join(tags), severity=sev)
        print(f"[ssh] {ip}:{port} {via} command: {line!r} {tags}", flush=True)

    def _run_exec(self, chan, server):
        ip, port, user = server.ip, server.port, server.username
        self._record_command(ip, port, user, server.exec_command, "exec")
        out, _ = run_fake_command_line(self.cfg, user, server.exec_command)
        chan.send(out.replace("\n", "\r\n"))
        chan.send_exit_status(0)
        chan.close()

    def _run_shell(self, chan, server, ip, port):
        user = server.username
        prompt = f"{user}@{self.cfg.hostname}:~{'#' if user == 'root' else '$'} "
        chan.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
                  "Last login: Mon Nov  9 08:14:52 2026 from 10.0.2.2\r\n" + prompt)
        buf, count, deadline = "", 0, time.time() + self.cfg.ssh_session_timeout
        while time.time() < deadline and count < self.cfg.max_commands:
            try:
                data = chan.recv(1024)
            except socket.timeout:
                break
            if not data:
                break
            for ch in data.decode("utf-8", "ignore"):
                if ch in "\r\n":
                    chan.send("\r\n")
                    line, buf = buf.strip(), ""
                    if line:
                        count += 1
                        self._record_command(ip, port, user, line, "shell")
                        out, leave = run_fake_command_line(self.cfg, user, line)
                        chan.send(out.replace("\n", "\r\n"))
                        if leave:
                            chan.close()
                            return
                    chan.send(prompt)
                elif ch in "\x7f\b":
                    if buf:
                        buf = buf[:-1]
                        chan.send("\b \b")
                elif ch == "\x03":
                    buf = ""
                    chan.send("^C\r\n" + prompt)
                elif ch == "\x04":
                    chan.close()
                    return
                elif ch.isprintable() and len(buf) < 512:
                    buf += ch
                    chan.send(ch)
        chan.close()
