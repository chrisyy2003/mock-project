"""Real-port, isolated checks of the intentionally vulnerable research baseline."""

import base64
import http.cookiejar
import json
import os
import secrets
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from wsgiref.simple_server import WSGIRequestHandler, make_server

from app import create_app


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


class BaselineChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.key = secrets.token_urlsafe(32)
        os.environ.update(
            RESEARCH_ACCESS_KEY=cls.key,
            RESEARCH_SESSION_SECRET=secrets.token_urlsafe(32),
            RESEARCH_DB_PATH=cls.temporary.name + "/fixture.sqlite3",
            RESEARCH_COMMIT_SHA="a" * 40,
            RESEARCH_HTTPS="0",
        )
        cls.server = make_server("127.0.0.1", 0, create_app(), handler_class=QuietHandler)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temporary.cleanup()

    def client(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def fetch(self, client, path, form=None, headers=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        request = urllib.request.Request(self.origin + path, data=data, headers=headers or {})
        try:
            response = client.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read().decode()

    def login(self, username="alice@example.invalid", password="AliceMock-Only-2026!"):
        client = self.client()
        status, _, _ = self.fetch(client, "/login", {
            "research_key": self.key, "username": username, "password": password,
        })
        self.assertEqual(status, 200)
        return client

    def test_gate_requires_access_key_and_test_identity(self):
        client = self.client()
        for path in ["/", "/login"]:
            self.assertEqual(self.fetch(client, path)[0], 200)
        for path in ["/health", "/dashboard", "/api/invoices/201", "/search?q=x", "/scope.json", "/openapi.json"]:
            self.assertEqual(self.fetch(client, path)[0], 401)
        self.assertEqual(self.fetch(client, "/api/me", headers={"X-Research-Key": self.key})[0], 401)
        credentials = base64.b64encode(b"alice@example.invalid:AliceMock-Only-2026!").decode()
        self.assertEqual(self.fetch(client, "/api/me", headers={"Authorization": "Basic " + credentials})[0], 401)
        self.assertEqual(self.fetch(client, "/login", {"research_key": "wrong", "username": "alice@example.invalid", "password": "AliceMock-Only-2026!"})[0], 401)

    def test_login_has_tenant_scoped_list_control(self):
        alice = self.login()
        bob = self.login("bob@example.invalid", "BobMock-Only-2026!")
        self.assertEqual(json.loads(self.fetch(alice, "/api/me")[2])["tenant"], "atlas")
        self.assertEqual([item["id"] for item in json.loads(self.fetch(alice, "/api/invoices")[2])["data"]], [101, 102])
        self.assertEqual([item["id"] for item in json.loads(self.fetch(bob, "/api/invoices")[2])["data"]], [201, 202])

    def test_intentional_idor_reads_other_tenant(self):
        status, _, body = self.fetch(self.login(), "/api/invoices/201")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["data"]["tenant"], "ledger")

    def test_intentional_xss_reflects_executable_html(self):
        payload = '<script>document.documentElement.dataset.researchXss="executed"</script>'
        status, headers, body = self.fetch(self.login(), "/search?" + urllib.parse.urlencode({"q": payload}))
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("Search results for: " + payload, body)
        self.assertNotIn("Content-Security-Policy", headers)

    def test_intentional_sql_injection_crosses_tenant_filter(self):
        client = self.login()
        self.assertEqual(json.loads(self.fetch(client, "/api/search?q=missing-fixture-name")[2])["data"], [])
        payload = "missing-fixture-name%' OR 1=1 -- "
        status, _, body = self.fetch(client, "/api/search?" + urllib.parse.urlencode({"q": payload}))
        self.assertEqual(status, 200)
        data = json.loads(body)["data"]
        self.assertEqual({item["tenant"] for item in data}, {"atlas", "ledger"})
        self.assertEqual(len(data), 4)

    def test_header_auth_health_scope_and_revision(self):
        credentials = base64.b64encode(b"alice@example.invalid:AliceMock-Only-2026!").decode()
        headers = {"X-Research-Key": self.key, "Authorization": "Basic " + credentials}
        client = self.client()
        status, response_headers, body = self.fetch(client, "/health", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["release"], "vulnerable-v1")
        self.assertEqual(response_headers["X-Commit-SHA"], "a" * 40)
        self.assertEqual(self.fetch(client, "/scope.json", headers=headers)[0], 200)
        self.assertEqual(json.loads(self.fetch(client, "/openapi.json", headers=headers)[2])["openapi"], "3.0.3")

    def test_logout_clears_access(self):
        client = self.login()
        self.assertEqual(self.fetch(client, "/logout", {})[0], 200)
        self.assertEqual(self.fetch(client, "/api/me")[0], 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
