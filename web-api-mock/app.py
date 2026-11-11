"""Access-controlled security research fixture with regression fixes. Never use real data."""

import hashlib
import hmac
import os
import sqlite3
from datetime import timedelta
from pathlib import Path
from wsgiref.simple_server import make_server

from flask import Flask, g, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

USERS = {
    "alice@example.invalid": {
        "tenant": "atlas",
        "password_hash": generate_password_hash("AliceMock-Only-2026!", method="pbkdf2:sha256:600000"),
    },
    "bob@example.invalid": {
        "tenant": "ledger",
        "password_hash": generate_password_hash("BobMock-Only-2026!", method="pbkdf2:sha256:600000"),
    },
}
BASE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attention security research mock</title>
<style>body{font:16px system-ui;max-width:760px;margin:40px auto;padding:0 20px}
label{display:block;margin:12px 0}input{padding:8px}pre{white-space:pre-wrap}
nav a{margin-right:16px}</style>
<h1>Attention security research mock</h1>
<p>Synthetic data only. Authorized security testing only.</p>
<!-- CONTENT --></html>"""


def page(content, **values):
    return render_template_string(BASE.replace("<!-- CONTENT -->", content), **values)


def create_app():
    access_key = os.environ.get("RESEARCH_ACCESS_KEY", "")
    session_secret = os.environ.get("RESEARCH_SESSION_SECRET", "")
    if len(access_key) < 32 or len(session_secret) < 32:
        raise RuntimeError("Set independent research access/session secrets (32+ characters)")
    if hmac.compare_digest(access_key, session_secret):
        raise RuntimeError("Research access and session secrets must be different")
    gate_fingerprint = hashlib.sha256(access_key.encode()).hexdigest()
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=session_secret,
        SESSION_COOKIE_NAME="research_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("RESEARCH_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=16_384,
    )
    database = Path(os.environ.get("RESEARCH_DB_PATH", Path(__file__).with_name("mock.sqlite3"))).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY, tenant TEXT NOT NULL,
                customer TEXT NOT NULL, amount INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO invoices VALUES
                (101, 'atlas', 'Atlas synthetic customer A', 125),
                (102, 'atlas', 'Atlas synthetic customer B', 250),
                (201, 'ledger', 'Ledger synthetic customer A', 375),
                (202, 'ledger', 'Ledger synthetic customer B', 500);
        """)

    def valid_key(value):
        return bool(value) and hmac.compare_digest(value, access_key)

    def valid_user(username, password):
        user = USERS.get(username)
        return bool(user) and check_password_hash(user["password_hash"], password or "")

    def query(sql, parameters=()):
        # Keep security-research queries read-only against the synthetic database.
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]

    @app.before_request
    def require_research_identity():
        if request.path in {"/", "/login"}:
            return None
        key_allowed = valid_key(request.headers.get("X-Research-Key", ""))
        cookie_allowed = hmac.compare_digest(session.get("gate", ""), gate_fingerprint)
        if not key_allowed and not cookie_allowed:
            return jsonify(error="Research access key required"), 401
        username = session.get("username") if cookie_allowed else None
        if key_allowed and request.authorization and request.authorization.type == "basic":
            auth = request.authorization
            username = auth.username if valid_user(auth.username, auth.password) else None
        if username not in USERS:
            return jsonify(error="Test-user login required"), 401
        g.username = username
        g.tenant = USERS[username]["tenant"]
        return None

    @app.after_request
    def response_metadata(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        response.headers["X-Research-Release"] = "fixed-v2"
        response.headers["X-Commit-SHA"] = os.environ.get("RESEARCH_COMMIT_SHA", "local-uncommitted")
        return response

    @app.get("/")
    def index():
        return page('<p>This isolated mock contains no real customer data.</p><a href="/login">Research login</a>')

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            key = request.form.get("research_key", "") or request.headers.get("X-Research-Key", "")
            username = request.form.get("username", "")
            if valid_key(key) and valid_user(username, request.form.get("password")):
                session.clear()
                session.update(gate=gate_fingerprint, username=username)
                session.permanent = True
                return redirect("/dashboard", code=303)
            error = "Invalid research key or test account"
        return page("""<h2>Research login</h2><p>{{ error or '' }}</p>
            <form method="post" action="/login">
            <label>Research access key <input name="research_key" type="password" autocomplete="off"></label>
            <label>Test email <input name="username" type="email" autocomplete="username" required></label>
            <label>Test password <input name="password" type="password" autocomplete="current-password" required></label>
            <button type="submit">Log in to research mock</button></form>""", error=error), (401 if error else 200)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect("/", code=303)

    @app.get("/dashboard")
    def dashboard():
        return page("""<p>Signed in as {{ username }} · tenant {{ tenant }}</p>
            <nav><a href="/search">Customer search</a><a href="/api/me">Current identity</a>
            <a href="/api/invoices">My invoices</a><a href="/scope.json">Test scope</a>
            <a href="/openapi.json">API schema</a></nav>
            <h2>Your synthetic invoices</h2><ul>{% for item in invoices %}
            <li><a href="/api/invoices/{{ item.id }}">Invoice {{ item.id }}</a> · {{ item.customer }}</li>
            {% endfor %}</ul><form action="/api/search"><label>Invoice API search
            <input name="q" value="Atlas"></label><button>Search API</button></form>
            <form method="post" action="/logout"><button>Log out</button></form>""",
            username=g.username, tenant=g.tenant,
            invoices=query("SELECT * FROM invoices WHERE tenant = ? ORDER BY id", (g.tenant,)))

    @app.get("/health")
    def health():
        return jsonify(status="ok", fixture="synthetic-security-research", release="fixed-v2")

    @app.get("/scope.json")
    def scope():
        return jsonify(
            purpose="Authorized testing of this isolated synthetic application only",
            paths=["/dashboard", "/search", "/api/me", "/api/invoices", "/api/invoices/{id}", "/api/search"],
            accounts=[{"username": name, "tenant": value["tenant"]} for name, value in USERS.items()],
            excluded=["Other hosts", "Infrastructure", "Denial of service", "Real customer data"],
        )

    @app.get("/openapi.json")
    def openapi():
        paths = {}
        for path, summary in {
            "/api/me": "Get the authenticated test identity",
            "/api/invoices": "List invoices owned by the current tenant",
            "/api/invoices/{invoice_id}": "Get one invoice; tenant ownership is required",
            "/api/search": "Search invoices by customer name within the current tenant",
        }.items():
            operation = {"summary": summary, "responses": {"200": {"description": "Synthetic JSON data"}, "401": {"description": "Research authentication required"}}}
            if "{invoice_id}" in path:
                operation["parameters"] = [{"name": "invoice_id", "in": "path", "required": True, "schema": {"type": "integer"}}]
            if path == "/api/search":
                operation["parameters"] = [{"name": "q", "in": "query", "schema": {"type": "string"}}]
            paths[path] = {"get": operation}
        return jsonify(openapi="3.0.3", info={"title": "Synthetic research invoice API", "version": "fixed-v2"},
                       security=[{"researchKey": [], "testLogin": []}], paths=paths,
                       components={"securitySchemes": {"researchKey": {"type": "apiKey", "in": "header", "name": "X-Research-Key"}, "testLogin": {"type": "http", "scheme": "basic"}}})

    @app.get("/api/me")
    def me():
        return jsonify(username=g.username, tenant=g.tenant)

    @app.get("/api/invoices")
    def invoices():
        return jsonify(data=query("SELECT * FROM invoices WHERE tenant = ? ORDER BY id", (g.tenant,)))

    @app.get("/search")
    def search():
        return page("""<h2>Customer search</h2><form action="/search">
            <label>Search <input name="q" value="{{ q }}"></label><button>Search</button></form>
            <p>Search results for: {{ q }}</p><a href="/dashboard">Dashboard</a>""", q=request.args.get("q", ""))

    @app.get("/api/invoices/<int:invoice_id>")
    def invoice(invoice_id):
        rows = query("SELECT * FROM invoices WHERE id = ? AND tenant = ?", (invoice_id, g.tenant))
        return (jsonify(data=rows[0]), 200) if rows else (jsonify(error="Invoice not found"), 404)

    @app.get("/api/search")
    def api_search():
        term = request.args.get("q", "")
        sql = "SELECT * FROM invoices WHERE tenant = ? AND customer LIKE ? ORDER BY id"
        try:
            return jsonify(data=query(sql, (g.tenant, f"%{term}%")))
        except sqlite3.Error:
            return jsonify(error="Invalid search query"), 400

    return app


if __name__ == "__main__":
    # Loopback-only, single-process WSGI fixture runner; no debugger or file watcher.
    with make_server("127.0.0.1", int(os.environ.get("PORT", "8765")), create_app()) as server:
        server.serve_forever()
