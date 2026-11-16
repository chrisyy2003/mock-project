# Isolated Web/API security research mock

**SECURITY RESEARCH FIXTURE. AUTHORIZED TESTING ONLY.** The current `fixed-v2`
version repairs the three known Web/API defects; the intentionally vulnerable
baseline is commit `d7e11cfc4add67a01055455dc001da1b69198baa` (`vulnerable-v1`).
Use only this isolated fixture and its synthetic data. Never add real data, reuse
these public test passwords, disable the research gate, or run this as a production product.
The existing Solidity fixture is independent and unchanged.

## Run locally

Python 3.9+; Flask is pinned to 3.1.3, checked against
[official PyPI](https://pypi.org/project/Flask/) on 2026-11-11. Storage uses only
standard-library sqlite3. Requests open the synthetic database read-only.

```sh
cd web-api-mock
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export RESEARCH_ACCESS_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export RESEARCH_SESSION_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export RESEARCH_COMMIT_SHA="$(git rev-parse HEAD)"
PORT=8765 .venv/bin/python app.py
```

Both independent secrets are required and must remain outside Git. Optional
`RESEARCH_DB_PATH` selects a separate database; `.env*`, SQLite files and `.venv/`
are ignored. The runner binds only 127.0.0.1, uses one process and has no watcher
or debugger. No tunnel or public deployment is created. A short-lived approved
HTTPS tunnel must expose only this port; set `RESEARCH_HTTPS=1` before startup to
mark cookies Secure. For longer lived hosting use a dedicated WSGI server per the
[Flask deployment guide](https://flask.palletsprojects.com/en/stable/deploying/).

## Login and scanner compatibility

Only `/` (mock notice/login link) and `/login` (empty form) are public. Every other
route requires the private research key **and** a test identity.

| Test email | Public fixture password | Tenant | Own invoices |
| --- | --- | --- | --- |
| `alice@example.invalid` | `AliceMock-Only-2026!` | `atlas` | 101, 102 |
| `bob@example.invalid` | `BobMock-Only-2026!` | `ledger` | 201, 202 |

For a scanner with natural-language/recorded login: open `/login`, fill **Research
access key** (`research_key`) with the run-specific secret, **Test email**
(`username`) and **Test password** (`password`), then click **Log in to research
mock**. Success redirects to `/dashboard` and sets an HttpOnly, SameSite=Lax cookie
for eight hours. There is no MFA/CAPTCHA/OAuth. Supply two login contexts when
testing tenant isolation. Anonymous scans only test the gate.

An API scanner may instead use global `X-Research-Key` plus HTTP Basic with a
test account. A header alone/account alone is insufficient. A global key header
also permits submitting the login form without repeating its key field. Provide
the private key through protected scanner auth configuration, never a query URL
or committed source. Key rotation invalidates existing gate cookies.

## Scope and version

Only the exact approved fixture origin is in scope. Exclude other hosts,
infrastructure, denial of service and real data. After login, `/scope.json` and
`/openapi.json` describe the small scope/API; `/health` reports readiness. The
dashboard links to the current identity, own invoice list and search forms.

`X-Commit-SHA` reports `RESEARCH_COMMIT_SHA` (or clearly `local-uncommitted`);
`X-Research-Release`, `/health` and the OpenAPI version are `fixed-v2` in the current
code. Capture these identifiers for both the baseline scan and the repair/retest;
changing a Git branch does not update an already-running process. The baseline
commit and current repair differ as follows:

| Baseline defect | Reproduction as Alice on `vulnerable-v1` | Current `fixed-v2` outcome |
| --- | --- | --- |
| Reflected XSS, CWE-79 | Set `/search` query `q` to `<script>document.documentElement.dataset.researchXss="executed"</script>`; result emits executable HTML | Term appears as text; DOM marker never executes |
| Invoice IDOR, CWE-639 | `/api/invoices` lists only 101/102, but `/api/invoices/201` returns Ledger's row with 200 | Alice gets 404; Bob still gets his invoice with 200 |
| SQL injection, CWE-89 | `/api/search?q=missing-fixture-name` gives zero rows; set `q` to `missing-fixture-name%' OR 1=1 -- ` to return all four rows across tenants | Payload is literal; zero rows and tenant filter preserved |

Use only these harmless read/DOM proof payloads. Do not turn off the gate to make
a scan easier. The repair removes the unsafe template filter, binds the tenant
and search term as SQL parameters, and scopes invoice lookup to the current tenant.

## Verify

```sh
.venv/bin/python verify.py
```

Eight regression checks use a real random loopback HTTP port and temporary SQLite
database: gate, tenant-scoped lists and details, normal search, literal SQL payloads,
escaped HTML, metadata/header auth, and logout. Alice cannot read Bob's invoice,
Bob can still read it, and ordinary searches return only the caller's tenant.
The HTTP XSS check verifies that the script markup is escaped, not emitted as an
executable tag. No external network, GitHub, SaaS, blockchain or real business
database is used.

These local checks do not establish that a SaaS scan or retest has passed. The
initial 0.security PR Security review reported the three baseline defects on
[PR #1](https://github.com/chrisyy2003/mock-project/pull/1). SaaS re-evaluation of
`fixed-v2` is pending; record the tested commit, deployed release and actual
platform verdict before claiming closure. An independently running `vulnerable-v1`
process must remain separate until its baseline assessment is complete.
