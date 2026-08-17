#!/usr/bin/env python3
"""End-to-end SQLi conductor runner.

Builds a fresh temp harness from references/sqli_blind_reference.py,
substitutes TARGET_URL / PARAM_NAME from the command line, runs it,
captures output, and emits a single JSON line with the result.

Exit codes:
    0  — injection confirmed
    1  — target not injectable (auth bypass failed)
    2  — runtime error (wrong args, harness crash, network issue)

Usage:
    python3 run.py <TARGET_URL> [PARAM_NAME]
"""

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REF_PATH = os.path.join(HERE, "references", "sqli_blind_reference.py")


def build_harness(target_url, param_name):
    """Read the reference harness, substitute config, write a temp copy."""
    with open(REF_PATH) as f:
        src = f.read()

    src = re.sub(
        r'TARGET_URL = "https://[^"]*"',
        f'TARGET_URL = "{target_url}"',
        src,
    )
    src = re.sub(
        r'PARAM_NAME = "username"',
        f'PARAM_NAME = "{param_name}"',
        src,
    )

    fd, tmp = tempfile.mkstemp(prefix="sqli_blind_run_", suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(src)
    return tmp


def run_harness(tmp_path):
    """Run the harness and return (stdout, stderr, returncode)."""
    result = subprocess.run(
        ["python3", tmp_path],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout, result.stderr, result.returncode


def parse_output(stdout, stderr, rc):
    """Parse harness output into a structured result dict."""
    combined = stdout + "\n" + stderr

    # Check for auth bypass success/failure
    if "[+] Auth bypass successful" in stdout:
        injectable = True
    elif "[-] Auth bypass failed" in stdout:
        return {"status": "not_injectable", "message": "Auth bypass failed", "raw": combined.strip()}
    elif "[!] CSRF not found" in stdout:
        return {"status": "error", "message": "CSRF token not found — wrong URL or lab expired", "raw": combined.strip()}
    elif "[!] Request failed" in stdout:
        return {"status": "error", "message": "Network request failed", "raw": combined.strip()}
    else:
        return {"status": "error", "message": "Unexpected harness output", "raw": combined.strip()}

    # Extract DBMS
    dbms = "unknown"
    m = re.search(r"\[\+\] Detected DBMS: (\w+)", stdout)
    if m:
        dbms = m.group(1)

    return {"status": "success", "injectable": injectable, "dbms": dbms}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "Usage: python3 run.py <TARGET_URL> [PARAM_NAME]"}))
        sys.exit(2)

    target_url = sys.argv[1].rstrip("/")
    param_name = sys.argv[2] if len(sys.argv) > 2 else "username"

    if not target_url.startswith("http"):
        print(json.dumps({"status": "error", "message": f"Invalid URL: {target_url}"}))
        sys.exit(2)

    tmp_path = None
    try:
        tmp_path = build_harness(target_url, param_name)
        stdout, stderr, rc = run_harness(tmp_path)
        result = parse_output(stdout, stderr, rc)
        print(json.dumps(result))
        sys.exit(0 if result["status"] == "success" else (1 if result["status"] == "not_injectable" else 2))
    except subprocess.TimeoutExpired:
        print(json.dumps({"status": "error", "message": "Harness timed out after 60s"}))
        sys.exit(2)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(2)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == "__main__":
    main()
