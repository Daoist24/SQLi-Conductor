#!/usr/bin/env python3
"""Runner for the sqli-conductor skill.

Builds a fresh temp harness from references/sqli_blind_reference.py on every
invocation by substituting TARGET_URL (and optionally PARAM_NAME) from the
command line. The temp harness is deleted before the script exits, so nothing
persists between runs.

Usage:
    python3 run.py <TARGET_URL> [PARAM_NAME]
Example:
    python3 run.py https://xxx.web-security-academy.net/login username
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REF_PATH = os.path.join(HERE, "references", "sqli_blind_reference.py")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run.py <TARGET_URL> [PARAM_NAME]")
        sys.exit(2)

    target_url = sys.argv[1].rstrip("/")
    param_name = sys.argv[2] if len(sys.argv) > 2 else "username"

    with open(REF_PATH) as f:
        src = f.read()

    src = re.sub(
        r'TARGET_URL = "https://[^"]*/login"',
        f'TARGET_URL = "{target_url}"',
        src,
    )
    src = re.sub(
        r'PARAM_NAME = "username"',
        f'PARAM_NAME = "{param_name}"',
        src,
    )

    fd, tmp = tempfile.mkstemp(prefix="sqli_blind_run_", suffix=".py")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(src)
        subprocess.run(["python3", tmp], check=False)
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    main()
