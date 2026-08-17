---
name: sqli-conductor
description: Conduct a blind boolean-based SQL injection attack against a PortSwigger Web Security Academy login-form lab. Use when the user provides a PortSwigger lab /login URL and asks to perform SQL injection, test for SQL injection, or identify the backend database. Confirms the injection with an auth-bypass POST and fingerprints the backend DBMS.
---

# SQL Injection Conductor

Conduct a blind boolean-based SQL injection against a PortSwigger login-form
lab. Authorized education only — target is the URL the user provides.

## Run

```bash
python3 <skill_dir>/run.py <TARGET_URL> [PARAM_NAME]
```

`TARGET_URL` is the lab's `/login` URL. `PARAM_NAME` defaults to `username`.

The script returns a single JSON line. Interpret it:

- `"status": "success"` — injection confirmed; `"dbms"` field has the backend.
- `"status": "not_injectable"` — auth bypass failed; target is not injectable.
- `"status": "error"` — runtime failure; check `"message"` and `"raw"` fields.

## Rules

1. OR, never AND, in the login-form wrap.
2. Redirect-only oracle: TRUE = `my-account` in `Location`, never body length.
3. CSRF is handled by the harness; do not bypass it manually.
4. POST for login forms, never GET.

## Done

Report injection confirmed + DBMS, or report not injectable.
