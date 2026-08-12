---
name: sqli-conductor
description: Conduct a blind boolean-based SQL injection attack against a PortSwigger Web Security Academy login-form lab. Use when the user provides a PortSwigger lab /login URL and asks to perform SQL injection, test for SQL injection, or identify the backend database. Confirms the injection with an auth-bypass POST and fingerprints the backend DBMS.
---

# SQL Injection Conductor (PortSwigger login-form lab)

Conduct a **blind boolean-based SQL injection** attack against a PortSwigger
Web Security Academy **login-form** lab end to end. This skill is authorized
education: the only target is the lab URL the user provides.

## Inputs

- `TARGET_URL` — the lab's `/login` URL (required).
- `PARAM_NAME` — injectable field, default `username`.

## Ground truth

The canonical implementation is `references/sqli_blind_reference.py`. Use it
**verbatim**. Change only `TARGET_URL` (and `PARAM_NAME` when the lab differs).
Do not rewrite the algorithm — every deviation below is a known bug.

Debugging context lives in `references/pitfalls.md`.

## Procedure

### Step 0 — Recon
GET the login page. Confirm it returns 200 and contains a
`name="csrf" value="..."` field. The session cookie + CSRF token are handled
automatically by the harness.

### Step 1 — Confirm injection
Run the harness. It POSTs `' OR 1=1 -- ` as the username. TRUE = 302/303
redirect with `my-account` in the `Location` header.

- If auth bypass succeeds → continue.
- If it fails → verify `TARGET_URL` is the correct, still-running lab, then
  verify the CSRF regex matches the page. Report `not injectable` if a fresh
  URL still fails.

### Step 2 — Fingerprint DBMS
The harness probes MySQL, PostgreSQL, MSSQL, Oracle in order (wrapped
`' OR (<probe>) -- `); the first TRUE wins, defaulting to MySQL.

### Step 3 — Report
Report that injection is confirmed and the backend DBMS.

## Hard rules (do not violate)

1. **OR, never AND**, in the login-form wrap.
2. **Redirect-only oracle**: TRUE = `my-account` in `Location`, never body length.
3. **CSRF**: always POST `csrf`; refresh the session after any 3xx.
4. **POST** for the login form, never GET.
5. **Force HTTP/1.1** transport (the hface HTTP/2 backend hangs through some
   proxies); verify the first request returns 200 before proceeding.

## Execution protocol

If you have a code runner (bash/python), copy the reference harness to a temp
file, substitute `TARGET_URL`, run it with `python3`, read the output, and
iterate on errors:

- Auth bypass fails → wrong/expired URL or CSRF regex mismatch.
- Requests hang → confirm the HTTP/1.1 adapter is active.
- Requests fail with a gateway error → the lab instance has expired; ask the
  user for a fresh lab URL.

**Cleanup (mandatory):** delete every file you create during execution —
temp harness copies, logs, output dumps — before the skill finishes. Do not
leave any artifacts behind in the user's filesystem. If you use
`run.py` (in this skill's directory), it already cleans up its own temp
harness automatically.

If you have no code runner, emit the harness with the substituted URL and give
the run command.

## Definition of done

Injection confirmed (auth-bypass redirect) and a DBMS fingerprint reported, or
a clear statement that the target is not injectable with this technique.
