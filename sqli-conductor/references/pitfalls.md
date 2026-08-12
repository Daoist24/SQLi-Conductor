# SQL Injection Debug Rules — Lessons from the LLM Comparison

Distilled from the `LLM_SQLi_Comparison.docx` report. These are the rules that
make blind boolean SQL injection through a **login form** work. Every one of
these was originally implemented wrong by at least one LLM (Claude, Gemini,
Mistral, Qwen, Zhipu).

> Scope note: `SKILL.md` v1 confirms the injection and fingerprints the DBMS
> only — it does not extract data. Rules 2–4, 8–9 below apply to data
> extraction; keep them if the skill is later extended to extract credentials.

## 1. Use OR, not AND, in login-form injection

`username='' AND condition` matches no rows when the input matches nothing, so
`AND FALSE = FALSE` always — every query returns no redirect and the oracle is
unusable. Login-form injection requires `OR`:

```
username=' OR (condition) -- ' AND password=...
```

All five LLMs independently chose `AND`. Treat `AND` as a bug.

## 2. Sort the character set by ordinal value

`string.printable` is **not** in ASCII order. Binary search requires a
monotonically sorted search space:

```python
CHARS = ''.join(sorted(string.printable.strip(), key=ord))
```

Unsorted CHARS silently produces wrong characters.

## 3. Guard against end-of-string with LENGTH(SUBSTRING(...)) > 0

MySQL `SUBSTRING` returns an **empty string**, not `NULL`, for out-of-bounds
positions. Testing `IS NOT NULL` never fires. Stop the loop only when:

```sql
LENGTH(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1)) > 0
```

is FALSE.

## 4. Two-stage .format() needs escaped braces

The template is formatted twice — once with the `subquery`, once per probe
with `pos`/`ord`. The first pass must leave `{pos}` and `{ord}` intact:

```python
EXTRACT_TMPL = "ASCII(SUBSTRING(({subquery}),{{pos}},1))>{{ord}}"
base_tmpl = EXTRACT_TMPL.format(subquery=USERQUERY)   # -> {pos} survives
condition = base_tmpl.format(pos=pos, ord=ord(CHARS[mid]))
```

## 5. Prefer the redirect oracle over body-length comparison

Across different sessions the baseline page length shifts, and content
comparison is fragile. On the login lab the reliable oracle is:

```
TRUE  = 302/303 with "my-account" in Location header
FALSE = no redirect
```

## 6. Handle CSRF — the lab will not respond without it

The login POST requires a `csrf` token bound to the session cookie:

1. GET `/login` to establish the session and read
   `name="csrf" value="..."`.
2. Include `csrf` in every POST.
3. The token survives failed logins but **not** successful ones (they
   redirect), so after any 3xx response start a fresh session + token.

## 7. Use POST for login forms, GET only for query-string params

A GET request to a form endpoint returns 400/405 and can never trigger the
oracle.

## 8. Use binary search, never a linear scan

Probing every character sequentially is ~15x slower and triples the requests
that can fail. Binary search is ~7–8 requests per character.

## 9. Never append inside the binary-search loop

Append a character exactly once per position, after the search finishes.
Appending on every iteration (Zhipu's bug) or selecting the wrong index
inflates/garble the output.

## Per-model failures seen in the report

| Model | Failure |
|---|---|
| Mistral | Equality match (`=`) instead of ASCII `>` comparison in binary search |
| Qwen   | GET instead of POST; fragile `string.split()` template parsing; uninstantiated classes in `__main__` (NameError) |
| Claude | GET instead of POST; linear scan instead of binary search |
| Zhipu  | GET instead of POST; extraction loop appended every iteration, selected wrong character |
| Gemini | GET instead of POST; binary search baseline passed as 0 → every non-empty response evaluated TRUE |
