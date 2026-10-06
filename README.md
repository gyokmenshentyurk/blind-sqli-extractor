# Blind SQL Injection — Conditional Response Password Extractor

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Topic](https://img.shields.io/badge/Topic-Web%20Security-orange)

A fast, automated extractor for the **PortSwigger Web Security Academy** lab
*"Blind SQL injection with conditional responses"*. It recovers the
`Administrator` password character-by-character using a boolean-based blind
SQL injection, replacing ~720+ manual Intruder requests with ~165 requests
via binary search.

## The vulnerability

The application tracks users with a cookie and embeds its value directly
into a SQL query. Because the query result changes the page content, it acts
as a **boolean oracle**:

| Injected condition | Response |
|---|---|
| TRUE  | Page contains `Welcome back` |
| FALSE | `Welcome back` absent |

## Payload anatomy

```sql
xyz' AND (SELECT ASCII(SUBSTRING((SELECT Password FROM Users
    WHERE Username = 'Administrator'), 1, 1))) > 109-- 
```

| Fragment | Purpose |
|---|---|
| `xyz'` | Terminates the original string literal in the SQL query |
| `AND (...)` | Appends our boolean condition |
| `SUBSTRING(..., pos, 1)` | Isolates a single character of the password |
| `ASCII(...)` | Converts to numeric code — deterministic ordering, immune to collation quirks |
| `> 109` | Comparison used to binary search the character's code point |
| `-- ` | Comments out the remainder of the original query |

## Why binary search?

A naive character-by-character sweep over `[a-z0-9]` needs up to
20 × 36 = **720 requests**. Binary searching the full printable ASCII range
(32–126) needs only ⌈log₂ 95⌉ = **7 requests per character**:

| Strategy | Requests |
|---|---|
| Intruder cluster bomb (linear) | ~720 |
| This script (binary search + verification) | **~165** |

## How it works

1. **Oracle sanity check** — confirms `1=1` yields the marker and `1=2`
   does not, before spending any requests (catches expired sessions and
   payload typos).
2. **Length verification** — one request confirms `LENGTH(Password) = 20`.
3. **Per-character binary search** — for each position, halves the ASCII
   range with `>` comparisons until one code point remains.
4. **Per-character verification** — the result is re-confirmed with `=`,
   and the position is retried if a transient network error corrupted the
   search.
5. Requests are sequential with a small delay to avoid lab rate limits.

## Usage

```bash
pip install requests
python3 blind_sqli_extract.py
```

Fill in the two placeholders at the top of the script:

```python
LAB_URL = "https://YOUR-LAB-ID.web-security-academy.net/"
SESSION_COOKIE = "YOUR_SESSION_COOKIE_VALUE"
```

## Sample output

```
============================================================
Blind SQLi (conditional responses) - password extractor
============================================================
[*] Sanity check: TRUE condition (1=1) ... ok (Welcome back seen)
[*] Sanity check: FALSE condition (1=2) ... ok (no Welcome back)
[*] Verifying password length == 20 ... ok
[+] Progress: 2f8a...
============================================================
[+] Administrator password: <recovered>
============================================================
Next: log in as Administrator with this password to solve the lab.
```

## Repository structure

```
.
├── blind_sqli_extract.py   # extractor script
├── README.md
├── LICENSE
└── .gitignore
```

## Ethical use

This tool is for **authorized, educational use only** — specifically the
intentionally vulnerable PortSwigger Web Security Academy labs. Do not run
it against systems you do not own or lack explicit written permission to
test. Unauthorized access to computer systems is illegal.

## License

[MIT](LICENSE)
