#!/usr/bin/env python3
"""Inspect PHPSESSID values for the forged-session-id artifact.

Background
----------
The OOM chains overwrite the in-memory session id (a `zend_string`) so that
`php_session_send_cookie()` serialises 4000 bytes instead of the normal
22-48 alphanumeric characters. Two artifacts are observable in the
`Set-Cookie` response header:

1. Length. A legitimate `PHPSESSID` value is 22-48 characters of the
   session id alphabet (`[A-Za-z0-9,-]`). A very long value (>= 128 chars)
   is either a forged id or a deliberately oversized `session.sid_length`.
2. Content. Freed heap memory is copied into the cookie. In the measured
   lab payload the forged value decodes to a run of filler (`M`), a block of
   NUL bytes (`%00`) and, depending on the heap state, pointers or other
   non-alphabet bytes. `%00` and any byte outside the session alphabet are
   impossible in a genuine id.

This tool is offline: it reads values from arguments, stdin or a HAR file.
It sends no traffic and cannot confirm exploitation by itself; it flags the
artifact for correlation with server logs.

Usage
-----
    python3 forged_cookie_check.py 'PHPSESSID=MMMM...; path=/'
    python3 forged_cookie_check.py --stdin < setcookie.txt
    python3 forged_cookie_check.py --har capture.har
    python3 forged_cookie_check.py --value 'MMM%00%00' --json

Exit codes: 0 clean, 1 forged (nul bytes), 2 forged length, 3 input error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse

SID_ALPHABET = re.compile(r"^[A-Za-z0-9,-]+$")
LENGTH_SUSPICIOUS = 128
LEAK_THRESHOLD = 4  # non-alphabet bytes before we call it a leak

VERDICT_CLEAN = "CLEAN"
VERDICT_LENGTH = "FORGED_LENGTH"
VERDICT_LEAK = "FORGED_LEAK"


def extract_values(text: str) -> list[str]:
    """Pull PHPSESSID values out of headers, HAR text or bare values."""
    values = []
    for match in re.finditer(r"PHPSESSID\s*=\s*([^;\r\n\"',:}\s]+)", text):
        values.append(match.group(1))
    if not values:
        stripped = text.strip()
        if stripped and "=" not in stripped and len(stripped) < 65536:
            values.append(stripped)
    # de-duplicate while preserving order
    seen, unique = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def inspect(value: str) -> dict:
    decoded = urllib.parse.unquote_to_bytes(value)
    alphabet_ok = bool(SID_ALPHABET.match(value))
    non_alphabet = [b for b in decoded if chr(b) not in
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,-"]
    nul_count = decoded.count(0)
    notes = []

    if nul_count > 0:
        verdict = VERDICT_LEAK
        notes.append(
            f"{nul_count} NUL byte(s) in the decoded value: impossible in a "
            "genuine session id, consistent with freed heap memory"
        )
    elif len(non_alphabet) >= LEAK_THRESHOLD:
        verdict = VERDICT_LEAK
        notes.append(
            f"{len(non_alphabet)} byte(s) outside the session alphabet in the "
            "decoded value: consistent with a memory copy"
        )
    elif len(decoded) >= LENGTH_SUSPICIOUS:
        verdict = VERDICT_LENGTH
        notes.append(
            f"decoded length {len(decoded)} >= {LENGTH_SUSPICIOUS}: forged id "
            "or an oversized session.sid_length; correlate with server logs"
        )
    else:
        verdict = VERDICT_CLEAN
        notes.append("length and alphabet consistent with a genuine session id")

    if not alphabet_ok and verdict == VERDICT_CLEAN:
        notes.append("value is percent-encoded but decodes to the expected alphabet")

    return {
        "raw_length": len(value),
        "decoded_length": len(decoded),
        "nul_bytes": nul_count,
        "non_alphabet_bytes": len(non_alphabet),
        "alphabet_ok": alphabet_ok,
        "verdict": verdict,
        "notes": notes,
        "head_hex": decoded[:32].hex(),
        "tail_hex": decoded[-16:].hex() if len(decoded) > 16 else decoded.hex(),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Flag forged PHPSESSID artifacts in Set-Cookie values "
                    "(offline, no traffic).")
    ap.add_argument("values", nargs="*", help="headers or raw cookie values")
    ap.add_argument("--stdin", action="store_true", help="read text from stdin")
    ap.add_argument("--har", metavar="FILE", help="read a HAR capture")
    ap.add_argument("--value", help="a single cookie value")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    chunks = list(args.values)
    if args.value:
        chunks.append(args.value)
    if args.stdin:
        chunks.append(sys.stdin.read())
    if args.har:
        try:
            with open(args.har, "r", encoding="utf-8", errors="replace") as fh:
                chunks.append(fh.read())
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
    if not chunks:
        text = sys.stdin.read()
        chunks.append(text)

    values = []
    for chunk in chunks:
        values.extend(extract_values(chunk))
    if not values:
        print("error: no PHPSESSID value found in the input", file=sys.stderr)
        return 3

    results = []
    worst = 0
    for value in values:
        result = inspect(value)
        result["value_prefix"] = value[:12] + ("..." if len(value) > 12 else "")
        results.append(result)
        worst = max(worst, {"CLEAN": 0, "FORGED_LENGTH": 2, "FORGED_LEAK": 1}[result["verdict"]])

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(f"value  {result['value_prefix']}")
            print(f"  raw_len {result['raw_length']}  decoded_len "
                  f"{result['decoded_length']}  nul {result['nul_bytes']}  "
                  f"non_alphabet {result['non_alphabet_bytes']}")
            print(f"  verdict {result['verdict']}")
            for note in result["notes"]:
                print(f"  note    {note}")
            print(f"  head    {result['head_hex']}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
