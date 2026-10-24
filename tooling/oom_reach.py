#!/usr/bin/env python3
"""php2shell OOM reachability estimator (offline, no network traffic).

Answers one question before anyone runs a destructive OOM probe: can a
multipart body even exhaust `memory_limit` on this configuration?

Model
-----
During multipart parsing PHP keeps more than one live copy of each field
value. In the calibrated lab payloads the steady-state footprint of the
request is approximately:

    footprint ~= 2 * body_size + 1 MiB

where 1 MiB is a conservative floor for the request, the session and the
script itself. This model is empirical: it was fitted on the calibration
points below and it is a planning aid, not a guarantee. Real allocator
behaviour, extensions, opcache and the SAPI add variance.

Calibration points (measured, PHP 8.4.26, one worker, multipart A payload)

    memory_limit  post_max_size  body     result
    8M            64M            3.7M     OOM (8/8 with display_errors=On)
    32M           8M             3.7M     no OOM
    128M          8M             3.7M     no OOM
    512M          512M           12M      no OOM
    512M          512M           480M     OOM
    128M          512M           114M     OOM (500, empty body)
    128M          512M           15M      no OOM (200)

Consequence for stock configurations: with the PHP defaults
(`memory_limit=128M`, `post_max_size=8M`) the largest body an attacker can
submit is 8 MiB, so the reachable footprint is ~17 MiB, far below 128 MiB.
The two 128M/512M rows were measured on 2026-10-24 and close the loop: the
primitive only fires when `post_max_size` is raised to allow the large body.
The OOM primitive that starts the public chains is not reachable without a
configuration change (a lowered `memory_limit` or a raised `post_max_size`).

Usage
-----
    python3 oom_reach.py --memory-limit 128M --post-max-size 8M
    python3 oom_reach.py -m 8M -p 64M -b 3.7M
    python3 oom_reach.py -m 128M -p 8M --json
    python3 oom_reach.py --calibration

Exit codes: 0 reachable, 1 unreachable, 2 borderline, 3 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys

MIB = 1024 * 1024
OVERHEAD = 1 * MIB
COPIES = 2

VERDICT_REACHABLE = "REACHABLE"
VERDICT_BORDERLINE = "BORDERLINE"
VERDICT_UNREACHABLE = "UNREACHABLE"


def parse_size(text: str) -> int:
    """Parse PHP-style sizes: 128M, 8M, 512K, 1G, 1048576, 3.7M."""
    s = text.strip().upper().replace(" ", "")
    factors = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if s and s[-1] in factors:
        number, factor = s[:-1], factors[s[-1]]
    else:
        number, factor = s, 1
    try:
        value = float(number) * factor
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid size: {text!r}") from exc
    if value < 0:
        raise argparse.ArgumentTypeError(f"negative size: {text!r}")
    return int(value)


def fmt(size: int) -> str:
    if size >= 1024 ** 3 and size % (1024 ** 3) == 0:
        return f"{size // (1024 ** 3)}G"
    if size >= MIB:
        return f"{size / MIB:.1f}M".replace(".0M", "M")
    if size >= 1024:
        return f"{size // 1024}K"
    return f"{size}B"


def estimate(memory_limit: int, post_max_size: int, body_size: int | None,
             upload_max_filesize: int | None) -> dict:
    cap = post_max_size
    if upload_max_filesize is not None:
        cap = min(cap, upload_max_filesize)
    body = cap if body_size is None else min(body_size, cap)
    footprint = COPIES * body + OVERHEAD

    if footprint > 1.25 * memory_limit:
        verdict = VERDICT_REACHABLE
    elif footprint > 0.90 * memory_limit:
        verdict = VERDICT_BORDERLINE
    else:
        verdict = VERDICT_UNREACHABLE

    notes = []
    if body_size is None:
        notes.append(
            "body_size not supplied: assuming the attacker uses the full "
            f"post_max_size cap ({fmt(post_max_size)})"
        )
    elif body_size > cap:
        notes.append(
            f"requested body {fmt(body_size)} exceeds the cap "
            f"({fmt(cap)}); using the cap"
        )
    if upload_max_filesize is not None and upload_max_filesize < post_max_size:
        notes.append(
            "upload_max_filesize is the binding limit for the file part; "
            "plain form fields are still bounded by post_max_size"
        )
    if verdict == VERDICT_UNREACHABLE:
        notes.append(
            "the standard OOM-driven chains cannot start on this "
            "configuration; request-level chains that do not need an OOM are "
            "not covered by this estimate"
        )
    if verdict == VERDICT_BORDERLINE:
        notes.append(
            "borderline: the calibration point at this ratio (8M limit, "
            "3.7M body) did abort 8/8, but allocator and extension variance "
            "is high; treat a borderline verdict as 'confirm only in a "
            "disposable replica'"
        )

    return {
        "memory_limit": memory_limit,
        "post_max_size": post_max_size,
        "upload_max_filesize": upload_max_filesize,
        "body_used": body,
        "body_cap": cap,
        "model": f"footprint = {COPIES} * body + {fmt(OVERHEAD)}",
        "footprint": footprint,
        "ratio": round(footprint / memory_limit, 3) if memory_limit else None,
        "verdict": verdict,
        "notes": notes,
    }


CALIBRATION = [
    ("8M", "64M", "3.7M", "OOM 8/8"),
    ("32M", "8M", "3.7M", "no OOM"),
    ("128M", "8M", "3.7M", "no OOM"),
    ("512M", "512M", "12M", "no OOM"),
    ("512M", "512M", "480M", "OOM"),
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Estimate whether a multipart body can exhaust "
                    "memory_limit (offline; sends no traffic).",
        epilog="Model: footprint = 2 * body + 1M. Planning aid, not a "
               "guarantee. See the module docstring for calibration.",
    )
    ap.add_argument("-m", "--memory-limit", type=parse_size, default=None,
                    help="PHP memory_limit, e.g. 128M (default: PHP default 128M)")
    ap.add_argument("-p", "--post-max-size", type=parse_size, default=None,
                    help="PHP post_max_size, e.g. 8M (default: PHP default 8M)")
    ap.add_argument("-u", "--upload-max-filesize", type=parse_size, default=None,
                    help="PHP upload_max_filesize, e.g. 2M (optional)")
    ap.add_argument("-b", "--body-size", type=parse_size, default=None,
                    help="body an attacker can/will send (default: the cap)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--calibration", action="store_true",
                    help="print the measured calibration points and exit")
    args = ap.parse_args(argv)

    if args.calibration:
        print("memory_limit  post_max_size  body   measured result")
        for row in CALIBRATION:
            print(f"{row[0]:<13} {row[1]:<14} {row[2]:<6} {row[3]}")
        return 0

    memory_limit = args.memory_limit if args.memory_limit is not None else 128 * MIB
    post_max_size = args.post_max_size if args.post_max_size is not None else 8 * MIB

    if memory_limit == 0:
        print("error: memory_limit must be > 0", file=sys.stderr)
        return 3

    result = estimate(memory_limit, post_max_size, args.body_size,
                      args.upload_max_filesize)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"memory_limit        {fmt(result['memory_limit'])}")
        print(f"post_max_size       {fmt(result['post_max_size'])}")
        if result["upload_max_filesize"] is not None:
            print(f"upload_max_filesize {fmt(result['upload_max_filesize'])}")
        print(f"body used           {fmt(result['body_used'])} "
              f"(cap {fmt(result['body_cap'])})")
        print(f"model               {result['model']}")
        print(f"footprint           {fmt(result['footprint'])} "
              f"({result['ratio']} x memory_limit)")
        print(f"verdict             {result['verdict']}")
        for note in result["notes"]:
            print(f"note                {note}")

    return {"REACHABLE": 0, "UNREACHABLE": 1, "BORDERLINE": 2}[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
