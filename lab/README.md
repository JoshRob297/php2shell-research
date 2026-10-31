# Lab: reproducible measurement harness

[English](README.md) · [Español](README.es.md)

---

Measurement and verification code for the php2shell research. This directory contains the
harness that produced the numbers in [`../EVIDENCE.md`](../EVIDENCE.md) and the matrices in
[`../validation/`](../validation/): heap geometry probes, allocator oracles, ASLR sweeps, cookie
leak parsers, the lab `php.ini`/Apache/FPM configs, and the unit suite that pins the arithmetic.

It is **not** an exploit framework. The operational modules (C2, exfiltration, WAF evasion,
payload forgers, anti-forensics, multi-target scanner, and the unified orchestrator) are not
distributed here. Copies of the chain modules are included for reference and unit testing; they
degrade to no-ops when the forge modules are absent, so no end-to-end remote chain can be
executed from this directory as published.

Use only against disposable containers on loopback. No request generator in this directory is
safe against a production host: the multipart bodies intentionally exceed `memory_limit` and
abort workers.

## Layout

| Path | What it is |
|---|---|
| `configs/` | Apache prefork single-worker, `php.ini` (On/Off profiles), FPM + nginx configs and the lab webroot |
| `scripts/` | Probe and measurement scripts: heap warmup, worker hold, stage-1 leak dumps, bin-128 oracle, page-residue sweep, fixed-branch differentials, GDB watchpoints |
| `exploit/aslr/` | ASLR window arithmetic, page sweep and FPM offset calibrator |
| `exploit/grooming/` | Heap oracle, allocator oracle, warmup and worker saturation (measurement) |
| `exploit/infoleak/` | Bounded autonomous leak primitive used to bound the window, not to weaponize it |
| `exploit/leak/` | Cookie leak parser, heap base extraction and pointer classification |
| `exploit/recon.py` | SAPI, version and ASLR detection; patch-level comparison |
| `exploit/safety/` | Rate limiter and lab-mode guards (private-IP / authorization gates) |
| `exploit/reporting/` | Evidence capture and structured run logs |
| `exploit/chains/` | Reference chain modules; require the non-distributed `forge/` package to execute |
| `exploit/encoding.py`, `payload_encoding.py`, `payload_wrappers.py`, `retry.py` | Encoding and retry helpers used by the probes |
| `tests/`, `exploit/tests/` | Unit suite; `147 passed, 4 skipped` as published |

## Running the unit suite

```bash
cd lab
python3 -m pytest tests/ exploit/tests/ -q
# 147 passed, 4 skipped
```

The 4 skips are the FPM/CLI chain tests: they assert the forged `ub_write`/`HashTable` payload
sizes, and the forge modules are intentionally not part of this repository. The skip is explicit
(`forge/ not distributed in the public lab`), not a silent pass.

## Reproducing a measurement

The lab profiles are the same ones referenced in `EVIDENCE.md`:

```bash
# vulnerable / control pair on loopback
docker run -d --name php2shell-lab -p 18080:80 \
  -v "$PWD/configs/php.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$PWD/configs/apache.conf:/etc/apache2/conf-enabled/zz-lab.conf:ro" \
  php:8.4.26-apache

# heap geometry sweep (writes CSV rows consumed by validation/)
python3 scripts/off_leak_e1.py --url http://127.0.0.1:18080/index.php --out out/e1.csv
```

GDB probes require `CAP_SYS_PTRACE` and `--security-opt seccomp=unconfined`; see
[`../tooling/labkit/README.md`](../tooling/labkit/README.md) for the debug-build workflow.

## Scope and limits

- The measurements hold for the exact image digests listed in `EVIDENCE.md`. A different build,
  allocator or kernel changes the geometry.
- Under ASLR, the in-band cookie channel bounds `libphp` to a ~1.88 MB window but does not pin
  it; the FPM path exposes no in-band leak at all. Those are measured limits, not tuning gaps.
- The FPM E-OOM watchpoint is included because it is the evidence for the DoS/P3 verdict. The
  payload builder and the automated run loop are not, deliberately.

See [`../SECURITY.md`](../SECURITY.md) for the responsible-use terms.
