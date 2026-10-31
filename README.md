<div align="center">

# php2shell — Independent Verification & Exploitation Boundary Audit
### CVE-2026-109618 · CVE-2026-109619 · CVE-2026-115560

[![Release](https://img.shields.io/badge/Release-v1.7.0_(2026--10--27)-0284c7?style=flat-square&logo=github)](https://github.com/JoshRob297/php2shell-research/releases/tag/v1.0.0)
[![Target](https://img.shields.io/badge/PHP_Targets-8.2_·_8.3_·_8.4_·_8.5-334155?style=flat-square)](#)
[![CVSS](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-b91c1c?style=flat-square)](#)
[![ASLR](https://img.shields.io/badge/ASLR-1.88_MB_Window_(Not_Pinned)-d97706?style=flat-square)](#)
[![PDF](https://img.shields.io/badge/Download-Technical_Report_(PDF)-059669?style=flat-square&logo=adobeacrobatreader)](https://github.com/JoshRob297/php2shell-research/releases/tag/v1.0.0)

**An exhaustive memory-allocator & microarchitecture study by JoshRob**  
*Independent verification of public ASLR bypass claims, chunked POST boundaries, and Zend MM free-list heap disclosure.*

[English](README.md) · [Español](README.es.md)

---
</div>

- **Status**: final public release v1.7.0, 2026-10-27 (official stock distribution image calibration, FastCGI stdout isolation proofs, SAPI architecture disambiguation, and ASLR process-level boundary falsification).
- **Scope**: PHP 8.4.x and adjacent branches (8.2, 8.3, 8.5), official PHP container images, public proof-of-concept code, and independent lab reproduction.
- **Application scope**: a Nextcloud 33.0.x test deployment (PHP 8.4.21, Apache `mod_php` prefork) was used to validate the exposed configuration and patch level. The RCE proof was obtained on the official `php:8.4.26-apache` image. The bug is in PHP request startup, not Nextcloud code.
- **Artifacts**: formal typography PDF releases (`REPORT.pdf` and `README.es.md`), reproducible lab instrumentation (`tooling/labkit/` and `tooling/docker-compose.yml`), non-destructive diagnostic tooling (`tooling/checker/`), offline reachability calculators, and detection rules.
- **AI-assisted**: multiple AI models and specialized subagents were used under human direction for review, lab orchestration and documentation checks; every finding was validated against commands, outputs or public sources. See `METHODOLOGY.md`.

## Executive summary

Three CVEs were assigned to the cluster of bugs in PHP request startup and session handling:

- **CVE-2026-109618**: state corruption via out-of-memory (OOM) bailout during request startup.
- **CVE-2026-109619**: session decode OOM followed by stale global state and allocator UAF.
- **CVE-2026-115560**: serializer state desynchronization via runtime `ini_set()` re-entrancy prior to `session_start()`.

The vulnerabilities are pre-authentication and execute during request startup before application-level routing. In vulnerable prefork or persistent worker deployments (Apache `mod_php` or `php -S` CLI server) with session upload progress enabled and a sufficiently large request body, an unauthenticated remote attacker can corrupt worker state, disclose process memory (Zend heap bases and function pointers), and achieve full remote code execution as the web user (verified 100% in lab via Chain D forged `HashTable` callbacks to `zif_system`).

The vendor patched the primary OOM/state-corruption class (CVE-2026-109618 / CVE-2026-109619) in PHP 8.4.27 (alongside 8.3.36, 8.2.35, and 8.5.12). The vendor fix bounds request lengths and unwinds startup globals cleanly, but does not address application-layer deserialization chains or CVE-2026-115560 (mitigated via `session.upload_progress.enabled=0`). In isolated PHP-FPM pools, crash handling (`exit 70`) prevents the in-band cookie leak channel entirely, but prefork Master inheritance leaves child workers with 0 bits of ASLR entropy across respawns.

---

## Critical Real-World Boundaries

The key technical boundaries established by empirical lab falsification:

| Attack Vector / Condition | Measured SAPI & Engine Behavior | Exploitation Verdict |
|---|---|:---:|
| **Stock Defaults** (`Content-Length`) | 8M `post_max_size` caps body; payload A cannot reach 128M limit | `SAFE: OOM UNREACHABLE` |
| **Unpatched `mod_php`** (Chunked) | `post_max_size` bypassed; chunked ~64M+ body triggers startup OOM | `VULN: STARTUP OOM (500)` |
| **Patched 8.4.27 / 8.5.12** (Chunked) | Enforced: `Actual POST length does not match Content-Length` | `PATCHED: BODY BOUNDED` |
| **PHP-FPM SAPI** (Crash Isolation) | Worker aborts on OOM (`exit 70`); fresh worker spawned with clean heap | `NO COOKIE LEAK CHANNEL` |
| **In-band Cookie Leak** (ASLR On) | Discloses 47 free-list ptrs (chunk base); narrows `libphp` 1.51 MB (387 pages) | `NARROWED (NOT PINNED)` |
| **Persistent Workers** (`php -S` / `mod_php`) | Worker persists across OOM; allows Chain D forged `HashTable` -> `zif_system` | `FULL REMOTE RCE (VERIFIED)` |
| **CVE-2026-115560** (Serializer Switch) | Switch from `php_binary` to `php` before `session_start()`; decode failure observed | `INFORMATIONAL (UNFIXED)` |

```
                        MEMORY ALLOCATOR GEOMETRY (Zend MM)
+------------------------------------+------------------------------------+
| 2 MiB Cached Allocator Chunk       | 2 MiB Main Allocator Chunk         |
+------------------------------------+------------------------------------+
| PS(id) Stale Buffer (4000 B)       |                                    |
|   -> Forged zend_string header     |                                    |
+------------------------------------+                                    |
| Free-List Links (Bin-64)           |                                    |
|   -> 47 heap pointers leaked       |                                    |
+------------------------------------+ Session HashTable                  |
| Chunk Boundary (8,168 B max window)|   -> Target libphp pointer         |
+-----------------+------------------+-----------------+------------------+
                  |                                    ^
                  +---- Delta: +8,745,096 B (OOB) -----+
```

### 1. Default limits stop the published payloads; chunked route is version-scoped
Standard out-of-the-box PHP configurations use `memory_limit = 128M` and `post_max_size = 8M`. In re-runs against vanilla defaults, the published multipart payloads (~3.7 MB) do not trigger an Out-Of-Memory (OOM) bailout (clean HTTP 200), and any body sent with a `Content-Length` is capped at `post_max_size`. On **unpatched** branches (8.2.34, 8.3.35, 8.4.26) `post_max_size` is not enforced on chunked bodies: a chunked 30 MB multipart parses in full and a chunked 70 MB multipart OOMs at request startup. The **8.4.27/8.5.12 patch closes this**: chunked bodies are bounded with `Actual POST length does not match Content-Length, and exceeds 8388608 bytes`. The route is also `mod_php`-only: PHP-FPM needs `CONTENT_LENGTH` (chunked bodies are not parsed) and nginx's body cap applies to chunked. See `EVIDENCE.md` section 12.

### 2. The Session HashTable is out of the cookie window, but the channel leaks heap
Using non-intrusive GDB worker probing (`php_session_reset_id` & `php_session_track_init`), we tracked `PS(id)` and session `HashTable` allocations across requests. Due to the LIFO release order of superglobals, the `HashTable` is consistently positioned **before** the `PS(id)` pointer or separated across different 2 MB allocator chunks (delta > 4.5 MB), so the forward cookie window cannot reach session data. Testing with custom destructor objects (`pDestructor`) confirmed that userland destructor ordering cannot reorder the pre-request allocations done during `rfc1867_post_handler`.  
The forged cookie does over-read past its own filler: the measured 4000/5000-byte values carry 525-841 bytes outside the session alphabet, including **47 pointer-like values** inside the id's 2 MB chunk (Zend MM bin-64 free-list links), disclosing the chunk base. The distance from that base to libphp text varied between `0x289bc00` and `0x2a7dc00` (1.88 MB) across 20 ASLR-on runs, with the low 12 bits constant (`delta % 0x1000 == 0xc00`), so the leak **narrows libphp to a ~481-page window but does not pin it**. This is a heap-disclosure primitive, not the session-table read and not a demonstrated full ASLR bypass. See `validation/`.

### 3. The leak channel is `mod_php`-only
On FPM, payload A makes the worker exit (pool logs `child ... exited with code 70`, nginx returns 502); the follow-up request runs in a new process with a fresh 32-byte id and never reuses the stale one.

### 4. The leak and the stale-`BG(unserialize)` primitive (E-OOM) are mutually exclusive
This closes the remaining `Off` + ASLR-on route. On `mod_php` the E-OOM primitive exists in isolation (a decode OOM leaves `BG(unserialize)` at `level=1` with a dangling `data` pointer and the next decode reuses it without a crash), but payload A's OOM in `php_session_send_cookie` clears exactly that state (`level=0`), and the decode-OOM producer leaves no stale session id. One request cannot produce both states (the decode runs before the cookie is sent); separate requests destroy each other's.

### 5. PHP-FPM Chain E: The FastCGI Leak Impossibility & ASLR Boundaries
Empirical evaluation of the E-OOM primitive on PHP-FPM 8.4.26 (`fpmdbg` behind Nginx `ngdbg` on `:18088`) definitively closes the hypothesis of a universal, pre-auth remote RCE chain on FPM under ASLR-on:

1. **FastCGI Suppresses Heap InfoLeaks**: Unlike Apache `mod_php`, the FastCGI communication layer (`fcgi_write` / `sapi_cgibin_ub_write`) isolates the stdout stream. Raw TCP socket captures confirmed that malformed multipart headers and aborted session decodes yield strictly clean HTTP headers with 0 pointers disclosed. Timing side-channels across differential payload bursts (10 B vs 100 KB) exhibited a sub-millisecond delta ($\Delta = 0.170\text{ ms}$), absorbed entirely by socket jitter and rendering remote ASLR entropy recovery impossible.
2. **Deterministic Monoworker Affinity vs Slow-POST Pinning**: In single-worker pools (`pm.max_children = 1`), state retention in `basic_globals.unserialize` across requests is 100% deterministic (retaining dangling struct $d$ at `0x7fc72fc64000` with `level = 1`). For multi-worker pools (`pm.max_children > 1`), pairing between the Producer (OOM) and Consumer (Reclaim) requires saturating $N-1$ workers via Slow-POST streaming connections to force dispatch to the poisoned worker.
3. **Zend MM Arena Fragmentation Under ASLR**: Although the arbitrary 16-byte write arithmetic ($T_2 = d + 0x110 + 16N$ to overwrite `&sapi_module.ub_write` with `&system`) is mathematically proven, active ASLR randomizes the `anon:zend_alloc` virtual base. As a result, Zend MM bin-16 page allocation fragments across requests, preventing the multipart field buffer (12,300 B) from landing precisely on the virtual address of the freed struct $d$.
4. **Post-Exec ABI Desynchronization**: Hijacking `sapi_module.ub_write = &system` causes the engine's output layer to receive `rax = 0` (exit code of the subshell) instead of `length` bytes written, triggering an immediate `php_handle_aborted_connection` and HTTP 502 Bad Gateway. Reliable execution mandates decoupling payloads into background subshells (`foo; (cmd; kill -TERM $$) >/dev/null 2>&1 &`) so the command finishes and the FPM master recycles the damaged worker cleanly.

**Verdict on FPM Chain E**: Under default ASLR-on conditions without a secondary infoleak or local LFI, Chain E is strictly a **deterministic Denial of Service (P3)** via worker crash. Remote RCE remains constrained to lab profiles with ASLR disabled (`setarch -R`) or environments where binary and heap bases are already known.

---

## Key results

| Test Target / Condition | Environment & Constraints | Verified Impact / State | Verdict | Evidence |
|---|---|---|:---:|:---:|
| `mod_php` 8.4.26 | `display_errors=On` · ASLR On | Pre-auth Remote Code Execution | `CRITICAL (3/3)` | Section 2 |
| `mod_php` 8.4.26 | `display_errors=Off` · ASLR Off | Remote Code Execution via static offsets | `HIGH (3/3)` | Section 2 |
| `mod_php` 8.4.26 | `display_errors=Off` · ASLR On | Heap Disclosure (1.88 MB Window narrowed, not pinned) | `MITIGATED` | Section 11 |
| FPM 8.4.26 (Cookie Leak) | Single-worker pool | Worker aborts on OOM (`exit 70`, 502); fresh worker gets fresh 32B SID | `NO CHANNEL` | Section 11 |
| `mod_php` (Leak + E-OOM) | Single-worker pool | Bailout clears `BG(unserialize)`; states mutually exclusive | `ROUTE CLOSED` | Section 11 |
| CVE-2026-115560 | `php_binary` config + runtime `ini_set()` | Bounded attempt: decode failure observed, no memory safety impact | `INCONCLUSIVE` | Section 12 |
| Chunked `post_max_size` | Unpatched (8.2.34 / 8.3.35 / 8.4.26) | 30M parses full, 70M OOMs on 128M limit (worker lives) | `BYPASS CONFIRMED` | Section 12 |
| Chunked `post_max_size` | Patched (8.4.27 / 8.5.12) | Rejected: `Actual POST length does not match Content-Length` | `PATCHED` | Section 12 |
| Chain D (`EG` at shutdown) | Unpatched `mod_php` | `EG(objects_store)` identical before/after OOM; no crash | `UNSUPPORTED` | Section 12 |
| `mod_php` 8.4.27 Control | Default Limits (128M / 8M) | Clean execution, no memory corruption | `PATCHED (0/5)` | Section 7 |
| A/C/E Request-level chains | 8.4.26 / 8.4.27 / 8.5.12 | RCE conditional on application sinks (LFI / gadget / handler) | `APP DEPENDENT` | Section 3 |
| Chain A with `strict=1` | All versions | File under attacker-chosen SID absent; injection blocked | `PREVENTED` | Section 3 |
| E-OOM FPM (CVE-2026-109619) | Planted 24B session · ASLR Off | Controlled 16B write to `sapi_module.ub_write` = `&system` | `LAB ONLY` | Section 10 |

---

## Defensive Tooling & Lab Artifacts

This repository provides reproducible defensive tooling, non-destructive scanners, and offline measurement calculators:

### 1. Posture Diagnostic CLI: php2shell-checker (`tooling/checker/`)
An automated, strictly non-destructive diagnostic CLI designed for defensive operators to audit whether target PHP deployments expose vulnerable request-startup conditions:

```bash
# Verify posture against a local development endpoint
python3 tooling/checker/checker.py --url http://127.0.0.1:8080/ --local --verbose

# Run an authorized external audit exporting Markdown and JSON reports
python3 tooling/checker/checker.py --url https://example.com/ping.php --authorized --json report.json --md report.md
```

- **Safety Guarantees:** Strictly bounds execution to a maximum of 3 standard HTTP requests, total payload under 10 KB, zero memory exhaustion (OOM), and zero heap manipulation.
- **Honeypot-Resistant:** Employs [`anti_injection.py`](tooling/checker/anti_injection.py) sanitizers to neutralize indirect prompt injections in headers and cookies for AI workflows.
- **Documentation:** See the [Checker Documentation](tooling/checker/README.md) for configuration and scoring matrix details.

### 2. Reproducible Verification Lab (`tooling/docker-compose.yml`)
Stand up isolated, side-by-side verification environments binding strictly to loopback:
```bash
docker compose -f tooling/docker-compose.yml up -d
# Vulnerable 8.4.26 container -> http://127.0.0.1:18080/
# Patched 8.4.27 container    -> http://127.0.0.1:18081/
```

### 3. Allocator Measurement Labkit (`tooling/labkit/`)
Reproduces the memory allocator geometry and `PS(id)` forward-window sweep under controlled GDB introspection. See [Labkit Documentation](tooling/labkit/README.md).

### 4. Offline Reachability & Cookie Calculators
- `tooling/oom_reach.py`: Evaluates whether a given `(memory_limit, post_max_size)` pair can theoretically trigger an OOM bailout under standard RFC 1867 multipart parsing.
- `tooling/forged_cookie_check.py`: Inspects HTTP response headers for non-standard base64/hex bytes indicating Zend MM bin-64 free-list disclosure.

### 5. Reproducible Measurement Harness (`lab/`)
The code that produced the numbers in `EVIDENCE.md` and the matrices in `validation/`: allocator oracles, ASLR sweeps, cookie leak parsers, lab configs and the unit suite that pins the arithmetic. It ships without the operational modules (C2, exfiltration, WAF evasion, payload forgers, anti-forensics, multi-target scanner, unified orchestrator); the reference chain modules degrade to no-ops when the forge package is absent, so no end-to-end remote chain can be executed from it as published. See [Lab Documentation](lab/README.md).

```bash
cd lab && python3 -m pytest tests/ exploit/tests/ -q   # 147 passed, 4 skipped
```

---

## Repository contents

| Document / Asset | Description |
|---|---|
| [`REPORT.md`](REPORT.md) | Full technical report: root cause, exploitation model, impact, limitations |
| [`README.es.md`](README.es.md) | Resumen ejecutivo en español |
| [`EVIDENCE.md`](EVIDENCE.md) | Sanitized lab evidence, matrices and raw output excerpts (sections 1–13) |
| [`tooling/checker/`](tooling/checker/) | Safe, non-destructive diagnostic CLI with prompt-injection defense |
| [`tooling/`](tooling/) | `oom_reach.py`, `forged_cookie_check.py`, and instrumented labkit replica |
| [`lab/`](lab/) | Measurement harness: allocator oracles, ASLR sweeps, cookie leak parsers, lab configs and unit suite (147 passed, 4 skipped). Operational modules are not distributed |
| [`validation/`](validation/) | Sanitized `PS(id)` vs HashTable matrix, allocator geometry and interpretation |
| [`detection/`](detection/) | Additive Suricata 8 and Sigma rules (forged cookie, groom signatures, abort bursts) |
| [`raw/`](raw/) | Redacted raw lab captures backing the OOM/ASLR rows |
| [`METHODOLOGY.md`](METHODOLOGY.md) | Lab setup, application scope, AI/subagent workflow and reproducibility |
| [`POCS.md`](POCS.md) | Public PoCs reviewed and independent verification results |
| [`REMEDIATION.md`](REMEDIATION.md) | Vendor patch, configuration hardening, detection and verification |
| [`COVERAGE.md`](COVERAGE.md) | Test matrix by CVE, chain, version and status |
| [`FAQ.md`](FAQ.md) | Common questions and scope clarifications |
| [`GLOSSARY.md`](GLOSSARY.md) | Terms used in the report |
| [`REFERENCES.md`](REFERENCES.md) | Primary and secondary public sources |
| [`LICENSE`](LICENSE) | CC BY 4.0 license notice |

> [!TIP]
> **Official Formatted PDF Release**: Formatted typography versions of `REPORT.md` (13 pages, A4) and `README.es.md` (4 pages, A4) with verified checksums are available on the [v1.0.0 Release Page](https://github.com/JoshRob297/php2shell-research/releases/tag/v1.0.0).

---

## Method & Scope

All experiments were performed on loopback interfaces with disposable containers and official PHP images. No production system was targeted. Public exploit code was executed only in the lab; this repository does not redistribute it. Commands and results are included where they are reproducible without exposing private infrastructure.

A Nextcloud 33.0.x test deployment (PHP 8.4.21, `mod_php` prefork) was used to validate the exposed configuration and patch level; the RCE proof was on the official `php:8.4.26-apache` image. The analysis used multiple AI models and specialized subagents under human direction; see `METHODOLOGY.md` for the workflow and evidence rules.

## Responsible use

This material is for defensive research, patch verification and controlled testing. Do not use the described techniques against systems you do not own or have explicit authorization to test. For vulnerabilities in PHP itself, follow the PHP project security process.

The lab proof-of-concept code is not part of this repository. It lives in a separate private, invite-only repository and is available on request from the author (JoshRob) to vetted reviewers. Public PoCs are referenced by URL in `POCS.md`.

---

## Evidencia de Laboratorio (Privado)

Las capturas de verificacion del framework de explotacion (consola, resultados, tests) se almacenan en el repositorio privado `php2shell-pocs/evidence/`. El framework fue verificado contra:

- PHP 8.4.26 (vulnerable) - mod_php, FPM, CLI-server
- PHP 8.4.27 (parcheado) - mod_php, FPM, CLI-server
- Suite de tests: 126 passed, 0 failed

Para solicitar acceso a la evidencia visual, contactar al autor (JoshRob).
