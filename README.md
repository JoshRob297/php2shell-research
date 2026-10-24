# php2shell: CVE-2026-109618 / CVE-2026-109619

Independent verification and exploitation analysis of the PHP request-startup vulnerabilities
known as **php2shell**. Prepared by **JoshRob**.

- Status: final public report, 2026-10-23 (updated with Phase 2 allocator & default limits analysis).
- Scope: PHP 8.4.x and adjacent branches, official PHP container images, public proof-of-concept
  code, and independent lab reproduction.
- Application scope: a Nextcloud 33.0.x test deployment (PHP 8.4.21, Apache `mod_php` prefork)
  was used to validate the exposed configuration and patch level. The RCE proof was obtained on
  the official `php:8.4.26-apache` image. The bug is in PHP request startup, not Nextcloud code.
- No infrastructure data: no production hostnames, addresses, credentials, customer data or
  private infrastructure details.
- AI-assisted: multiple AI models and specialized subagents were used under human direction for
  review, lab orchestration and documentation checks; every finding was validated against
  commands, outputs or public sources. See `METHODOLOGY.md`.

## Executive summary

Two CVEs were assigned to a cluster of bugs in PHP request startup:

- **CVE-2026-109618**: state corruption via bailout during request startup.
- **CVE-2026-109619**: session decode OOM followed by stale global state.

A third issue in the same feature, **CVE-2026-115560**, was disclosed on 2026-10-23 in an
informational advisory. It is unfixed by the emergency releases and requires an unusual
condition: the application configures `session.serialize_handler` as `php_binary` or
`php_serialize` and then switches it back to `php` at runtime with `ini_set()` before
`session_start()`. Mitigation: `session.upload_progress.enabled=0`. This report does not test
it; the test deployment does not meet the condition.

The vulnerabilities are pre-authentication and run before application code. In a vulnerable
`mod_php` prefork deployment with session upload progress enabled and a sufficiently large
request body, a remote attacker can corrupt worker state, disclose process memory, and in the
tested conditions achieve remote code execution as the web user. Denial of service through
worker aborts is also possible.

The vendor fixed the OOM/state-corruption class in PHP 8.4.27 (and the corresponding 8.3.36,
8.2.35 and 8.5.12 releases). The fix is necessary but not sufficient for every public exploit
chain: the request-level A/C/E chains described by public PoCs still worked against 8.4.27 and
8.5.12 in our lab when their prerequisites were present. `session.use_strict_mode=1` blocked
the fixed-session variant of chain A in our tests; the other chains require application-level
or local conditions.

### Critical Real-World Boundaries (October 24 Update)

1. **Default limits stop the published payloads, and the chunked route is version-scoped.**
   Standard out-of-the-box PHP configurations use `memory_limit = 128M` and `post_max_size = 8M`.
   In re-runs against vanilla defaults, the published multipart payloads (~3.7 MB) do not
   trigger an Out-Of-Memory (OOM) bailout (clean HTTP 200), and any body sent with a
   `Content-Length` is capped at `post_max_size`. On **unpatched** branches (8.2.34, 8.3.35,
   8.4.26) `post_max_size` is not enforced on chunked bodies: a chunked 30 MB multipart parses
   in full and a chunked 70 MB multipart OOMs at request startup. The **8.4.27/8.5.12 patch
   closes this**: chunked bodies are bounded with `Actual POST length does not match
   Content-Length, and exceeds 8388608 bytes`. The route is also `mod_php`-only: PHP-FPM needs
   `CONTENT_LENGTH` (chunked bodies are not parsed) and nginx's body cap applies to chunked.
   So the published payloads are ineffective against defaults, the chunked OOM works only on
   unpatched `mod_php`, and no front-end body cap is the remaining exposure condition. See
   `EVIDENCE.md` section 12.

2. **The Session HashTable Is Out of the Cookie Window, but the Channel Leaks Heap:**
   Using non-intrusive GDB worker probing (`php_session_reset_id` & `php_session_track_init`), we tracked `PS(id)` and session `HashTable` allocations across requests. Due to the LIFO release order of superglobals, the `HashTable` is consistently positioned **before** the `PS(id)` pointer or separated across different 2 MB allocator chunks (delta > 4.5 MB), so the forward cookie window cannot reach session data. Testing with custom destructor objects (`pDestructor`) confirmed that userland destructor ordering cannot reorder the pre-request allocations done during `rfc1867_post_handler`.
   The forged cookie does over-read past its own filler, however: the measured 4000/5000-byte values carry 525-841 bytes outside the session alphabet (range across runs), including **47 pointer-like values** inside the id's 2 MB chunk, which discloses the chunk base. The distance from that base to libphp text varied between `0x289bc00` and `0x2a7dc00` (1.88 MB) across 20 ASLR-on runs, with the low 12 bits constant (`delta % 0x1000 == 0xc00`), so the leak **narrows libphp to a ~481-page window but does not pin it**. This is a heap-disclosure primitive, not the session-table read and not a demonstrated full ASLR bypass. See `validation/`.

3. **The leak channel is `mod_php`-only.** On FPM, payload A makes the worker exit (pool logs `child ... exited with code 70`, nginx returns 502); the follow-up request runs in a new process with a fresh 32-byte id and never reuses the stale one.

4. **The leak and the stale-`BG(unserialize)` primitive (E-OOM) are mutually exclusive**, which closes the remaining `Off` + ASLR-on route. On `mod_php` the E-OOM primitive exists in isolation (a decode OOM leaves `BG(unserialize)` at `level=1` with a dangling `data` pointer and the next decode reuses it without a crash), but payload A's OOM in `php_session_send_cookie` clears exactly that state (`level=0`), and the decode-OOM producer leaves no stale session id. One request cannot produce both states (the decode runs before the cookie is sent); separate requests destroy each other's.

## Key results

| Test | Result |
|---|---|
| PHP 8.4.26, `display_errors=On`, ASLR on | RCE 3/3 as `uid=33` |
| PHP 8.4.26, `display_errors=Off`, ASLR off | RCE 3/3 as `uid=33` |
| PHP 8.4.26, `display_errors=Off`, ASLR on | 4000-byte cookie state-dependent; no session-table read; heap pointers disclosed (see `EVIDENCE.md` section 11) |
| Cookie leak on FPM | No channel: payload A exits the worker (`child ... exited with code 70`, 502) |
| Leak + E-OOM combination on `mod_php` | Mutually exclusive: A clears the `BG(unserialize)` state E needs; route closed |
| CVE-2026-115560 (informational, 2026-10-23) | Bounded reproduction attempt: condition reproduced (decode failure) but no memory-safety symptom; not fixed by 8.4.27; condition not met in our deployment |
| `post_max_size` vs chunked bodies | Not enforced on unpatched 8.2.34/8.3.35/8.4.26 (chunked 30M parses in full; chunked 70M OOMs at defaults); 8.4.27/8.5.12 enforce it; FPM does not parse chunked bodies (no `CONTENT_LENGTH`) |
| Chain D (stale `EG` after startup OOM) | OOM reproduced; `EG(objects_store)` identical before and after the OOM at `php_request_shutdown`; no stale-EG crash observed; RCE step not reproduced |
| PHP 8.4.27 control | 0/5, no aborts or over-read |
| A/C/E request-level chains, 8.4.26 / 8.4.27 / 8.5.12 | RCE with the lab configuration; see `EVIDENCE.md` |
| A with `use_only_cookies=1`, `strict=0`, SID only in multipart | RCE on 8.4.26 / 8.4.27 / 8.5.12 |
| A with `strict=1` | Blocked in the tested configuration |
| Apache `mod_php` per-directory serializer test | No stale `PS(serializer)` across requests |
| E-OOM (FPM stale `BG(unserialize)`), 8.4.26 | Deterministic UAF crash (502) with the default mechanism (allocator free-list encoding); with the multipart-reclaimed struct (planted 24-byte session, ASLR off) the fake `var_dtor_entries` gives a controlled 16-byte write to `sapi_module.ub_write` = `&system` -> command execution in the lab; 8.4.27 stable; see `EVIDENCE.md` section 10 |

## Repository contents

| File | Contents |
|---|---|
| `RESUMEN.md` | Resumen ejecutivo en español |
| `REPORT.md` | Full technical report: root cause, exploitation model, impact, limitations |
| `METHODOLOGY.md` | Lab, application scope, AI/subagent workflow and reproducibility |
| `POCS.md` | Public PoCs reviewed and independent verification results |
| `EVIDENCE.md` | Sanitized lab evidence, matrices and raw output excerpts |
| `REMEDIATION.md` | Vendor patch, configuration hardening, detection and verification |
| `COVERAGE.md` | Test matrix by CVE, chain, version and status |
| `FAQ.md` | Common questions and scope clarifications |
| `GLOSSARY.md` | Terms used in the report |
| `REFERENCES.md` | Primary and secondary public sources |
| `tooling/oom_reach.py` | Offline estimator: can a multipart body exhaust `memory_limit`? |
| `tooling/forged_cookie_check.py` | Offline check for forged `PHPSESSID` artifacts in `Set-Cookie` values |
| `detection/` | Additive Suricata and Sigma rules (forged cookie, groom signatures, abort bursts) |
| `validation/` | Sanitized `PS(id)` vs HashTable matrix and its interpretation |
| `tooling/labkit/` | Instrumented replica: gdb probe, payloads and sweep driver for the allocator study |
| `raw/` | Redacted raw lab captures backing the OOM/ASLR rows |
| `LICENSE` | License notice for this text |

PDF versions of `REPORT.md` and `RESUMEN.md` (plus `SHA256SUMS`) are attached to the
[v1.0.0 release](https://github.com/JoshRob297/php2shell-research/releases/tag/v1.0.0).

The `tooling/` and `detection/` directories complement the ecosystem's scanners
and rule sets rather than replacing them: they encode the configuration,
geometry and artifact findings of this report (default limits, allocation order,
forged-cookie content) and are offline unless stated otherwise. `tooling/labkit/`
is the exception: it sends traffic, by design, to a disposable debug build you
control.

## Method

All experiments were performed on loopback interfaces with disposable containers and official
PHP images. No production system was targeted. Public exploit code was executed only in the
lab; this repository does not redistribute it. Commands and results are included where they
are reproducible without exposing private infrastructure.

A Nextcloud 33.0.x test deployment (PHP 8.4.21, `mod_php` prefork) was used to validate the
exposed configuration and patch level; the RCE proof was on the official `php:8.4.26-apache`
image. The analysis used multiple AI models and specialized subagents under human direction;
see `METHODOLOGY.md` for the workflow and evidence rules.

## Responsible use

This material is for defensive research, patch verification and controlled testing. Do not use
the described techniques against systems you do not own or have explicit authorization to test.
For vulnerabilities in PHP itself, follow the PHP project security process.

The lab proof-of-concept code is not part of this repository. It lives in a separate private,
invite-only repository and is available on request from the author (JoshRob) to vetted
reviewers. Public PoCs are referenced by URL in `POCS.md`.

## License

The text in this repository is licensed under CC BY 4.0 unless otherwise noted. Third-party
proof-of-concept code and quoted material remain under their own licenses; see `LICENSE`.
