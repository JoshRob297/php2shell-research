# Public PoCs: review and independent verification

This document reviews the public proof-of-concept material available during the disclosure
window. It does not redistribute third-party exploit code; links point to the original
repositories. All execution was in a disposable lab, on loopback, against official PHP images.

Scope note: the RCE proof is on the official `php:8.4.26-apache` image. A Nextcloud 33.0.x test
deployment (PHP 8.4.21, `mod_php` prefork) was used to validate the exposed configuration and
patch level; the RCE was not executed against that deployment. The bug is in PHP request
startup, not in Nextcloud code.

The lab proof-of-concept code itself is kept in a separate private, invite-only repository,
available on request from the author. This document reviews and links the public PoCs; it does
not redistribute them.

## Summary

| Repository | What it is | Independent result |
|---|---|---|
| `9bie/php2shell-bypass-aslr-exp` | Python ASLR-bypass exploit, standard library only | Functional in the lab: 8/8 with ASLR on, 5/5 with ASLR off; host-layout dependent |
| `ikow/php2shell-poc` | Five chains; A/B/C public, D/E with public verification scripts and paid full exploits | A/B/C readable and testable; D/E verification public; full D/E not public |
| `GoldraK/php2shell-poc` | Fork/rewrite by the same author; A/C/E scanner, lab and rules | Scanner reports 24/24 vulnerable; measures A/C/E, not the OOM chain |
| `dinosn/php-cve-2026-10961x-lab-poc` | Lab with instrumented allocator | Lab-assisted; uses `USE_ZEND_ALLOC=0`; not a universal remote PoC |
| `pentestershell/php2shellbt` | Small scanner | Confirmed false positive on 8.4.27; CVEs mislabeled |
| `eness/php2shell-...-PoC` | Placeholder | No code published |

## 9bie: ASLR-bypass exploit

- Python 3, standard library, no external hosts.
- The exploit targets the OOM/state-corruption chain and includes an ASLR bypass.
- In our lab it produced `uid=33(www-data)` on 8/8 runs with ASLR on and 5/5 runs with ASLR
  off.
- The earlier 0/49 "Off" sweep was a harness bug: stage A was sent to the wrong port while
  stage B hit the container port. It was not a PoC failure.
- Caveat: the chain depends on host/kernel allocator layout. The same public exploit did not
  reproduce on every host tested; the exploit is not universal without calibration.

## ikow: five-chain research repository

- A: session upload-progress filename injection + LFI.
- B: local `/proc/self/mem` primitive; not remote.
- C: session handler mismatch across directories, plus an application gadget.
- D/E: OOM/state chains. The repository publishes verification scripts; the full exploits are
  not public in the reviewed state.
- The README's claims are useful but are claims; each chain needs its own prerequisites and
  proof. Our independent tests are in `EVIDENCE.md`.

## GoldraK: A/C/E fork and scanner

- Fork of the previous repository, rewritten by the same author (12 commits ahead, 6 behind at
  review time).
- Scanner covers A/C/E against a long version list; it reports 24/24 "vulnerable".
- The lab configuration is intentionally weak: `session.use_only_cookies=0`,
  `session.use_strict_mode=0`, `session.upload_progress.cleanup=Off`. That makes A easy but does
  not represent a hardened default.
- The scanner does not measure the OOM/state-corruption chain. 8.4.27 appears in
  `versions.json` but not in the 24-row result table.
- Our differential: A/C/E work on 8.4.26, 8.4.27 and 8.5.12 with the lab configuration. With
  `use_only_cookies=1`, `strict=0` and SID only in the multipart body, A still works; `strict=1`
  blocks it. C is per-directory handler mismatch plus gadget; E requires local file planting in
  the harness. None of these results contradicts the 8.4.27 fix for the OOM chain.
- A separate lab dropper based on the same upload-progress write can keep a shell-readable file
  alive during a slow upload even with `cleanup=On`; execution still requires a command
  primitive such as `sh</tmp/sess_<id>`. It is a post-exploitation write primitive, not a
  standalone remote RCE.

## dinosn: lab-assisted

- Reproduces the bug with an instrumented allocator and `USE_ZEND_ALLOC=0`.
- The repository itself scopes the result as lab-assisted; it is not a turnkey remote exploit.

## pentestershell/php2shellbt: false positive

- Labels CVE-2026-109618 as "session fixation" and CVE-2026-109619 as "var_destroy UAF";
  neither mapping matches the advisories.
- Its check 2 marks 8.4.27 vulnerable because it only looks for session warnings with
  `display_errors=On`.
- Its check 1 ignores PHP 7.x, 8.0 and 8.1.
- It disables TLS verification (`ssl.CERT_NONE`).
- Verdict: not a reliable detector; do not use it as patch evidence.

## eness: placeholder

No code was published at review time.

## What makes a PoC credible

A useful PoC should state:

1. the exact PHP version and SAPI (mod_php/FPM, prefork/worker);
2. the relevant `php.ini` values (`memory_limit`, `post_max_size`,
   `session.upload_progress.*`, `display_errors`, `session.use_strict_mode`);
3. whether ASLR is on or off, and how the leak works;
4. the network/proxy conditions (buffering, KeepAlive, worker count);
5. the proof (command output, `uid`, file write) and the failure modes;
6. that it is authorized lab use, with no hardcoded external targets or disabled TLS
   verification.

A scanner that only observes warnings is not proof of RCE. A CVE identifier is not proof of
exploitability on a given build.

## Independent results

See `EVIDENCE.md` for the full matrices. The short version:

- 8.4.26 `mod_php`, `display_errors=On`, ASLR on: RCE 3/3.
- 8.4.26 `mod_php`, `display_errors=Off`, ASLR off: RCE 3/3.
- 8.4.26 `mod_php`, `display_errors=Off`, ASLR on: controlled repetitions 0/3; the 4000-byte cookie is state-dependent and over-reads into heap objects (47 pointer-like values per run); no session-table read, and the chunk-to-libphp distance varies 1.88 MB (fixed page offset, ~481 pages).
- Chain D (mod_php stale EG + forged `zend_object` spray -> `zif_system`): described in
  `ikow/php2shell-poc` `docs/ANALYSIS.md` (sections 3.5/3.6); the exploit scripts were not
  public at review time and we did not test it. Its OOM precondition — a chunked-encoding
  bypass of `post_max_size` — **we independently confirmed** on 8.4.26 `mod_php` with stock
  defaults (chunked 30M parses in full; chunked 70M OOMs at request startup; see
  `EVIDENCE.md` section 12). The full chain D itself remains untested here.
- Community backports for EOL PHP 5.4-8.1 exist (e.g. `Anton-Barinov/php2shell-patches`); they
  are third-party code we did not review for correctness.
- 8.4.27: 0/5, no aborts or over-read.
- A/C/E: RCE with lab prerequisites on 8.4.26, 8.4.27 and 8.5.12.
- A with `strict=1`: blocked in the tested configuration.
- `PS(serializer)`: no stale handler across requests in FPM or `mod_php`.
- E-OOM (FPM stale `BG(unserialize)`): deterministic UAF crash (502) on 8.4.26 with a symbol
  build; with the multipart-reclaimed struct (planted 24-byte session, ASLR off) the fake
  `var_dtor_entries` gives a controlled 16-byte write to `sapi_module.ub_write` = `&system` and
  command execution in the lab; 8.4.27 stable; the remote ASLR-on variant was not demonstrated.
