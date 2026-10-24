# Coverage matrix

Status definitions:

- **fail**: the vulnerability or chain succeeded in the tested conditions.
- **pass**: the control blocked the tested case, or the patched build did not reproduce the
  bug.
- **n/a**: the prerequisite is absent (for example, a local-only chain in a remote test).
- **not tested**: no independent measurement.

## 1. OOM / state-corruption CVEs

| Test | 8.4.21 | 8.4.26 | 8.4.27 | 8.5.12 | Notes |
|---|---|---|---|---|---|
| OOM abort / heap corruption | affected by version; not exploited | fail | pass | pass (0/3) | 8.4.27 control: 0/5, no aborts; fixed branches blocked at stage 1 |
| RCE, `display_errors=On`, ASLR on | not tested | fail (3/3) | pass (0/5) | pass (0/3) | mod_php prefork; control rerun 3/3 in the same harness |
| RCE, `display_errors=Off`, ASLR off | not tested | fail (3/3) | pass | not tested here | offset-calibrated build; fixed branches not exercised in this profile |
| RCE, `display_errors=Off`, ASLR on | not tested | not stable (controlled 0/3) | pass | not tested | 12/12 claim withdrawn; cookie state-dependent |
| FPM session decode OOM / stale BG | not tested | deterministic UAF crash (502) verified with watchpoint; with the multipart-reclaimed struct, controlled 16-byte write to `sapi_module.ub_write` = `&system` -> command execution in the lab | not tested | not tested | CVE-2026-109619; default mechanism = allocator free-list encoding over `used_slots`; controlled variant = fake `var_dtor_entries` (ASLR off, planted 24-byte session); 8.4.27 stable (early reset) |
| Memory disclosure via cookie | not tested | partial (4000-byte cookie discloses heap pointers; session table not reachable; libphp narrowed ~1.88 MB, not pinned) | pass | pass (0/3) | geometry-dependent; fixed branches: leak not reproducible |
| CVE-2026-115560 (informational, 2026-10-23) | not tested | not tested | not fixed | not tested | narrow condition (config `php_binary`/`php_serialize` + runtime `ini_set()` switch to `php`); mitigation `session.upload_progress.enabled=0` |

Fixed branches 8.3.36 and 8.2.35 (same harness, 3 runs each): 0/3, blocked at stage 1 (heap
leak). Raw: `raw/fixed-branches-verify.txt`.

## 2. Request-level chains

| Chain | 8.4.26 | 8.4.27 | 8.5.12 | Remote? | Notes |
|---|---|---|---|---|---|
| A: upload-progress filename + LFI | fail | fail | fail | requires LFI | `strict=0`, `cleanup=Off`, `use_only_cookies=1` tested |
| A with `strict=1` | pass | pass | pass | requires LFI | file under chosen SID absent |
| A with `cleanup=On` + race | not tested | inconclusive (2 attempts) | not tested | requires LFI | not a formal guarantee |
| B: local `/proc/self/mem` | n/a | n/a | n/a | no | local primitive |
| C: per-directory handler mismatch + gadget | fail | fail | fail | application-level | one prefork child in the mod_php test |
| D and E-OOM: OOM/state chains | public verification; E-OOM reached command execution in the lab with local prerequisites | public verification | not tested | D remote, E-OOM local in the harness | full D/E not public; the FPM controlled-write variant is in `EVIDENCE.md` section 10 |
| `PS(serializer)` across requests | pass (no stale; per-dir mismatch + OOM abort: next request uses its own INI) | pass (no stale; same test) | not tested | n/a | FPM and mod_php |

## 3. Patch and guard status

| Item | Status | Evidence |
|---|---|---|
| 8.4.27 includes the OOM/state-corruption fix | pass | `NEWS`, source diff, 0/5 control |
| 8.4.27 resets `PS(serializer)` | fail (not present; no exploitable stale measured: ini handler keeps pointer and INI paired) | source diff + per-directory abort test |
| 8.4.27 includes PR #22113 fixed-SID guard | fail (not present) | PR open; source diff |
| `session.use_strict_mode=1` blocks A fixed SID | pass | lab, 8.4.26/8.4.27/8.5.12 |
| `session.use_only_cookies=1` alone blocks A | fail | A succeeded with SID only in multipart |
| `session.upload_progress.enabled=0` blocks A | not tested (expected block) | A requires the handler |
| `cleanup=On` blocks A deterministically | not proven | 2 race attempts failed; not conclusive |
| `PS(serializer)` leak across requests | pass (not observed) | h1/h2, FPM and mod_php |
| 8.5 `fatal_error_backtraces` arm | pass (not reproduced) | symbol build; zval UNDEF -> valid IS_ARRAY_EX; 0 anomalies in sweeps |
| OPcache SHM corruption | pass (not reproduced) | 8.4.26 vs 8.4.27 differential; wasted_memory=0; 8.4.27 caches valid entry |

## 4. PoC reliability

| PoC | Claim | Independent status |
|---|---|---|
| 9bie | ASLR bypass / RCE | pass in the lab; host-layout dependent |
| ikow A/B/C | chains | readable; A/C need prerequisites; B local |
| ikow D/E | verification scripts | public; full exploits not public |
| GoldraK A/C/E scanner | 24/24 vulnerable | pass for A/C/E; does not measure OOM; 8.4.27 omitted from the table |
| dinosn | lab-assisted RCE | pass as lab-assisted; not a universal remote PoC |
| php2shellbt | scanner | fail: false positive on 8.4.27; CVEs mislabeled |
| eness | placeholder | n/a |

## 5. Deployment scope

| Layer | What was tested | Generalization |
|---|---|---|
| Official `php:8.4.26-apache` | RCE 3/3 On/ASLR on; 3/3 Off/ASLR off; 0/3 Off/ASLR on | PHP-level primitive; build/allocator dependent |
| Official `php:8.4.27-apache` | 0/5 control | Patch for the OOM class |
| Nextcloud 33.0.x test deployment, PHP 8.4.21 `mod_php` | Version/config validated; RCE not executed | App-independent primitive; deployment-specific |
| FPM A/C/E | RCE with lab prerequisites | App/config-dependent |
| Other PHP applications | not tested | Expected under the same conditions; not proven |

## 6. Gaps

- The FPM stale-BG sequence was reproduced to a deterministic UAF crash (DoS); the default crash
  mechanism was measured (allocator free-list encoding). A later controlled variant (fake
  `var_dtor_entries` in the multipart-reclaimed struct) gives a 16-byte write and reached command
  execution in the lab with local prerequisites (ASLR off, planted session); the remote ASLR-on
  variant was not demonstrated.
- The 8.5 backtraces arm and the OPcache arm were tested and did not reproduce as
  memory-safety issues in the lab.
- The 12/12 and 15/15 cookie counts were withdrawn: controlled repetitions on the official image gave 0/3 (ASLR on) and 0/3 (ASLR off); the 4000-byte cookie is state-dependent.
- `Off` + ASLR-on RCE was not achieved. The forged cookie discloses heap (id chunk base) but
  never the session HashTable and narrows `libphp` to a 1.88 MB window without pinning it; the
  channel is single-shot per OOM and `mod_php`-only, and on `mod_php` the leak and the
  stale-`BG(unserialize)` primitive are mutually exclusive. Both mechanisms were tested and
  closed.
- Kernel/allocator portability is not solved; public PoC results vary by host.
- A/C/E prerequisites are application-specific; the matrix records the lab conditions, not a
  universal exploitability claim.
- The Nextcloud 33.0.x test deployment was used for configuration validation, not as the RCE
  target; no other PHP applications were tested.
- No test was performed against a production system.
