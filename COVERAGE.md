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
| OOM abort / heap corruption | affected by version; not exploited | fail | pass | not tested | 8.4.27 control: 0/5, no aborts |
| RCE, `display_errors=On`, ASLR on | not tested | fail (3/3) | pass (0/5) | not tested | mod_php prefork |
| RCE, `display_errors=Off`, ASLR off | not tested | fail (3/3) | pass | not tested | offset-calibrated build |
| RCE, `display_errors=Off`, ASLR on | not tested | not stable (controlled 0/3) | pass | not tested | 12/12 claim withdrawn; cookie state-dependent |
| FPM session decode OOM / stale BG | not tested | public verification; not independently end-to-end | not tested | not tested | CVE-2026-109619; full FPM chain not reproduced |
| Memory disclosure via cookie | not tested | partial (4000-byte cookie; code leak blocked under ASLR on) | pass | not tested | geometry-dependent |

## 2. Request-level chains

| Chain | 8.4.26 | 8.4.27 | 8.5.12 | Remote? | Notes |
|---|---|---|---|---|---|
| A: upload-progress filename + LFI | fail | fail | fail | requires LFI | `strict=0`, `cleanup=Off`, `use_only_cookies=1` tested |
| A with `strict=1` | pass | pass | pass | requires LFI | file under chosen SID absent |
| A with `cleanup=On` + race | not tested | inconclusive (2 attempts) | not tested | requires LFI | not a formal guarantee |
| B: local `/proc/self/mem` | n/a | n/a | n/a | no | local primitive |
| C: per-directory handler mismatch + gadget | fail | fail | fail | application-level | one prefork child in the mod_php test |
| D/E: OOM/state chains | public verification | public verification | not tested | D remote, E local in the harness | full D/E not public |
| `PS(serializer)` across requests | pass (no stale) | pass (no stale) | not tested | n/a | FPM and mod_php |

## 3. Patch and guard status

| Item | Status | Evidence |
|---|---|---|
| 8.4.27 includes the OOM/state-corruption fix | pass | `NEWS`, source diff, 0/5 control |
| 8.4.27 resets `PS(serializer)` | fail (not present) | source diff |
| 8.4.27 includes PR #22113 fixed-SID guard | fail (not present) | PR open; source diff |
| `session.use_strict_mode=1` blocks A fixed SID | pass | lab, 8.4.26/8.4.27/8.5.12 |
| `session.use_only_cookies=1` alone blocks A | fail | A succeeded with SID only in multipart |
| `session.upload_progress.enabled=0` blocks A | not tested (expected block) | A requires the handler |
| `cleanup=On` blocks A deterministically | not proven | 2 race attempts failed; not conclusive |
| `PS(serializer)` leak across requests | pass (not observed) | h1/h2, FPM and mod_php |

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

- The full FPM OOM chain was not independently reproduced end-to-end.
- The 12/12 and 15/15 cookie counts were withdrawn: controlled repetitions on the official image gave 0/3 (ASLR on) and 0/3 (ASLR off); the 4000-byte cookie is state-dependent.
- `Off` + ASLR-on RCE was blocked by allocator geometry in the tested build.
- Kernel/allocator portability is not solved; public PoC results vary by host.
- A/C/E prerequisites are application-specific; the matrix records the lab conditions, not a
  universal exploitability claim.
- The Nextcloud 33.0.x test deployment was used for configuration validation, not as the RCE
  target; no other PHP applications were tested.
- No test was performed against a production system.
