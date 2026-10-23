# Raw lab captures

These are redacted terminal captures from the disposable lab containers used for the report.
Container IPs were replaced with `<container-ip>`; no hostnames, private addresses, credentials
or user data are included.

| File | Backs |
|---|---|
| `evidence-vuln-8426.txt` | 8.4.26 OOM/abort evidence (EVIDENCE section 2) |
| `evidence-fixed-8427.txt` | 8.4.27 control, no aborts (EVIDENCE section 2) |
| `evidence-aslr-diff.txt` | ASLR off/on leak and proof counts (EVIDENCE section 2) |
| `rce-on-aslr-on-8426.txt` | Final validation, 8.4.26 RCE, `display_errors=On`, ASLR on: 3/3 `uid=33` |
| `ctl-8427.txt` | Final validation, 8.4.27 control, 5 runs: `HEAP_LEAK_FAILED`, no aborts |
| `ace-8427.txt` | Final validation, A/C/E on 8.4.27-fpm: RCE `uid=33` |
| `ace-8512.txt` | Final validation, A/C/E on 8.5.12-fpm: RCE `uid=33` |
| `fpm-chain-e-8426.txt` | FPM chain E: gdb evidence of the `var_push` UAF, poison state and the 8.4.27 differential |
| `fpm-chain-e-encoding-8426.txt` | FPM chain E: watchpoint on the allocator free-list encoding over `used_slots` (EVIDENCE section 10) |
| `fpm-rce-ub-write.txt` | FPM chain E: watchpoint on `sapi_module.ub_write` = `&system`, nine `system` calls, `id` output (EVIDENCE section 10) |
| `backtraces-8511-gdb.txt` | 8.5.11 `fatal_error_backtraces` arm: zval UNDEF -> valid `IS_ARRAY_EX` (EVIDENCE section 10) |
| `opcache-differential-8426-8427.txt` | OPcache arm: compile-OOM differential, `wasted_memory=0` (EVIDENCE section 10) |
| `fixed-branches-verify.txt` | OOM/RCE harness on 8.5.12 / 8.3.36 / 8.2.35: 0/3, blocked at stage 1 (EVIDENCE section 3) |

The A/C/E and warmup matrices are summarized in `EVIDENCE.md`; their raw terminal captures are
retained in the private lab repository and are available to reviewers on request, together with
the lab harness. The earlier 12/12 and 15/15 cookie counts were withdrawn after controlled
repetitions gave 0/3 with ASLR on and 0/3 with ASLR off; the 4000-byte cookie is state-dependent.
No third-party exploit code is included here.

The full command lines and configuration are in `EVIDENCE.md` and `METHODOLOGY.md`.
