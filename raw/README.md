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

The A/C/E and warmup matrices are summarized in `EVIDENCE.md`; their raw terminal captures are
retained in the private lab repository and are available to reviewers on request, together with
the lab harness. The earlier 12/12 and 15/15 cookie counts were withdrawn after controlled
repetitions gave 0/3 with ASLR on and 0/3 with ASLR off; the 4000-byte cookie is state-dependent.
No third-party exploit code is included here.

The full command lines and configuration are in `EVIDENCE.md` and `METHODOLOGY.md`.
