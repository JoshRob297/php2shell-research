# php2shell: CVE-2026-109618 / CVE-2026-109619

Independent verification and exploitation analysis of the PHP request-startup vulnerabilities
known as **php2shell**. Prepared by **JoshRob**.

- Status: final public report, 2026-10-22.
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

## Key results

| Test | Result |
|---|---|
| PHP 8.4.26, `display_errors=On`, ASLR on | RCE 3/3 as `uid=33` |
| PHP 8.4.26, `display_errors=Off`, ASLR off | RCE 3/3 as `uid=33` |
| PHP 8.4.26, `display_errors=Off`, ASLR on | No stable leak; controlled repetitions 0/3; 4000-byte cookie state-dependent |
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
| `raw/` | Redacted raw lab captures backing the OOM/ASLR rows |
| `LICENSE` | License notice for this text |

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
