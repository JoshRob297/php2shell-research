# Verify: pending runs to back the evidence rows

Status: **readme for the main operator agent**. Three claims in `EVIDENCE.md`
are documented but do not have a committed raw-output trail in any repo. This
runbook defines the runs, where the outputs go and the acceptance criteria so
the rows stop being "documented" and become "backed".

Generic rules:

- Images by digest as pinned in `EVIDENCE.md` section 1. No pulls by tag.
- All runs in disposable containers, loopback only, no real user data.
- Record **raw stdout/command line outputs** with timestamps in `raw/`
  (`raw/README.md` has naming and redaction rules).
- After each run, update the backing table at the end of `EVIDENCE.md`
  (row -> `raw/<file>` and pass/fail). `REPORT.md` keeps its claims; if a run
  fails, that claim's row gets a correction note and the REPORT section gets
  an errata line before publication.

## Run 1 — `php:8.4.27-apache` control (0/5)

Where EVIDENCE claims it: section 2, last row "control 5, 0/5".

1. Run the official image by digest with the pocs lab configs
   (`php.ini` On profile + `apache.conf`, single worker).
2. Request sequence: prime warmup POST (multipart, big fields), then the
   9bie-style chain stages 1-3, same parameters used in the 8.4.26 runs of
   `php2shell-audit` (`07-plan/progress/2026-10-22-orquestador-rce-oficial.md`).
3. Five independent container restarts.
4. Acceptance to keep the "0/5" row: no `zend_mm_heap corrupted`, no
   `child pid N exit signal Abort`, no 4000-byte cookie, no stage-3 output.
   If any run behaves differently, the row must be rewritten with the real
   numbers and REPORT section 3 corrected.

## Run 2 — A/C/E chains on 8.4.27 and 8.5.12

Where EVIDENCE claims it: section 3 table (`RCE uid=33` cells).

1. Environment: per `EVIDENCE.md` section 3 harness — single FPM worker,
   `session.use_only_cookies=0`, `session.use_strict_mode=0`,
   `session.upload_progress.cleanup=Off` (scanner config; the doc already
   says so). Toy app: LFI page `vuln.php?page=` per the chains' own docs.
2. Chains from `ikow/php2shell-poc` (A/C/E) and confirm with the GoldraK
   A/C/E scanner, run per their own READMEs. These repos
   are third-party: clone into `../lab/`, do not copy code into `pocs/`.
3. Runs: A, C, E x 2 image targets (8.4.27-fpm, 8.5.12-fpm), one run each
   minimum, more if the first diverges.
4. Acceptance to keep each `uid=33` cell: raw terminal capture showing
   `uid=33(www-data)` or equivalent web-user id. For A hardened variants
   (strict=1 -> payload not executed) capture the include warning as well.
5. If any cell fails: the REPORT and EVIDENCE tables get corrected the same
   day; an unbacked RCE claim does not go to publication.

## Run 3 — warmup stabilization counts (15/15)

Where EVIDENCE claims it: section 2 paragraph ("15/15 4000-byte cookies:
12 with ASLR on, 3 with ASLR off").

1. Environment: pocs `configs/display_errors_off/php.ini` + `apache.conf`.
2. Chain A+B warmup sweeps: 12 runs with ASLR on and 3 with ASLR off,
   warmup request between 1.2 and 2.0 MB before the A stage.
3. Acceptance: capture the 15 cookie-length oracle lines plus the
   `b_forge.py` output files imported into `raw/`.
4. Backing already documented partially in `php2shell-audit`
   (PRs #32) but without a run-by-run capture; this run closes it.

## Where the outputs go

- `raw/` in this repository (redacted per `raw/README.md`).
- Cross-check: `php2shell-audit` (private) progress docs gain the same runs
  as progress entries, so the lab trail and the publication trail match.
