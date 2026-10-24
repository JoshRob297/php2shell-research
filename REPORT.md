# php2shell: technical report

**CVE-2026-109618 / CVE-2026-109619**

Version 1.6, 2026-10-23. Prepared by **JoshRob**. Independent security research. No hostnames,
addresses, credentials or customer data.

Changelog: v1.1 documented the FPM stale-BG chain reproduction. v1.2 records the definitive crash
mechanism of that chain (allocator free-list encoding, DoS), retracts an earlier misreading of
the watchpoint evidence, and closes the 8.5 `fatal_error_backtraces` and OPcache arms with
symbol builds and controlled differentials (see section 6 and `EVIDENCE.md`). v1.3 verified the
fixed branches (8.5.12, 8.3.36, 8.2.35). v1.4 evaluated `PS(serializer)` without reset (no stale
handler). v1.5 documents the controlled-write variant of the FPM stale-BG chain (E-OOM) and the
full FPM command execution reached in the lab (section 5.5, section 9, `EVIDENCE.md` section
10); the v1.2 retraction covered the residual-block reading, not this controlled variant. v1.6
is an editorial revision: it labels the request-level arm E (decode failure + local file
planting) and the FPM stale-`BG(unserialize)` chain E-OOM, and keeps the iteration history in
this changelog; no measurement changes.

## 1. Executive summary

`php2shell` is a cluster of vulnerabilities in PHP request startup. The two assigned CVEs cover
related manifestations of state corruption caused by out-of-memory (OOM) conditions and bailout
paths that do not fully unwind per-request state:

- **CVE-2026-109618** — state corruption via bailout during request startup.
- **CVE-2026-109619** — session decode OOM followed by stale global state.

The OOM/state-corruption bugs are pre-authentication: they occur before the application's PHP
code runs. In a vulnerable `mod_php` prefork deployment with session upload progress enabled, a
remote attacker can use large multipart requests to force worker aborts, pair a corrupted worker
with a later request, leak process memory, and in the tested conditions execute code as the web
user. Worker aborts also provide a denial-of-service primitive.

PHP 8.4.27 and the corresponding 8.3.36, 8.2.35 and 8.5.12 releases contain the vendor fix for
the OOM/state-corruption class. The fix is necessary. It is not a complete fix for every public
exploit chain: the request-level A/C/E chains still worked against 8.4.27 and 8.5.12 in our lab
when their prerequisites were present. A/C/E are not the same primitive as the OOM chain; their
prerequisites and impact are described in section 5.5.

## 2. Disclosure timeline

Times are UTC, from public sources.

| Date | Event |
|---|---|
| 2026-08-11 | First reports of the bug class |
| 2026-08-24 | Additional independent reports |
| 2026-09-21 | PHP begins the coordinated fix |
| 2026-10-20 15:00 | CVE identifiers leak with an incorrect 10.0 score |
| 2026-10-20 19:30 | PHP moves the release forward to 2026-10-21 |
| 2026-10-21 03:02 | A major CDN/WAF publishes preventive rules |
| 2026-10-21 07:41 | Early fixed container images appear before the release |
| 2026-10-21 07:43 | First attack traffic reported |
| 2026-10-21 11:35 | Large-scale exploitation via upload progress reported |
| 2026-10-21 14:00 | Coordinated release: 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| 2026-10-21 14:17 | NVD records both CVEs |
| 2026-10-21 20:30 | One vendor reports no exploitation in its partner base |
| 2026-10-22 | Independent lab reproduction and patch verification (this report) |

The leak and the early images compressed the patch window. The release was originally planned
for 2026-10-22 and was moved forward.

## 3. Affected and fixed versions

| Version | OOM/state-corruption CVEs | Request-level A/C/E chains |
|---|---|---|
| 8.4.21 | Vulnerable by version; not exploited in this report | Prerequisites dependent |
| 8.4.26 | Vulnerable (lab RCE) | RCE with lab prerequisites |
| 8.4.27 | Fixed (vendor) | Still work with lab prerequisites |
| 8.5.12 | Fixed (0/3 with the lab OOM chain; blocked at the heap leak stage) | Still work with lab prerequisites |
| 8.3.36 / 8.2.35 | Fixed (0/3 each with the lab OOM chain; blocked at the heap leak stage) | Not tested here |

The independent OOM/RCE reproduction used official `php:8.4.26-apache` and
`php:8.4.27-apache` images, and the same harness was run against `php:8.5.12-apache`,
`php:8.3.36-apache` and `php:8.2.35-apache` (0/3 each; the vulnerable control rerun in the same
harness gave 3/3). The request-level A/C/E differential additionally used `php:8.4.26-fpm`,
`php:8.4.27-fpm` and `php:8.5.12-fpm`. See `EVIDENCE.md` and `raw/fixed-branches-verify.txt`.

A **Nextcloud 33.0.x test deployment** running PHP 8.4.21 under Apache `mod_php` prefork was
used to validate the exposed configuration and patch level. The RCE proof was on the official
`php:8.4.26-apache` image; we did not execute the RCE against the Nextcloud deployment. The bug
is in PHP request startup, before application code, so the application name is not the
primitive; the deployment conditions determine exploitability.

## 4. Root cause

CWE mapping used in this report: CWE-416 (use-after-free), CWE-755 (improper handling of
exceptional conditions), CWE-824 (access of uninitialized pointer), CWE-1325 (improperly
controlled sequential memory allocation).

### 4.1 Request startup and bailout

PHP request startup allocates and initializes per-request globals before user code runs. An OOM
or fatal error during this phase can invoke `zend_bailout()`/`longjmp`. If the unwind is
incomplete, the worker can retain state that belongs to the aborted request. The next request
served by that worker then observes stale pointers, flags or session state.

The bug class is timing-dependent: the attacker must cause the abort and then get a later
request routed to the same worker. Multi-worker `mod_php` prefork and body-streaming proxies make
the pairing practical; buffering proxies and `KeepAlive` change the odds.

### 4.2 CVE-2026-109618

The advisory describes state corruption via bailout during request startup. In the lab, large
multipart bodies and low `memory_limit` values produced worker aborts and corrupted session
state. A second request could consume the stale state and leak memory or redirect execution.

### 4.3 CVE-2026-109619

The session module's decode path can run out of memory while reading a large session. The
`BG(unserialize)` state remains dirty after the abort. A later request that processes session
upload progress can consume that state, leading to object/destructor confusion and a
use-after-free. Public verification code demonstrates the OOM and stale-state sequence under
PHP-FPM; this report independently reproduced the stale-state sequence on PHP-FPM 8.4.26 to a
use-after-free crash (502) and verified that 8.4.27 closes it. A symbol build with a hardware
watchpoint shows the crash mechanism: the freed `struct php_unserialize_data` run is recycled as
an allocator page for bin 16, and the free-list construction overwrites `used_slots` with an
encoded pointer (`bswap` store in `zend_mm_alloc_small_slow`); `var_push` then writes outside
the mapping and the worker dies (deterministic 502). That is the default behavior when the freed
run is not reclaimed by attacker data. A controlled variant (section 5.5) reclaims the struct
with the multipart field buffer and turns the destructor walk into a controlled 16-byte write;
aimed at `sapi_module.ub_write`, it executed a command in the lab. The full remote-style RCE
reproduction remains on `mod_php` prefork.

### 4.4 The 8.4.27 patch

The 8.4.27 `ext/session/session.c` contains:

- early reset of request globals before session/upload-progress processing;
- `PS(in_rfc1867_update)` and `php_session_unserialize_init()` with
  `php_var_unserialize_set_incomplete_classes_only()`: during upload-progress decode, objects
  are kept as `__PHP_Incomplete_Class`, with no autoload, `__wakeup` or `__unserialize`;
- a `PG(modules_activated)` guard in the rfc1867 callback, explicitly commented for
  `request_parse_body()`, so the callback does not run after normal request startup;
- cleanup of `_SESSION` after the upload-progress update.

The patch does **not** reset `PS(serializer)` and does **not** contain the fixed-SID guard from
PR #22113. Those are different issues; see section 5.5 and `EVIDENCE.md`.

The missing `PS(serializer)` reset was tested directly, because a stale serializer pointer
would mean session-format confusion. With per-directory serializer differences
(`php_serialize` in one directory, `php` in another), an OOM abort in either directory does not
leave a stale serializer: the next request uses the serializer dictated by its own INI
(verified through the session-file format), in both 8.4.26 and 8.4.27. The non-reset remains a
defense-in-depth gap; no attacker-reachable divergence window was found (the INI update handler
performs no limited-heap allocation). The configuration-level hazard (different handlers per
directory) is a separate issue and stays in remediation.

## 5. Exploitation model

### 5.1 Preconditions

The full OOM/RCE chain observed in the lab required:

- Apache with `mod_php` and `mpm_prefork` (multiple workers);
- `session.upload_progress.enabled=On`;
- a `post_max_size`/`memory_limit` combination that allows a body large enough to exhaust a
  worker (tens to hundreds of MB, depending on the build);
- a request path that reaches PHP before application routing or authentication;
- for code execution with `display_errors=Off`, either ASLR disabled or a usable code leak.

A representative deployment with these conditions was assessed during the disclosure window; network
gating reduced the practical exposure. See section 7.

### 5.2 OOM and worker pairing

The attacker sends large multipart requests to exhaust the worker's memory. The worker aborts
and Apache replaces it. By saturating the worker pool and streaming request bodies, the attacker
increases the chance that a later request lands on a worker that still contains corrupted state.
In the lab, N-1 saturation produced successful pairing with 4, 8 and 16 workers.

### 5.3 Memory disclosure and ASLR

With `display_errors=On`, error output and malformed session handling provided enough
information to complete the chain. With `display_errors=Off`, the attacker needs a separate
leak, typically through a large `PHPSESSID` cookie and the response header path.

In the tested image, the stale session id lands in the cached chunk while the session
`HashTable` — the only pointer to `libphp` — sits in the main chunk at a distance of
8,745,096 bytes. The reachable window is 8,168 bytes at the chunk boundary. This geometry
blocked the `Off` + ASLR-on chain in our lab; the `Off` + ASLR-off variant succeeded 3/3.

### 5.4 Code execution

With a usable leak or ASLR disabled, the chain reaches `libphp` and executes a command as the
web user. The lab proof was `uid=33(www-data)`. The exact offsets are build-specific; a debug
build with the same configure flags was used for introspection. Stripped builds need a
different calibration or leak.

### 5.5 The A/C/E request-level chains

Name note: the public fork labels its third request-level arm E (decode failure + destructor,
local file planting). This report calls that arm E (decode failure) and labels the FPM
stale-`BG(unserialize)` chain E-OOM, the OOM/state primitive fixed in 8.4.27.

Public PoCs group several chains under the php2shell name. They are useful, but they are not all
the same vulnerability and not all are remote:

- **A — session upload-progress filename injection + LFI.** The multipart `PHPSESSID` field is
  copied to the upload-progress session even when `session.use_only_cookies=1`; the attacker's
  filename ends up in the session file. An LFI sink then includes the file. This worked on
  8.4.26, 8.4.27 and 8.5.12 with `strict=0`; `strict=1` blocked the fixed-SID variant in our
  tests. PR #22113 (open) is the missing `use_only_cookies` guard, not a fix for the OOM CVEs.
  A separate lab dropper uses the same write to place a shell-readable file during the upload
  window, including with `cleanup=On`; execution still requires a command primitive such as
  `sh</tmp/sess_<id>`. It is a post-exploitation write primitive, not an independent remote RCE.
- **B — local `/proc/self/mem`.** Local primitive; not a remote chain.
- **C — per-directory session handler mismatch.** One directory writes with `php_serialize`,
  another reads with `php`; a gadget's `__destruct` fires. This is an application-level
  configuration/gadget issue; the 8.4.27 memory patch does not address it.
- **D and E-OOM — OOM/state chains.** The public D/E material includes verification scripts; the
  full exploits are not public in the reviewed repository. In our FPM lab, E-OOM produces more
  than the DoS. When the dangling `php_unserialize_data` is reclaimed by the multipart field
  buffer, the attacker controls both the fake structure and its `var_dtor_entries`; a negative
  `used_slots` turns the destructor walk into a 16-byte `{value, IS_LONG}` write at a chosen
  16-aligned address. The write was aimed at `sapi_module.ub_write`, replaced with the libc
  `system` entry, so each subsequent output chunk runs as a command. Command execution was
  reached in the lab, with local prerequisites: ASLR off, a locally planted 24-byte session
  file, and a symbol build for address calibration. It is not a remote ASLR-on exploit.

### 5.6 Generalizability: PHP-level bug, deployment-specific exploitability

The primitive is in PHP request startup, not in Nextcloud. The official `php:8.4.26-apache`
RCE proves the PHP-level bug; the Nextcloud 33.0.x test deployment validated the exposed
configuration and patch level. Other PHP applications on the same SAPI and configuration are
expected to be affected, but we did not test them. Do not turn "PHP-level bug" into "every PHP
deployment is exploitable with the same PoC".

| Layer | What was tested | Generalization |
|---|---|---|
| PHP 8.4.26 `mod_php` official | RCE 3/3 On/ASLR on; 3/3 Off/ASLR off; 0/3 Off/ASLR on | PHP-level primitive; build/allocator dependent |
| PHP 8.4.27 official | 0/5 control | Patch for the OOM class |
| Nextcloud 33.0.x test deployment, PHP 8.4.21 `mod_php` | Version/config validated; RCE not executed | App-independent primitive; deployment-specific |
| FPM A/C/E | RCE with lab prerequisites | App/config-dependent |
| Other PHP applications | not tested | Expected under the same conditions; not proven |

Exploitability depends on the SAPI (`mod_php` prefork vs PHP-FPM), worker count,
`session.upload_progress`, `memory_limit`/`post_max_size`, ASLR, allocator and kernel layout,
build flags, and any proxy/WAF in front of PHP. The public ASLR-bypass PoC reproduced on one
host and not on another. The A/C/E chains additionally need LFI, a per-directory serializer
mismatch, or a local write, depending on the chain.

The analysis used multiple AI models and specialized subagents under human direction; see
`METHODOLOGY.md`. AI output was treated as a hypothesis. Every claim in this report is backed by
a command/output, a public source or a source-code comparison.

## 6. Independent verification

| Claim | Independent result |
|---|---|
| 8.4.26 `mod_php`, `display_errors=On`, ASLR on | RCE 3/3, `uid=33` |
| 8.4.26 `mod_php`, `display_errors=Off`, ASLR off | RCE 3/3, `uid=33` |
| 8.4.26 `mod_php`, `display_errors=Off`, ASLR on | 4000-byte cookie state-dependent; no session-table read; heap pointers disclosed (section: in-band channel audit) |
| 8.4.27 control | 0/5, no aborts or over-read |
| A on 8.4.26 / 8.4.27 / 8.5.12 with lab config | RCE |
| A with `use_only_cookies=1`, `strict=0`, SID only in multipart | RCE on all three |
| A with `strict=1` | Blocked in the tested configuration |
| C on 8.4.26 / 8.4.27 / 8.5.12 | RCE in the lab harness |
| E (decode failure + destructor, local file planting) on 8.4.26 / 8.4.27 / 8.5.12 | RCE with local session-file planting |
| `PS(serializer)` across requests, FPM and `mod_php` | No stale handler observed |
| `PS(serializer)` with per-directory serializer differences + OOM abort (8.4.26/8.4.27) | No stale: the next request uses its own INI serializer (session-file format verified); divergence window not reachable |
| E-OOM (FPM stale `BG(unserialize)`) | Deterministic UAF crash (502) on 8.4.26; default mechanism = allocator free-list encoding over `used_slots`; with the multipart-reclaimed struct (planted 24-byte session, ASLR off) the fake `var_dtor_entries` gives a controlled 16-byte write to `sapi_module.ub_write` = `&system` -> command execution in the lab; 8.4.27 stable |
| 8.5.11 `fatal_error_backtraces` arm (symbol build) | Not reproducible: zval UNDEF -> valid `IS_ARRAY_EX` after the fetch, guarded by `Z_ISUNDEF`; 0 anomalies in 128+120 request sweeps |
| OPcache SHM arm (8.4.26 vs 8.4.27) | No corruption (`wasted_memory=0`); measured differential: 8.4.27 completes the near-OOM compile and caches a valid entry, 8.4.26 fails every run |
| OOM/RCE harness rerun on `php:8.4.26-apache` (control) | 3/3 PROOF `uid=33(www-data)` (stages 1-2-3) |
| OOM/RCE harness on `php:8.5.12-apache` | 0/3; blocked at stage 1 (heap leak) |
| OOM/RCE harness on `php:8.3.36-apache` | 0/3; blocked at stage 1 (heap leak) |
| OOM/RCE harness on `php:8.2.35-apache` | 0/3; blocked at stage 1 (heap leak) |

The scanner from one public fork reports 24/24 vulnerable versions using A/C/E. That result is
consistent with our A/C/E tests, but it does not measure the OOM/state-corruption chain and it
does not include 8.4.27 in its result table. It is not evidence against the 8.4.27 patch for the
OOM CVEs.

## 7. Impact and severity

- **RCE as the web user**, before application authentication, in the tested `mod_php` prefork
  configuration.
- **Memory disclosure** from the worker, including credentials, session tokens or keys present
  in process memory, via the `PHPSESSID` response path.
- **Denial of service** through worker aborts and repeated OOM conditions.
- **Lateral movement** is possible if the web user can reach internal services or mounted data.

Vendor CVSS: 9.2 (v4.0, `AC:H`/`AT:P`). NVD: 9.8 (v3.1, `AC:L`). The difference reflects the
v3.1 inability to express attack requirements; it is not a contradiction.

Our deployment-specific assessment (Bugcrowd VRT priority scale): **P1** if the PHP endpoint is
reachable unauthenticated; **P2** when a forward-auth or equivalent gate is the only barrier,
because the bug is pre-authentication but the external path is gated. Severity is
deployment-dependent; do not apply a single score without the network context.

## 8. Remediation

Upgrade to 8.4.27 or the corresponding fixed release (8.3.36, 8.2.35, 8.5.12), then apply the
configuration and detection guidance in `REMEDIATION.md`. The short version:

- upgrade and verify `php -v`;
- set `session.use_strict_mode=1` and `session.use_only_cookies=1`;
- disable `session.upload_progress` if the application does not need it, or keep
  `session.upload_progress.cleanup=On`;
- keep request-body buffering/limits and WAF rules in front of PHP;
- remove LFI sinks, per-directory serializer mismatches and gadget classes from the reachable
  path;
- monitor OOM/abort logs, worker restarts and anomalous `PHPSESSID` behavior.

The 8.4.27 patch fixes the OOM/state-corruption CVEs. It does not fix the request-level A/C/E
chains; those require the application/configuration controls above.

## 9. Limitations

- All tests were in a lab with official images and loopback traffic; no production system was
  targeted.
- The Nextcloud 33.0.x test deployment was used for configuration validation, not as the RCE
  target. The RCE proof was on the official PHP image; no other PHP applications were tested.
- The `Off` + ASLR-on RCE was blocked by allocator geometry in the tested build; a different
  build or primitive may change the distance.
- The 4000-byte cookie is state-dependent: controlled repetitions on the official image gave
  0/3 with ASLR on and 0/3 with ASLR off.
- Results are kernel- and allocator-sensitive. The same public PoC did not reproduce on every
  host.
- The FPM stale-BG sequence (E-OOM) was independently reproduced to a deterministic UAF crash
  (502) with a symbol build; the crash mechanism (allocator free-list encoding over `used_slots`)
  was verified with a hardware watchpoint. The residual `var_dtor_entries` block alone does not
  give an attacker-controlled write. When the dangling struct is reclaimed by the multipart
  field buffer, the fake `var_dtor_entries` gives a controlled 16-byte write. With ASLR off and
  a locally planted session file, that write reached `sapi_module.ub_write` and executed a
  command as the web user (section 5.5). The remote ASLR-on variant was not demonstrated; the
  `mod_php` chain remains the full remote-style RCE reproduction.
- The 8.5 `fatal_error_backtraces` arm and the OPcache SHM arm were tested with symbol builds
  and controlled differentials; neither reproduced as a memory-safety issue in the lab (see
  section 6).
- A/C/E results depend on lab prerequisites (LFI, per-directory handlers, local file planting).
- Public PoC quality varies; one scanner produced a confirmed false positive on 8.4.27.
- No third-party exploit code is redistributed in this repository.
- The lab scripts and PoC code exist in a separate private, invite-only repository, available on
  request from the author; they are not part of this release.

## 10. Conclusion

The php2shell OOM/state-corruption bugs are a PHP-level, pre-authentication risk for deployments
that expose request startup to untrusted multipart traffic. The Nextcloud 33.0.x test
deployment validated the exposed configuration; it was not the RCE proof target. The official
PHP image proves the primitive. Patch 8.4.27 closes the OOM/state-corruption class; it is not a
universal fix for every public chain. The FPM variant shows that the corrupt state can become a
controlled write and command execution when the dangling structure is reclaimed by attacker
data; our FPM demonstration stayed in the lab with local prerequisites (section 9). Defenders
should patch, then verify the configuration and
application conditions that make the request-level chains reachable. Independent reproduction
matters: a CVE identifier, a scanner verdict or a public exploit name is not proof of
exploitability on a given build.

See `POCS.md` for the public PoC review, `EVIDENCE.md` for the sanitized measurements,
`REMEDIATION.md` for the full guidance and `REFERENCES.md` for sources.
