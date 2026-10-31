# FAQ

[English](FAQ.md) · [Español](FAQ.es.md)

---

## Is upgrading to 8.4.27 enough?

For the OOM/state-corruption class (the two CVEs), yes: 8.4.27 resets the stale state early and
our control runs show no aborts or over-read. It is not enough for the request-level A/C/E
chains, which need application/configuration controls, and it does not cover CVE-2026-115560
(mitigation: `session.upload_progress.enabled=0` until the next regular release).

## Does `post_max_size` stop the OOM primitive at stock defaults?

For any body sent with a `Content-Length`, yes. On **unpatched** `mod_php` (8.2.34, 8.3.35,
8.4.26) a chunked multipart is not bounded: 30M parses in full and 70M OOMs at request startup
with defaults (`memory_limit=128M`, `post_max_size=8M`). **8.4.27/8.5.12 reject chunked bodies
over the limit** (`Actual POST length does not match Content-Length, and exceeds 8388608
bytes`), so the patch closes this route too. PHP-FPM does not parse chunked bodies at all
(no `CONTENT_LENGTH`), and nginx's `client_max_body_size` applies to chunked (413 at the
default 1M). The published ~3.7M payloads still do not OOM at defaults.

## Does `session.use_strict_mode=1` fix chain A?

It blocked the fixed-SID variant in our tests on 8.4.26, 8.4.27 and 8.5.12: the file under the
attacker-chosen SID does not exist. It does not fix C or E. It is defense in depth, not a
substitute for the patch.

## Is this a Nextcloud vulnerability?

No. The bug is in PHP request startup, before application code. The RCE proof was obtained on
the official `php:8.4.26-apache` image. A Nextcloud 33.0.x test deployment (PHP 8.4.21,
`mod_php` prefork) was used to validate the exposed configuration and patch level; the RCE was
not executed against that deployment.

## Does this repository contain PoCs?

No. It reviews public PoCs and links to them (`POCS.md`), and it includes independent
measurements and a reproduction outline. It does not redistribute third-party exploit code or
publish the lab scripts. The lab proof-of-concept code lives in a separate private, invite-only
repository, available on request from the author to vetted reviewers.

## Is the scanner php2shellbt reliable?

No. It produced a confirmed false positive on 8.4.27, mislabels the CVEs, ignores some PHP
branches and disables TLS verification. Use it as an anecdote, not as patch evidence.

## Why is there no universal PoC?

Exploitability depends on the SAPI (`mod_php` prefork vs PHP-FPM), worker count,
`session.upload_progress`, `memory_limit`/`post_max_size`, ASLR, allocator and kernel layout,
build flags, and any proxy/WAF. The public ASLR-bypass PoC reproduced on one host and not on
another. A/C/E additionally need LFI, a per-directory handler mismatch, or a local write.

## How do I verify my own deployment?

1. Patch to the fixed release for your branch.
2. Run the 8.4.27 control described in `EVIDENCE.md`.
3. Apply the configuration in `REMEDIATION.md`.
4. Check the detection signals (OOM/abort logs, anomalous `PHPSESSID`).
5. Re-derive the measurements with the published harness in [`lab/`](lab/README.md)
   (`147 passed, 4 skipped`); it ships without the operational modules.

## Who wrote this?

The report is authored by **JoshRob**. The analysis used multiple AI models and specialized
subagents under human direction; AI output was treated as a hypothesis and every finding was
validated against commands, outputs or public sources. See `METHODOLOGY.md`.

## License

Text under CC BY 4.0 (see `LICENSE`). Third-party PoCs remain under their own licenses.

## Does the FPM variant work?

The stale-BG chain (E-OOM) was reproduced on PHP-FPM 8.4.26 with a symbol build: a session
decode OOM leaves `BG(unserialize)` stale, and the next request's upload-progress decode reuses
the dangling pointer (SIGSEGV in `var_push`, 502). 8.4.27 resets the state early and stays stable.
In the lab the chain goes further: when the dangling struct is reclaimed by the multipart field
buffer, a fake `var_dtor_entries` turns the destructor walk into a controlled 16-byte write.
Aimed at `sapi_module.ub_write` = `&system`, the script output executed a command
(`uid=33(www-data)`). This required ASLR off, a locally planted 24-byte session file and a
symbol build; the remote ASLR-on variant was not demonstrated.

Note: the forged-cookie heap leak of section 11 is `mod_php`-only. On FPM the OOM that creates
the stale id also kills the worker (exit code 70, 502), so that leak channel does not exist
there; and on `mod_php` the leak and the E-OOM state are mutually exclusive (payload A clears
`BG(unserialize)`).

## Is there a third CVE?

Yes. On 2026-10-23 PHP published an informational advisory for CVE-2026-115560, a third issue
in the session upload-progress feature. It is not fixed by the 2026-10-21 emergency releases;
the fix lands in the next regular release. The condition is narrow: the application must set
`session.serialize_handler` to `php_binary` or `php_serialize` in configuration and then switch
it back to `php` at runtime with `ini_set()` before `session_start()`, with upload progress
enabled. PHP describes it as an unlikely vector; no exploitation was reported as of
2026-10-24. Until the fix ships, set `session.upload_progress.enabled=0`. Our test deployment
does not meet the condition, and this report does not test it.
