# FAQ

## Is upgrading to 8.4.27 enough?

For the OOM/state-corruption CVEs (CVE-2026-109618 / CVE-2026-109619): yes, in our control
tests. For the request-level A/C/E chains grouped under the same name: no. Those require
configuration and application controls (`session.use_strict_mode=1`, disabling or locking down
upload progress, removing LFI sinks, avoiding per-directory serializer mismatches). See
`REMEDIATION.md`.

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

## Who wrote this?

The report is authored by **JoshRob**. The analysis used multiple AI models and specialized
subagents under human direction; AI output was treated as a hypothesis and every finding was
validated against commands, outputs or public sources. See `METHODOLOGY.md`.

## License

Text under CC BY 4.0 (see `LICENSE`). Third-party PoCs remain under their own licenses.

## Does the FPM variant work?

The stale-BG chain E was reproduced on PHP-FPM 8.4.26 with a symbol build: a session decode OOM
leaves `BG(unserialize)` stale, and the next request's upload-progress decode reuses the
dangling pointer (SIGSEGV in `var_push`, 502). 8.4.27 resets the state early and stays stable.
Full RCE in FPM was not reached; the crash is a denial-of-service primitive in the tested
configuration.
