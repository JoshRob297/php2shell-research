# Methodology

[English](METHODOLOGY.md) · [Español](METHODOLOGY.es.md)

---

## Lab

All experiments were performed on loopback interfaces with disposable containers and official
PHP images. No production system was targeted. The request-level chains were exercised with a
public PoC harness in a single-worker FPM pool; the OOM/RCE chain was exercised against official
`php:8.4.26-apache` and `php:8.4.27-apache` images with a prefork worker pool.

ASLR was controlled with `setarch -R` only in the ASLR-off runs. A debug build with the same
configure flags was used for symbol introspection; the official image does not expose the
internal symbols needed for offset calibration.

## Application deployment

A **Nextcloud 33.0.x test deployment** running **PHP 8.4.21 under Apache `mod_php` prefork** was
used to validate the exposed configuration and patch level. The RCE proof was obtained on the
official `php:8.4.26-apache` image, not by executing the exploit against the Nextcloud
deployment. This distinction matters: the bug is in PHP request startup, before application
code, so the application name is not the primitive; the deployment's SAPI, worker model, body
limits, session settings and network path determine exploitability.

## AI-assisted workflow

This research was conducted with multiple AI models and specialized subagents under human
direction. The workflow used:

- an orchestrator model for planning, evidence tracking and final review;
- subagents for literature review, public PoC review, static source comparison, lab
  orchestration and documentation checks;
- independent re-checks of high-impact conclusions with a different model where possible.

AI output was treated as a hypothesis, not as evidence. Every finding in this repository is
backed by a reproducible command/output, a public source, or a source-code comparison. Claims
that could not be reproduced are marked as hypotheses, limitations or "not tested". No AI is
listed as an author; the human author is **JoshRob**.

## Evidence rules

- No finding without a command, request, log excerpt or source line.
- Lab-only results are labeled as lab results.
- Public PoC claims are separated from independent measurements.
- Versions, SAPI, relevant `php.ini` values and ASLR state are recorded with each result.
- Third-party exploit code is not redistributed.

## Reproducibility

The PHP-level primitive is reproducible on official images under the stated configuration.
Exploitability is not universal: it depends on the SAPI (`mod_php` prefork vs PHP-FPM), worker
count, `session.upload_progress`, `memory_limit`/`post_max_size`, ASLR, allocator and kernel
layout, build flags, and any proxy/WAF in front of PHP. The public ASLR-bypass PoC reproduced
on one host and not on another. The A/C/E request-level chains additionally depend on
application conditions (LFI, per-directory serializer mismatch, local file write).

Do not read "PHP-level bug" as "every PHP deployment is exploitable with the same PoC". Read it
as "the application code is not the root cause; the deployment conditions decide whether the
primitive is reachable and reliable".
