# Reliability — how often it actually fires
[English](RELIABILITY.md) · [Español](RELIABILITY.es.md)


A single successful run is not a result. These are the conditions that decide whether the
`display_errors=Off` + ASLR-on chain fires at all, and how often, measured across fresh targets.

## Geometry: 128M and `php.ini-production`, or nothing

The upstream `pure/` chain is calibrated for the stock geometry: `memory_limit=128M`, the
official `php.ini-production`, and the prefork worker pool as the image ships it.

- 128M, one worker, official image → **3/3**
- 8M, one worker, same image → **0/3**

The failure at 8M is **calibration, not the trigger**. A1 does fire at 8M — our older chain goes
**8/8** there with `display_errors=On` (see `PORTABILITY.md`). What breaks is the offset
arithmetic and the leak window, both sized for the 128M arena.

This matters because a widely quoted sentence says that lowering `memory_limit` does not help,
because the attacker sizes the OOM request to whatever the limit is. **Both statements are
true and they are about different chains.** In the mod_php cookie chain, the attacker picks the
body size and the limit does not stop them. In the upstream `pure/` chain, the constants are
fixed for 128M, so an 8M target fails for a reason that has nothing to do with the attacker's
control over the body.

## The target's `php.ini` decides more than the version

Our own `tooling/docker-compose.yml` does not reproduce the 10/10. The service `vuln-8426` loads
no `php.ini` at all:

```
Loaded Configuration File => (none)
display_errors => STDOUT
```

Adding `display_errors=Off` on top of `hardening-off.ini` gives **0/3**, because that is a
`conf.d` overlay, not `php.ini-production`. The chain needs the file the image ships with, not
an equivalent-looking directive.

## Cold start is not characterised

A fresh target, first run: **0/3**, with `no heap pointers in leak window`. The same target after
`docker restart`: **3/3**. The ten-run result in `raw/9bie-pure-off-aslr-on-10run.txt` restarts
the target before every run for exactly this reason.

We have not characterised the first-run failure: it could be pool warm-up, allocator state, or
page residency. It is a known unknown, written down instead of averaged away.

## What is not measured

- **FPM**: the E-OOM arm is `LAB ONLY` and is covered in `CHAIN-E.md`. No remote ASLR-on result.
- **CVE-2026-115560**: no stable fix at the time of writing; our attempt was inconclusive.
- **Long-running soak**: all runs are seconds-to-minutes. Nothing here says anything about
  behaviour after hours of load.

If a number in this repository is not in this file or in a `raw/` transcript, it is not a
measurement. It is a citation.
