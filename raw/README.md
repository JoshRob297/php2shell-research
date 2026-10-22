# raw/ — redacted raw outputs backing EVIDENCE.md

Purpose: every run documented in `EVIDENCE.md` gets its raw terminal capture
committed here so the published report stays verifiable without access to the
private lab repos.

## Naming

```
YYYYMMDD_<run>_<target>.txt
```

- `<run>`: short label matching a row or bullet in `VERIFY.md`
  (examples: `ctl-84.27-run2`, `chainA-84.27`, `warmup-off-aslr-on-run7`).
- append `.log` when it is a pure log capture.

## Redaction rules

| Keep | Drop |
|---|---|
| command lines as run | any value from outside the lab loopback |
| raw log lines with timestamps (worker, proxy, scanner) | hostnames of the operator machine (docker container names are fine) |
| oracle outputs (cookie lengths, counters, aborts) | 100.x / 192.168.x addresses, user names, real domains |
| hex addresses, offsets, digests | anything that came from secret management |

Size: keep files small — one file per run, no directory dumps.
A run that cannot produce a smaller capture (too verbose) includes a
truncated tail (the part that shows the acceptance criterion) plus its exact
command line.

## When

The run is done when: raw file committed here, the corresponding row of the
backing table in `EVIDENCE.md` points to the file, and the parallel progress
entry exists in the lab repo (`php2shell-audit`).
