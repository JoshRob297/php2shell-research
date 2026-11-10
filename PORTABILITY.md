# Portability: why the same PoC gives different numbers

Every cell below was measured in the same lab — loopback, `php:8.4.26-apache`, three attempts
per cell unless stated — and answers one question: which conditions actually gate the chain,
and which ones only look like gates.

| Configuration | Result | Aborts |
|---|---|---|
| `display_errors=On`, `memory_limit=8M`, 1 worker | **8/8** | 32 (8 runs) |
| `display_errors=Off`, `memory_limit=8M`, 1 worker | 0/3 | 12 |
| `On`, `512M`, 1 worker, 12 MB field | 0/3 | 0 |
| `On`, `512M`, 1 worker, 480 MB field | **1/1 PROOF** | 4 |
| `On`, `8M`, 4 workers, standard exploit, no saturation | 0/3 | 0 |
| `On`, `8M`, 4 workers, saturation (hold N-1) | **6/6 PROOF** | 24 |
| `On`, `8M`, 8 workers, saturation (hold N-1) | **4/4 PROOF** | 16 |
| `On`, `8M`, 16 workers, saturation (hold N-1) | **3/3 PROOF** | 12 |
| `On`, `8M`, 4 workers, nginx proxy, buffering off, trickle, 64k | **3/3 PROOF** | 12 |
| `On`, `8M`, 4 workers, nginx proxy, **buffering on** | 0/1 | n/a |
| `On`, `8M`, 4 workers, **`KeepAlive On`** | 0/5 | 20 |
| `Off`, `8M`, 1 worker, debug build (primitive A, bin-128 oracle) | **4/4 OOM-in-cookie** (NB=235, K=4) | n/a |
| `On`, `8M`, 1 worker, official image, ASLR on | **3/3 PROOF RCE** | ~12 |
| `Off`, `8M`, 1 worker, official image, A+B warmup, ASLR on/off | 15/15 cookie at 4000 B inside its window (12 on / 3 off); controlled repetition **0/3** — stability claim withdrawn | n/a |
| `Off`, `8M`, 1 worker, official image, ASLR **off**, fixed addresses | **3/3 PROOF RCE** | n/a |
| `Off`, `8M`, 1 worker, official image, ASLR **on** | **0/3** — blocked by the `libphp` leak | n/a |
| `On`, `8M`, 1 worker, kernel pve 7.0, ASLR on | 0/3 | n/a |

## What the matrix says

1. **`memory_limit` is not the gate; `post_max_size` is.** At 512M/480 MB the chain runs the
   same, because the body fits; with the default 128M/8M the 3.7 MB A never exhausts memory and
   the primitive never starts. The 512M/480 MB row is a non-default configuration (the kind a
   Nextcloud deployment runs), and it is `display_errors=On`.
2. **`display_errors=Off` blocks exactly one thing: the `libphp` leak.** Primitive A and the
   `chunk_base` survive; what disappears is the pointer that turns a heap write into a code
   target.
3. **On prefork, worker saturation is mandatory.** Without holding the other children, the OOM
   lands on a child that is not the one that will carry the next request, and the chain dies at
   0/3. Holding `N-1` gives 6/6, 4/4 and 3/3 at 4, 8 and 16 workers.
4. **A proxy has to stop buffering.** With nginx buffering off and trickle delivery the chain
   survives; with buffering on it does not, because the connection never sits in the state the
   OOM needs.
5. **`KeepAlive On` breaks it**: 0/5. This is the cheapest mitigation on the matrix and it is
   not in PHP at all.
6. **A single measured run proves nothing.** The 15/15 row was the withdrawn cookie claim: in
   its window it reproduced, in controlled repetition it gave 0/3. Every number here that says
   `PROOF` came from a cell where the counts were repeated until they were stable.

This is the answer to "why does the public PoC work on my machine and not on yours": the
difference is usually the worker pool, the proxy buffering, or `KeepAlive`, not the PHP build.

## Provenance

Every cell was measured in the lab described in `METHODOLOGY.md`. The rows that need only the
checker and the stock images are reproducible with `make up`; the saturated-worker, proxy and
`KeepAlive` rows were driven by request-sequence scripts that carry the operational bodies, so
those transcripts stay in the private lab log rather than in this repository. The 9bie rows have
their raw sweeps committed (`raw/9bie-aslr-on-8run.txt`, `raw/9bie-aslr-off-5run.txt`,
`raw/9bie-display-off-3run.txt`).

If a number here does not reproduce on your host, the first three things to check are the worker
pool, the proxy buffering mode and `KeepAlive` — in that order, because that is the order in
which they break the chain.
