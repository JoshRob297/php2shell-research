# Validation matrix: `PS(id)` vs the session HashTable

This directory holds the sanitized measurements behind the Phase 2 conclusion in
`REPORT.md`: under `display_errors=Off` the in-band `Set-Cookie` channel does not
disclose usable memory, and under stock resource limits the OOM primitive that
starts the chains does not fire at all.

## What was measured

For each run the server was restarted, a GDB probe was attached to the single
Apache worker, and two HTTP requests were sent:

- **A** — a multipart request carrying `PHP_SESSION_UPLOAD_PROGRESS` and a
  calibrated heap-grooming body. The body sizes the Zend MM bins so that the
  session id is the last bin-64 (or bin-56 with `sid_length=31`) chunk freed,
  and `php_session_send_cookie()` aborts during the id encode.
- **B** — a forged request that reuses the freed id chunk with a fake
  `zend_string` of length 4000 and asks the server to echo the cookie.

The probe logged `php_session_reset_id` (the in-memory id pointer) and
`php_session_track_init` (the session `HashTable` pointer) for every request.
`delta = ht - id` is the distance between the two, and the cookie window is
`8168 B` from the id's value pointer to the end of its 2 MiB chunk.

## Columns

| Column | Meaning |
|---|---|
| `label` | Run name used in the lab logs |
| `ini_profile` | Configuration profile: PHP defaults, 32M, or the 8M lab override |
| `memory_limit`, `post_max_size` | Effective PHP values |
| `id_len` | Length recorded on the in-memory session id at RESET |
| `id_page`, `ht_page` | Offset inside the 2 MiB chunk (not a system address) |
| `delta` | `ht_page - id_page`; positive means the HashTable is after the id |
| `same_chunk` | 1 if both fall in the same 2 MiB chunk |
| `a_resp_len`, `b_resp_len` | Raw HTTP response sizes |
| `leak_bytes` | Bytes outside the session alphabet `[A-Za-z0-9,-]` in the decoded `Set-Cookie` value |
| `ptr_like` | Count of 8-byte little-endian values in the `0x7f...` (user-space mmap) range inside the decoded value |
| `note` | Short interpretation |

## Conclusions

1. **Stock defaults stop the published payloads; the chunked route is version- and
   SAPI-scoped.** With `memory_limit=128M` and `post_max_size=8M`, request A (the ~3.7M
   published payload) returns a clean 200 and never aborts — for any body sent with a
   `Content-Length`. On unpatched `mod_php` (8.2.34, 8.3.35, 8.4.26) `post_max_size` is
   **not enforced on chunked bodies**: a chunked 30M multipart parses in full and a chunked
   70M multipart OOMs at request startup (worker survives). **8.4.27/8.5.12 reject chunked
   bodies over the limit** (`Actual POST length does not match Content-Length`), and PHP-FPM
   does not parse chunked bodies at all (no `CONTENT_LENGTH`). The published payload sizes
   remain ineffective against defaults; the chunked OOM is an unpatched-`mod_php` path.
2. **No forward-window geometry under the 8M lab profile.** In every 8M run the
   session `HashTable` lands in a different 2 MiB chunk, several megabytes away
   from the id, or up to 4552 B *before* it. The cookie window only reads
   forward, so it cannot reach the HashTable.
3. **`sid_length=31` produces adjacency, not control.** `sid31_128` shows the
   HashTable 56 B after the id, but that id is the one request B generates
   itself (31 chars, not attacker-controlled), so the forged 4000-byte length
   never applies and the cookie stays 258 B.
4. **Destructor ordering does not help.** In `pd_dummy` a registered class with
   a 31-byte property and a destructor was placed in `$_SESSION`; the
   HashTable still landed 4.56 MB away in a separate chunk, and the 4000-byte
   cookie decoded to 3000 NUL bytes with zero memory content. The id is
   assigned during `rfc1867_post_handler`, before any userland destructor runs.
5. **The forged-cookie channel discloses heap memory, but not the session
   HashTable.** The over-read starts at the forged header and continues past the
   1000-byte BF filler region, so it copies whatever follows it. In the 8M rows
   with a successful forge the decoded cookie carries 525-841 bytes outside the
   session alphabet (range across runs), including **47 pointer-like values at
   64-byte intervals starting at offset 1000** (e.g. `0x...e400`, `+0x80`,
   `+0x40`, ...). These are heap addresses inside the id's 2 MiB chunk, so the
   chunk base is recoverable by masking. A gdb follow-up identified them: they
   are the **Zend MM bin-64 free-list links**, carved out of a previous
   request's freed 4000-byte field buffer (the link qword overwrote the first 8
   bytes of each 64-byte chunk; the rest still holds the attacker's fill byte).
   No live object, session data or code pointer is disclosed. `pd_dummy` is the
   exception (no pointers): its object layout overwrites the over-read region
   with zeros.

6. **The leak narrows libphp, it does not pin it.** In a 20-run follow-up on the
   same point, the distance from the chunk base to libphp text (the
   `php_session_reset_id` breakpoint address) ranged from `0x289bc00` to
   `0x2a7dc00` (1.88 MB), with 19 distinct values and the low 12 bits constant
   (`delta % 0x1000 == 0xc00`). The page offset is therefore fixed and the
   unknown is the page index (~481 pages). The disclosure does not
   deterministically defeat ASLR for libphp; whether the window is usable
   depends on the build and on other primitives, and was not demonstrated.

   Correction: an earlier version of this file and of the matrix said the
   cookie leaked zero bytes. That was measured on the `pd_dummy` replication
   only and generalised by mistake. The byte counts above come from decoding
   every stored `*.b.resp` and are reproducible with the script in
   `evidence/` of the private audit repository.

7. **The channel is single-shot per OOM and does not accumulate entropy.** A
   second forged request without a new OOM returns a normal 32-byte cookie (the
   stale id is gone). Repeating A -> B with a new OOM per leak is possible, but
   the worker reuses the same id chunk: two consecutive cycles produced the same
   chunk, page and delta. Sampling different chunks requires restarting the
   worker, which is how the 20-run distribution was collected.
8. **The channel is `mod_php`-only.** On FPM the same payload A makes the worker
   exit (pool logs `child ... exited with code 70`, nginx returns 502), so the
   follow-up request runs in a new process, gets a fresh 32-byte session id and
   never sees the stale one. The leak and the FPM chain E cannot be combined in
   one worker: the leak needs the process to survive the OOM, and FPM does not.
9. **The leak and the stale-`BG(unserialize)` primitive are mutually exclusive.**
   On `mod_php` the E primitive does exist in isolation: after a decode OOM,
   `BG(unserialize)` stays at `level=1` with a dangling `data` pointer, and the
   next decode reuses it (`INIT level=1`), without a crash because the writes
   land in mapped heap. But payload A's OOM in `php_session_send_cookie` clears
   that state (`level=0`), and the producer that sets it leaves no stale session
   id. In one request the decode runs before the cookie is sent, so a single
   request cannot produce both; in separate requests each one destroys the
   other's state. Combining the leak with chain E is therefore not possible in
   one worker.

## Reproducing the matrix

`tooling/labkit/` contains the instrumentation: the gdb probe, the payload
generators, the single-worker configuration and the sweep driver. One calibrated
point (`base_off` geometry) is reproduced with:

```bash
cd tooling/labkit
./check_build.sh <container>
python3 sweep.py --container <container> --url http://127.0.0.1:18080/index.php \
    --label base_off --warmup 1500000 --S 63 --NB 235 --BL 15000 --X 208 --K 4 --KL 4000
```

## Evidence location

The raw gdb logs and A/B responses for the committed rows are archived in the
private audit repository, available to reviewers on request as described in
`README.md`. The `pd_dummy` row is an ad-hoc replica archived there as well.
Nothing in this directory is derived from a production system; all runs were
loopback containers with disposable state.
