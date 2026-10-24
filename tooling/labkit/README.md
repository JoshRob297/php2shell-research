# labkit: instrumented replica of the `PS(id)` allocator study

This kit reproduces the Phase 2 measurement published in `validation/`: where
the in-memory session id (`PS(id)`) and the session `HashTable` land, and why
the `Set-Cookie` window cannot reach the HashTable under
`display_errors=Off`.

It is lab-only. Payload A is destructive by design: it kills the request with an
OOM inside `php_session_send_cookie()`. Run it only against a disposable
container you built for this purpose.

## What it does

| Step | Action |
|---|---|
| 1 | Restart the container (clean allocator state). |
| 2 | Attach `psid_probe.gdb` to the single worker. |
| 3 | Optional warm-up request (`warmup.py`). |
| 4 | Payload A (`make_payload_a.py`): exhausts the bins and pages so the id encode aborts. |
| 5 | Payload B (`b_forge.py`): re-allocates the freed id chunk with a fake `zend_string` of length 4000. |
| 6 | Read the probe log, parse `RESET`/`TRACK` lines, append a CSV row. |

The probe logs, for every request:

```
RESET hit=N id=0x... len=... send=... chunk=0x... page=0x...
TRACK hit=N id=0x... ht=0x... ht_chunk=0x... ht_page=0x... delta=...
```

`delta = ht - id` is the quantity of interest. The cookie can only read forward
from the id's value pointer to the end of its 2 MiB chunk (at most 8168 B from
the id value). A negative delta, or a different chunk, means the HashTable is
unreachable.

## Prerequisites

1. **Debug build of the target PHP with symbols.** The reference build is PHP
   8.4.26 with the `docker-library/php` configure (Apache `apxs2`, 39
   extensions) and `CFLAGS="-O2 -g3"`. Recorded configure:

   ```
   --build=x86_64-linux-gnu --sysconfdir=/usr/local/etc
   --with-config-file-path=/usr/local/etc/php
   --with-config-file-scan-dir=/usr/local/etc/php/conf.d
   --enable-option-checking=fatal --with-mhash --with-pic --enable-mbstring
   --enable-mysqlnd --with-password-argon2 --with-sodium=shared
   --with-pdo-sqlite=/usr --with-sqlite3=/usr --with-curl --with-iconv
   --with-openssl --with-readline --with-zlib --disable-phpdbg --with-pear
   --with-libdir=lib/x86_64-linux-gnu --disable-cgi --with-apxs2
   ```

   A build with `--enable-debug --disable-all` does **not** reproduce the
   allocator behaviour: the extension set and `max_input_vars` change the
   request path.
 The probe needs
   `php_session_reset_id`, `php_session_track_init`, `php_session_initialize`
   and `zend_mm_safe_error` visible in `libphp.so`. Verify with
   `./check_build.sh <container>`.
2. **One prefork worker** (`apache-prefork.conf`). Both requests must land in
   the same process.
3. **`CAP_SYS_PTRACE`** and `seccomp=unconfined` for the container, otherwise
   gdb cannot attach:
   `docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ...`
4. **The lab `php.ini`** (`php.ini` in this directory): `display_errors=Off`,
   `memory_limit=8M`, `post_max_size=64M`, upload progress on.

The 8M limit is a deliberate calibration override. With the PHP defaults
(128M / 8M) payload A does not abort and the study does not apply; see
`tooling/oom_reach.py`.

## Running the sweep

```bash
# 1. Check the container first.
./check_build.sh p2s-lab

# 2. One calibrated point (matches the `base_off` row in validation/).
python3 sweep.py \
    --container p2s-lab \
    --url http://127.0.0.1:18080/index.php \
    --outdir out \
    --label base_off \
    --warmup 1500000 --S 63 --NB 235 --BL 15000 --X 208 --K 4 --KL 4000

# 3. A small grid (warm-up x S x X), if you want to map the neighbourhood.
python3 sweep.py --container p2s-lab --url http://127.0.0.1:18080/index.php \
    --outdir out --grid --K 4 --KL 4000
```

Every point restarts the container. Do not point the driver at anything that is
not disposable.

## Reading the output

`sweep.py` writes, per point:

- `<label>.gdb.log` — probe log (`RESET`, `TRACK`, chunk and bin dumps);
- `<label>.a.resp`, `<label>.b.resp` — raw HTTP responses;
- `sweep.csv` — one row per point with `id_page`, `ht_page`, `delta`,
  `same_chunk`, `window_ok`, response sizes and errors.

`window_ok = 1` means the HashTable starts at or after the id value and ends
within the readable window. It does not mean data leaked: that also requires the
forged id to be the one the worker sends (the `id_len` in `RESET`) and the
cookie to contain non-filler bytes. The published matrix shows cases with
`window_ok=1` and no leak, and why.

## Recalibrating

The defaults (`--d 1036288`, `--bb1 1048551`, `--read 4000`, field counts) are
calibrated for the reference build, one worker, the lab `php.ini`, and the
warm-up above. They are sensitive to PHP build, extension set and ASLR state.
If your build differs:

1. Run one point and read `id_page` and `ht_page` from the probe log.
2. Adjust `--d` so that `BF_start + d` equals the `RESET` id address. The probe
   prints `id` and the BF buffer starts at a stable offset from the request
   allocation; `--d` is the offset inside the value.
3. If `RESET` never fires, the worker is not the one serving requests, the
   build lacks symbols, or gdb is not attached (see prerequisites).

## Reproduced result

Against the reference image at `memory_limit=8M`, one worker, `display_errors=Off`:

```
a_resp_len  211      OOM aborted inside php_session_send_cookie
b_resp_len  5579     forged 4000-byte cookie returned
id_page     0x1fe000
ht_page     0x571c0
same_chunk  0
window_ok   0        HashTable lives in another 2 MiB chunk
```

This matches the `base_off` row in `validation/sweep-matrix.csv` (chunk base and
therefore `delta` vary with the run; the geometry does not).

## Files

| File | Purpose |
|---|---|
| `make_payload_a.py` | OOM-in-cookie payload generator (bins + page exhaustion) |
| `warmup.py` | Forces and releases a large chunk before payload A |
| `b_forge.py` | Forged session-id payload with absolute header offset |
| `psid_probe.gdb` | Read-only gdb probe: RESET/TRACK, chunk and bin dumps |
| `sweep.py` | Driver: restart, attach, A, B, parse, CSV |
| `php.ini` | Lab configuration |
| `apache-prefork.conf` | Single worker, KeepAlive off |
| `check_build.sh` | Verifies symbols, config and worker count |

## Scope

This is measurement instrumentation, not an exploit. It targets a build you
control, with one worker and a known configuration, and it aborts requests on
purpose. The published results (including the negative ones) are in
`../validation/`.
