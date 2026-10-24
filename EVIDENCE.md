# Evidence

Sanitized measurements from disposable lab containers. All traffic was loopback. Hostnames,
addresses and private paths are omitted; the commands are reproducible with official PHP images.

## 1. Lab setup

- Vulnerable image: `php:8.4.26-apache` (also `php:8.4.26-fpm` for the A/C/E differential).
- Control image: `php:8.4.27-apache` / `php:8.4.27-fpm`.
- Additional request-level tests: `php:8.5.12-fpm`.
- Apache `mpm_prefork` with a small worker pool; one worker where the test required
  determinism.
- `display_errors=On`, `memory_limit=8M`, `post_max_size=64M`,
  `session.upload_progress.enabled=On` for the public 9bie-style chain.
- ASLR controlled with `setarch -R` only in the ASLR-off runs.
- A debug build with the same configure flags was used for symbol introspection; the official
  image does not expose the internal symbols needed for offset calibration.

Image digests as pulled for the lab:

| Image | Digest |
|---|---|
| `php:8.4.26-apache` | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| `php:8.4.27-apache` | `sha256:a0b75cee7023ba2c127138dcad2ecc6ec7e09435534645e70450f29f24ea2a5a` |
| `php:8.4.26-fpm` | `sha256:f5431b57bda75455d5271967cc6b67df8f0d0b943832756e0c78eccdc98767dd` |
| `php:8.4.27-fpm` | `sha256:e2d8e787dc775bdbd9d7e0c5e8f2f9ddb41ce5977c8bbaf99a2ba2e7d90fd8ae` |
| `php:8.5.12-fpm` | `sha256:f665ad19c093eee54db3a03c89102d6828b1bbf4f327689e5947a8686c6585a1` |
| `nginx:alpine` | `sha256:892bb2152464f0c5d8972593a5f5afaf8054552580b699d95f8ff4af08c2d33d` |

## 2. OOM / RCE matrix (`mod_php`, official `php:8.4.26-apache`)

| Profile | Runs | Result |
|---|---|---|
| `display_errors=On`, ASLR on | 3 | RCE 3/3, `uid=33(www-data)` |
| `display_errors=Off`, ASLR off | 3 | RCE 3/3, `uid=33(www-data)` |
| `display_errors=Off`, ASLR on | 3 | Controlled repetitions 0/3; 4000-byte cookie state-dependent; heap pointers disclosed, no session-table read (section 11) |
| `display_errors=Off`, ASLR on, RCE attempt | 3 | 0/3; blocked by the leak geometry |
| `php:8.4.27-apache` control | 5 | 0/5; no aborts, no over-read (`raw/ctl-8427.txt`) |

An earlier lab run reported 12/12 and 15/15 4000-byte cookie counts. Controlled repetitions on
the official image later gave 0/3 with ASLR on and 0/3 with ASLR off; the 4000-byte cookie was
observed after many prior requests, suggesting chunk-pool state dependence. The 12/12 and 15/15
rows are therefore not stable, reproducible claims and are withdrawn as general results.

Raw captures for this section: `raw/evidence-vuln-8426.txt`, `raw/evidence-fixed-8427.txt`,
`raw/evidence-aslr-diff.txt`, `raw/rce-on-aslr-on-8426.txt`, `raw/ctl-8427.txt`.

### 8.4.26 abort evidence

```
zend_mm_heap corrupted
[mpm_prefork:error] server reached MaxRequestWorkers setting
[core:notice] child pid 18 exit signal Abort (6)
...
zend_mm_heap corrupted
[core:notice] child pid 31 exit signal Abort (6)
zend_mm_heap corrupted
[core:notice] child pid 32 exit signal Abort (6)
```

### 8.4.27 control

```
Apache/2.4.69 (Debian) PHP/8.4.27 configured -- resuming normal operations
...
POST /index.php HTTP/1.1 200 693
POST /index.php HTTP/1.1 200 259
...
server reached MaxRequestWorkers setting
```

No `zend_mm_heap corrupted` and no `exit signal Abort` in the 8.4.27 control.

### ASLR difference

```
== ASLR OFF 8.4.26 (5 runs) ==
PROOF: uid=33(www-data) 5/5

== ASLR OFF 8.4.27 ==
HEAP_LEAK_FAILED, 0 aborts

== leak ASLR OFF ==
hex128: 4c4141...b534d21e47b85c6ea070caf4ff7f0000 (pointers 0x7ffff4ca..., 104 hits)

== leak ASLR ON ==
hex128: 4c4141...2705be810d803a79a070aa36cd72 (0 hits in the 0x7f range)
```

## 3. Request-level A/C/E differential

Harness: public fork lab with a single FPM worker. Lab configuration:
`session.use_only_cookies=0`, `session.use_strict_mode=0`,
`session.upload_progress.cleanup=Off`. This is the scanner's configuration, not a hardened
default.

| Test | 8.4.26 | 8.4.27 | 8.5.12 |
|---|---|---|---|
| A: upload-progress filename + LFI | RCE `uid=33` | RCE `uid=33` | RCE `uid=33` |
| C: per-directory handler mismatch + gadget | RCE `uid=33` | RCE `uid=33` | RCE `uid=33` |
| E (request-level): decode failure + destructor, local file planting | RCE `uid=33` | RCE `uid=33` | RCE `uid=33` |

Final validation 2026-10-22: A/C/E re-run on 8.4.27-fpm and 8.5.12-fpm; raw captures in
`raw/ace-8427.txt` and `raw/ace-8512.txt`.

A with a hardened `use_only_cookies=1`, `strict=0`, `cleanup=Off`, SID only in the multipart
body, no cookie:

```
POST /index.php  -> 200
GET  /vuln.php?page=/tmp/sessions/sess_<sid>&c=id
payload executed
uid=33(www-data)
```

A with `strict=1`:

```
GET /vuln.php?page=/tmp/sessions/sess_<sid>
Warning: include(...): Failed to open stream: No such file or directory
payload not executed
```

The file under the chosen SID is absent because strict mode regenerates an uninitialized SID.
With `cleanup=On` and a slow-upload race (8 s, 256 KB padding, 20 ms delay), no RCE was observed
in two attempts. This is not enough to treat `cleanup=On` as a guaranteed mitigation.

C and E are not the OOM primitive:

- C requires a per-directory serializer mismatch and an application gadget.
- E's harness plants the session file locally (`docker exec`); it proves the destructor on
  decode failure, not a remote write.

## 4. 8.5.12

```
PHP 8.5.12
SAPI fpm-fcgi
upload_progress 1
OK
```

| Test | Result |
|---|---|
| A, lab configuration | RCE `uid=33` |
| A, `use_only_cookies=1`, `strict=0`, `cleanup=Off`, SID only in multipart | RCE `uid=33` |
| A, `strict=1` | no RCE; chosen SID file absent |
| C, lab configuration | RCE `uid=33` |
| E, lab configuration + local planting | RCE `uid=33` |

## 5. Apache `mod_php` per-directory serializer

One prefork child. `/app` sets `php_value session.serialize_handler php_serialize`; `/api` sets
`php_value session.serialize_handler php`; both share the session save path.

```
== h1 (app, php_serialize) ==
H1=php_serialize
== h2 over a php-format file (api, php) ==
H2=php
A=b
== h2 direct control ==
H2=php
A=b
== h1s writes php_serialize ==
H1s=php_serialize SID=<sid>
== h2 reads the mismatch with php ==
Warning: session_start(): Failed to decode session object. Session has been destroyed
H2=php
A=none
```

The reader uses its own configured handler (`php`); it does not retain the previous request's
`php_serialize` pointer. The decode failure is the deliberate per-directory mismatch (chain C),
not a stale `PS(serializer)`.

## 6. `PS(serializer)` in FPM

Endpoints:

- `h1.php`: `ini_set('session.serialize_handler','php_serialize')`, no session start.
- `h2.php`: `session_start()`, prints the handler and `$_SESSION['a']`.
- Session file `sess_leaktest` contains `a|s:1:"b";` (php format).

```
h1:            H1=php_serialize
h2 after h1:   H2=php
               A=b
h2 direct:     H2=php
               A=b
```

No decode warning. The INI cycle restores the handler per request; no cross-request stale
serializer was observed.

### Per-directory serializer mismatch plus OOM abort

Setup: mod_php prefork, one worker, two directories; `/a/` overrides
`session.serialize_handler=php_serialize`, `/b/` keeps the global `php`. `abort.php` calls
`session_start()` and then exhausts `memory_limit`; `check.php` calls `session_start()` and sets
`$_SESSION["k"]="v"`, so the session file format reveals the effective serializer.

| Sequence | File written | Effective serializer |
|---|---|---|
| `/a/check` | `a:1:{s:1:"k";s:1:"v";}` | php_serialize (directory INI) |
| `/b/check` | `k\|s:1:"v";` | php (global INI) |
| abort `/a/` -> `/b/check` | `k\|s:1:"v";` | no stale: next request uses php |
| abort `/b/` -> `/a/check` | `a:1:{s:1:"k";s:1:"v";}` | no stale: next request uses php_serialize |

Identical results on 8.4.26 and 8.4.27. The aborted request itself writes its session with the
directory serializer (`a:0:{}`), so the pointer follows the INI; the shutdown restore returns it
to the global value. `OnUpdateSerializeHandler` is the only writer of the pointer and runs on
both the INI change and the restore, keeping INI and pointer paired. A divergence would require
an allocation failure inside the handler, which performs no limited-heap allocation.

## 7. Static patch diff (8.4.26 -> 8.4.27)

`ext/session/session.c`:

- `php_rinit_session_globals()` adds `PS(in_rfc1867_update) = false;`.
- `php_session_unserialize_init()` / `php_session_serialize_init()` use
  `php_var_unserialize_set_incomplete_classes_only()` when `in_rfc1867_update` is set.
- `php_session_rfc1867_update()` sets the flag around decode/re-encode.
- The rfc1867 callback returns early when `PG(modules_activated)`, with a comment about
  `request_parse_body()`.
- `_SESSION` is cleaned after the upload-progress update.

Not present in 8.4.27:

- a reset of `PS(serializer)`;
- the `!PS(use_only_cookies)` guard on the multipart SID field (PR #22113, open).

Key additions, as they appear in the diff:

```c
PS(in_rfc1867_update) = false;

static void php_session_unserialize_init(php_unserialize_data_t *var_hash)
{
    PHP_VAR_UNSERIALIZE_INIT(*var_hash);
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
}

if (PG(modules_activated)) {
    /* request_parse_body(). Do not run here as it corrupts the session. */
    return retval;
}
```

## 8. Reproduction outline

The exact exploit code is not included. A minimal lab uses official images and public PoCs:

```bash
docker run -d --name lab-vuln -p 127.0.0.1:8080:80 \
  -v "$PWD/php.ini:/usr/local/etc/php/conf.d/zz.ini:ro" \
  -v "$PWD/apache.conf:/etc/apache2/conf-enabled/zz.conf:ro" \
  php:8.4.26-apache
# php.ini: display_errors=On, memory_limit=8M, post_max_size=64M,
#          session.upload_progress.enabled=On
# apache.conf: mpm_prefork with a small worker pool
```

Then use one of the public PoCs listed in `POCS.md` against `127.0.0.1:8080`. For the control,
replace the image with `php:8.4.27-apache` and repeat. Do not run against systems without
authorization.

## 9. Notes

- Results are allocator- and kernel-sensitive; the same public PoC did not reproduce on every
  host tested.
- The official image does not expose internal symbols; a debug build with the same configure
  flags was required for offset calibration.
- The 8.4.27 control used the same request generator and worker model; the absence of aborts and
  over-read is the relevant comparison, not a claim that every possible input is safe.


## 10. E-OOM: FPM stale BG (CVE-2026-109619)

Environment: `phpdebug:8.4.26-fpm` (PHP 8.4.26 source, `-O1 -g3`, `--enable-fpm`), single FPM
worker, nginx, `memory_limit=32M`, `display_errors=On`, `session.upload_progress.enabled=On`.
Full reproduction in `raw/fpm-chain-e-8426.txt`.

Producer: a 28 MB session file (`k|s:29360128:"AAA..."`) makes the read succeed and the decode
OOM inside `php_var_unserialize`. After the request, gdb shows:

```
basic_globals.unserialize.level = 1
basic_globals.unserialize.data = 0x7f7b81a64000   (dangling)
```

Consumer: a POST multipart with `PHP_SESSION_UPLOAD_PROGRESS`, a cookie whose session file
exists, and an endpoint that reads `$_POST`, triggers the upload-progress decode, which reuses
the dangling pointer (the `else` branch of `php_var_unserialize_init`) and crashes in `var_push`:

```
Program received signal SIGSEGV, Segmentation fault.
#0 var_push at var_unserializer.c:133
#1 php_var_unserialize_internal :886
#2 php_var_unserialize :852
#3 ps_srlzr_decode_php at session.c:1135
#4 php_session_decode :279
#5 php_session_initialize :502
#6 php_session_rfc1867_update :3196
#7 php_session_rfc1867_callback :3335
#8 rfc1867_post_handler :973
```

nginx returns 502; the worker stays poisoned and crashes on every later non-empty decode.

Differential:

| Vector | 8.4.26 | 8.4.27 |
|---|---|---|
| Chain E (decode OOM -> stale BG -> consumer) | 502 / UAF | 200, stable |
| Startup OOM with progress field (header bomb) | worker dies (`exit code 70`, 502) | 200 |
| `request_parse_body()` on PUT with multipart | parses and writes the session | parses `$_POST`, no session write |

### Definitive crash mechanism (verified with a watchpoint)

The value written over `used_slots` (`d+0x38`) is not bucket content: it is the allocator's
free-list linkage. The freed 12 KB run (3 pages) is handed to bin 16 (`zend_mm_alloc_pages`
inside `zend_mm_alloc_small_slow`), and the free-list construction stores an encoded pointer
(`mov %rax,%rdx ; bswap %rdx`, `zend_mm_alloc_small_slow+242`) over the first 8 bytes of the
area. `var_push` reads that value as `used_slots` and writes `rval` at `d + 0x48 + enc*8`
(unmapped, fixed per worker generation) -> SIGSEGV -> 502. An earlier reading that attributed
the watchpoint value to HashTable bucket content was wrong and is retracted. The residual
`var_dtor_entries` block is bounded (`used_slots=1`, writes stay inside the block), so the
residual block alone adds no write primitive in this configuration. The controlled variant below
uses an attacker-owned fake `var_dtor_entries` in the reclaimed buffer instead. Raw:
`raw/fpm-chain-e-encoding-8426.txt`.

### 8.5 backtraces arm (symbol build)

`phpdebug:8.5.11-fpm` with symbols; OOM trigger with `fatal_error_backtraces=1`. The
`EG(last_fatal_error_backtrace)` zval is UNDEF before the fetch and a valid `IS_ARRAY_EX`
array (type `0x307`, valid HashTable) afterwards; the `Z_ISUNDEF` guard in the error formatter
prevents reading the residual value field. The fetch completes on the already-reserved chunk
memory even during the OOM. Sweeps (128 requests at 64-byte granularity plus 120 fatals per
version): no anomalies, no crashes, persistent worker pid. Not reproducible as a memory-safety
issue in 8.5.11 with these triggers. Raw: `raw/backtraces-8511-gdb.txt`.

### Fixed branches verification (mod_php prefork, OOM/RCE harness)

The same harness, container configuration and 9bie chain used for the vulnerable control were
run against the four fixed branches. Control rerun in the same session: `php:8.4.26-apache`
3/3 PROOF `uid=33(www-data)` (stages 1-2-3). Fixed: `php:8.4.27-apache` 0/3,
`php:8.5.12-apache` 0/3, `php:8.3.36-apache` 0/3, `php:8.2.35-apache` 0/3; every failure stopped
at stage 1 (heap leak), i.e. the OOM abort/state corruption does not occur. Raw:
`raw/fixed-branches-verify.txt`.

### OPcache arm

Official `php:8.4.26-fpm`/`php:8.4.27-fpm` with opcache and `memory_limit=32M`; compile-OOM
trigger (60000-assignment file). 8.4.26 hard-fails the compile on every request and never
caches; 8.4.27 completes the compile via the deferred-OOM framework and caches a valid entry
that executes correctly (including in other workers). `wasted_memory=0`, no partial entries,
no crashes in either version. No reproducible SHM corruption; the measured differential is
tolerance, not corruption. Raw: `raw/opcache-differential-8426-8427.txt`.

RCE in FPM was not reached with the residual-block mechanism alone. The E-OOM reproduction
with the allocator-encoding mechanism and no content lever over `used_slots` is a deterministic
DoS (502).

### Controlled write and command execution (ub_write)

A separate configuration controls the content of the walk. The 24-byte planted session
`C|i:<V>;AAAA` fixes the layout and the multipart field buffer (12300 bytes) reclaims the
dangling `php_unserialize_data`, so the attacker supplies both the fake struct and its fake
`var_dtor_entries`: `last_dtor` points into the buffer and a negative `used_slots`
(N = (T2 - d - 0x110)/16 = -2932019265844) wraps the walk to a chosen 16-aligned address. The
destructor step writes `{value, IS_LONG}` there, 16 bytes.

With T2 = `&sapi_module.ub_write` (0x555556ae2dd0, mod 16 = 0), value = `&system`
(0x7ffff7070090), the sink becomes the output writer: each output chunk is passed as the
command string (rdi = chunk, rsi ignored). The chunk from the script echo delivered
`read=foo;id>/tmp/pwned`, the shell ran the assignment and the redirect, and `/tmp/pwned`
contained `uid=33(www-data)`. The prior warnings and headers are the first eight benign system
calls; the echo chunk is the ninth. The `system` return value (child status) breaks the output
layer, so nginx returns 502 after the command already ran.

Watchpoint on the write (`WATCH_ub_write: val=0x7ffff7070090`), the nine `system` calls with
their arguments, and the `id` output: `raw/fpm-rce-ub-write.txt` (full run log). The session
layout is exact: `C|i:<V>;AAAA` works; `hello|i:<V>;` (also 24 bytes) corrupts the layout
before the write (SEGV in `tmp_var` without hitting the watchpoint).

Prerequisites measured in the lab: ASLR off, a locally planted session file, and a symbol build
for address calibration. The remote ASLR-on variant was not demonstrated.

## 11. Phase 2: `PS(id)` vs Session HashTable (in-band channel audit)

Measurements taken with the live GDB probe (`php_session_reset_id`,
`php_session_track_init`) on the reference debug build of 8.4.26. `leak bytes`
counts bytes outside `[A-Za-z0-9,-]` in the decoded `Set-Cookie` value; `ptrs`
counts 8-byte values in the `0x7f...` range inside it.

| Label | Config | A resp | B resp | `id` page | `ht` page | Delta | leak bytes | ptrs |
|---|---|---|---|---|---|---|---|---|
| `base128` | 128M / 8M | 259 (clean 200) | 259 | `0x78000` | `0x571c0` | -134720 | 0 | 0 |
| `sid31_128` | 128M / 8M, sid_length 31 | 258 | 258 | `0x571c0` | `0x571f8` | +56 | 0 | 0 |
| `drain65_128` | 128M / 8M | 259 | 259 | `0x7e000` | `0x7ce38` | -4552 | 0 | 0 |
| `base_off` | 8M override, Off | 211 (OOM abort) | 5469 | `0x1fe000` | `0x571c0` | +8753600 | 621 | 47 |
| `drain65` | 8M, Off | 211 | 6909 | `0x1fe000` | `0x7ce38` | +8908344 | 841 | 47 |
| `pd_dummy` | 8M, Off, userland destructor | 211 | 10227 | `0x1fe000` | `0x571c0` | +4559296 | 3000 (all NUL) | 0 |
| `base_on` | 8M, `display_errors=On` | 364 | 6041 | `0x1fe000` | `0x571c0` | +8753600 | 663 | 47 |

Findings:

1. **The HashTable is never in the forward window.** Under 8M it lands in the
   main chunk, 4.5-10.2 MB away, or (with `sid_length=31`) 168 B *before* the
   id. Under the 128M defaults no stale id exists at all: A returns a clean 200.
2. **The forged cookie does disclose heap memory.** It over-reads past the
   forged filler region and returns 47 pointer-like values at 64-byte intervals
   from offset 1000, all inside the id's 2 MiB chunk. A gdb follow-up
   (`identify_leak.gdb`) identified them as the Zend MM **bin-64 free-list
   links**, carved out of a previous request's freed 4000-byte field buffer:
   each 64-byte chunk starts with the next link and keeps the attacker's fill
   byte in the rest. No live object, session data or code pointer is disclosed;
   the chunk base is recoverable by masking.
3. **libphp is narrowed, not pinned.** Across 20 ASLR-on runs the
   chunk-base-to-libphp distance ranged from `0x289bc00` to `0x2a7dc00`
   (1.88 MB) with the low 12 bits constant (`delta % 0x1000 == 0xc00`): the
   page offset is fixed and only the page index (~481 pages) is unknown. The
   disclosure does not deterministically defeat ASLR for code pointers.
4. **`pd_dummy` shows the contrast.** Its destructor test overwrites the
   over-read region with zeros: 3000 NUL bytes and no pointers.

An earlier revision of this document said the channel leaked zero bytes. That
was true only of the `pd_dummy` replication and was generalised by mistake; the
counts above were recomputed from every stored `*.b.resp`.

