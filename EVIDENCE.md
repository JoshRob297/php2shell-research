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
| `display_errors=Off`, ASLR on | 12 | 12/12 4000-byte cookies; no `libphp` leak; no RCE |
| `display_errors=Off`, ASLR on, RCE attempt | 3 | 0/3; blocked by the leak geometry |
| `php:8.4.27-apache` control | 5 | 0/5; no aborts, no over-read |

The A+B stage with `display_errors=Off` stabilized with a 1.2-2.0 MB warmup: 15/15 4000-byte
cookies (12 with ASLR on, 3 with ASLR off). With ASLR off, the chunk was stable at
`0x7ffff4200000`; the Off RCE used stage3 chunk `0x7ffff4c00000`, `HTDATA=0x7ffff4c690d8`,
`ZIF=0x7ffff6c70370`.

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
| E: decode failure + destructor, local file planting | RCE `uid=33` | RCE `uid=33` | RCE `uid=33` |

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
