# Remediation

[English](REMEDIATION.md) · [Español](REMEDIATION.es.md)

---

This document describes solutions to the vulnerability. It is not a deployment checklist for a
specific environment.

## 1. Patch

Upgrade to a fixed PHP release:

| Branch | Fixed release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

The vendor fix addresses the OOM/state-corruption class (CVE-2026-109618 / CVE-2026-109619).
It does **not** fix every request-level chain that public PoCs group under php2shell; see
section 3.

### Verify the patch

```bash
php -v
php -i | grep -E 'memory_limit|post_max_size|session.upload_progress'
```

For a source build, confirm that `ext/session/session.c` contains the 8.4.27 changes:

- early reset of request globals;
- `PS(in_rfc1867_update)` and `php_session_unserialize_init()` with incomplete classes only;
- the `PG(modules_activated)` guard in the rfc1867 callback;
- `_SESSION` cleanup after the upload-progress update.

Run the 8.4.27 control from `EVIDENCE.md`: the same request generator that aborts 8.4.26 should
produce no `zend_mm_heap corrupted` and no `exit signal Abort` on 8.4.27.

## 2. Configuration hardening

The patch is the primary control. The following reduce exposure and cover the request-level
chains.

| Control | What it addresses | Notes |
|---|---|---|
| `session.use_strict_mode=1` | Rejects uninitialized session IDs; blocks the fixed-SID variant of chain A in our tests | Compatible with file and Redis session handlers; test login flows after enabling |
| `session.use_only_cookies=1` | Prevents URL/POST session IDs in normal session startup | Not sufficient alone for upload progress; PR #22113 is the missing guard |
| `session.upload_progress.enabled=0` | Removes the upload-progress session write primitive | Only if the application does not need upload progress |
| `session.upload_progress.cleanup=On` | Removes progress data at request end; reduces the A window | The default; a slow-upload race was not reproduced in 2 attempts, but this is not a formal guarantee |
| Request-body limits / buffering | Makes OOM pairing harder; buffering proxies block the multi-worker pairing path | Balance against legitimate large uploads |
| WAF / reverse-proxy rules | Blocks known multipart patterns and large abusive bodies | Defense in depth; not a substitute for patching |
| Rate limiting and worker isolation | Raises the cost of worker saturation and pairing | Useful for the OOM chain |

Relevant configuration:

```ini
session.use_strict_mode = 1
session.use_only_cookies = 1
session.upload_progress.enabled = 0   ; if upload progress is not required
; or, if required:
; session.upload_progress.enabled = 1
; session.upload_progress.cleanup = 1
```

`session.use_strict_mode=1` is supported by the current phpredis session handler
(`PS_VALIDATE_SID_FUNC` uses `EXISTS`). Verify the login flow, WebDAV and any custom session
handler after enabling it.

## 3. Application-level controls

The request-level chains depend on application conditions:

- **A** requires an LFI sink. Remove file-include sinks that accept user-controlled paths, or
  restrict them with an allowlist.
- **C** requires a per-directory `session.serialize_handler` mismatch and a gadget class. Use
  one serializer across the application and avoid magic methods on untrusted session data.
- **E** requires a local session-file write in the harness; do not treat it as a remote chain
  without a separate write primitive.
- Do not deserialize untrusted session data with a handler different from the one that wrote it.
- Keep authentication and routing in front of PHP where possible; the OOM chain runs before
  application code.

## 4. Detection

Cheap signals:

- `zend_mm_heap corrupted` in web-server logs;
- `child pid ... exit signal Abort (6)`;
- spikes in 500/502 responses and worker restarts;
- anomalous `PHPSESSID` values, especially very large cookies;
- large multipart requests or unusually slow uploads;
- OOM messages around request startup.

If exploitation is suspected, treat the web user as compromised: rotate application secrets and
session tokens, inspect mounted data for writes, review outbound connections, and preserve logs.

## 5. Response plan

1. Identify every PHP deployment exposed to untrusted request bodies.
2. Patch to the fixed release for its branch.
3. Verify the patch with the control test.
4. Apply `session.use_strict_mode=1` and `session.use_only_cookies=1`.
5. Disable upload progress if unused; otherwise keep `cleanup=On` and add body limits.
6. Put buffering/WAF/rate limits in front of PHP where the architecture allows it.
7. Remove LFI sinks, per-directory serializer mismatches and gadget classes from reachable code.
8. Monitor the detection signals for at least one exposure cycle.
9. If compromise is suspected, follow the incident-response steps in section 4.

## 6. What not to rely on

- A CVE scanner verdict without version/SAPI/config context.
- `session.use_only_cookies=1` alone for chain A.
- `display_errors=Off` as a security control.
- ASLR alone; the public PoC bypasses it in some builds, and the Off+ASLR-on case is
  geometry-dependent rather than a guarantee.
- WAF rules alone; the bug is pre-authentication and the payload space is broad.
- A public exploit that works on one host as proof for another build.

## 7. Verification summary

After patching and hardening, the expected results are:

- 8.4.27 control: no aborts, no over-read.
- A with `strict=1`: no session file under the chosen SID; no RCE.
- `upload_progress.enabled=0`: A is not applicable.
- `PS(serializer)`: no cross-request stale handler.
- C and E: still require application/local conditions; do not treat their absence in a scanner
  as proof that the OOM patch is effective, or their presence as proof that it failed.

See `EVIDENCE.md` for the measurements behind these statements.

## 8. Triage: is the OOM primitive reachable at all?

Most public scanners answer "is this PHP version patched?". The more useful
first question for a SOC is whether the OOM-driven chains can start on the
observed configuration. They cannot without reaching `memory_limit` inside
request startup.

Decision order:

1. **Version.** `php -v`. At or above 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12: the
   vendor class is fixed. Stop for the OOM chains; continue only if you are
   validating request-level chains (section 3).
2. **`session.upload_progress.enabled`.** If `Off`, the primary vector for the
   OOM chains is not reachable. Continue for inventory, not for scanning.
3. **Resource limits.** Run `tooling/oom_reach.py` with the effective values:

   ```bash
   php -i | grep -E 'memory_limit|post_max_size|upload_max_filesize'
   python3 tooling/oom_reach.py -m 128M -p 8M
   ```

   With stock defaults the verdict for `Content-Length` bodies is
   `UNREACHABLE`: the largest body a client can submit with a declared length
   is bounded by `post_max_size` (8 MiB) and the resulting request footprint
   (~17 MiB) is far below `memory_limit` (128 MiB). **Chunked bodies are not
   bounded by `post_max_size` on unpatched `mod_php`** (measured, `EVIDENCE.md`
   section 12): a chunked ~64 MB+ multipart reaches the OOM at stock defaults on
   8.2.34/8.3.35/8.4.26. The 8.4.27/8.5.12 patch rejects chunked bodies over the
   limit, and PHP-FPM does not parse chunked bodies. A triage report should say
   whether the host is patched, whether the body arrived chunked, and whether a
   front-end proxy/WAF capped it (nginx `client_max_body_size` applies to
   chunked; Apache `LimitRequestBody` defaults to unlimited).
4. **Leak channel.** `display_errors=Off` removes the `libphp` address leak.
   With ASLR on and no in-band leak, the measured outcome is a worker abort
   (DoS), not RCE; see `validation/` for the geometry.
5. **Detection.** If the configuration is reachable and you still must test,
   prefer passive detection first: `detection/php2shell-refined.rules` flags the
   forged-cookie artifact and abort bursts without sending a destructive probe.

What this triage does **not** say: that a host with defaults is safe from every
php2shell-labelled chain. Request-level chains that do not require an OOM
(section 3) depend on application code and local conditions; assess them
separately.

---

## 9. Drop-In Hardening & Detection Snippets

For immediate defense in production, apply the following configurations at the respective layers:

### A. PHP Engine Hardening (`/etc/php/*/conf.d/99-php2shell-hardening.ini`)

```ini
; Disable upload progress tracking if real-time upload meters are unused
session.upload_progress.enabled = Off

; Enforce strict session handling (mitigates arbitrary SID planting via Chain A)
session.use_strict_mode = 1

; Ensure immediate unlinking of completed progress descriptors
session.upload_progress.cleanup = On

; Disable in-band address leaking via PHP errors
display_errors = Off
display_startup_errors = Off
```

### B. Nginx Reverse Proxy Protection (`/etc/nginx/conf.d/php2shell-guard.conf`)

```nginx
# 1. Enforce strict request body caps to prevent chunked/streaming OOM amplification
client_max_body_size 8M;

# 2. Block abnormally large Cookie headers (forged Zend MM cookie channel ~4000 bytes)
large_client_header_buffers 4 8k;

# 3. Drop multipart requests attempting to force arbitrary upload progress markers
location ~ \.php$ {
    # If using Coraza / ModSecurity WAF module:
    # SecRule ARGS:PHP_SESSION_UPLOAD_PROGRESS "@rx [^a-zA-Z0-9_\-]" "id:1096181,phase:2,deny,status:400"

    fastcgi_pass unix:/run/php/php-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

### C. ModSecurity / OWASP CRS WAF Rule (`php2shell-crs.conf`)

```apache
# 1. Block multipart parameter manipulation targeting PHP upload progress buffer with oversized cookies
SecRule REQUEST_METHOD "@streq POST" \
    "id:202610961,phase:2,deny,status:403,log,msg:'Potential PHP2SHELL Request-Startup Exploit Attempt (Large Cookie)',\
    chain"
    SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
        "chain"
        SecRule REQUEST_HEADERS:Cookie "@rx (?:PHPSESSID=.{128,})"

# 2. Block deeply nested multipart array inflation (KillaBoi Chain D memory exhaustion pattern)
SecRule REQUEST_METHOD "@streq POST" \
    "id:202610962,phase:2,deny,status:400,log,msg:'Potential PHP2SHELL Nested Array Memory Exhaustion',\
    chain"
    SecRule REQUEST_HEADERS:Content-Type "@rx (?i)multipart/form-data" \
        "chain"
        SecRule ARGS_NAMES "@rx (?:\[[^\]]*\]){10,}"
```

### D. Architectural Hardening: Prohibition of Built-in CLI Server (`php -S`) in Production

The `stealmybitcoin.com` challenge fell because it ran `php -S 0.0.0.0:8000` with `PHP_CLI_SERVER_WORKERS=4` behind Nginx instead of a true isolated FastCGI daemon.
- **Never expose `php -S` to production traffic:** The built-in CLI server is strictly single-tenant development software; it does not isolate workers upon unhandled runtime exceptions or OOM bailouts.
- **Always use modern PHP-FPM or Apache with proper process isolation.**

### E. Log Monitoring / SIEM Query (Detecting Worker Aborts and Memory Exhaustion)

In PHP-FPM, unhandled allocator bailouts or OOMs trigger exit code 70:

```bash
# Grep for worker exit 70 crashes in PHP-FPM master logs
grep -E "child [0-9]+ exited with code 70" /var/log/php*-fpm.log

# Systemd journal filter for FPM worker aborts
journalctl -u php-fpm -g "exited with code 70"

# Detect PHP memory exhaustion fatal errors across web server logs
grep -E "Allowed memory size of [0-9]+ bytes exhausted" /var/log/nginx/*error.log /var/log/apache2/*error.log
```


