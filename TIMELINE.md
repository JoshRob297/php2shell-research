# Disclosure timeline (UTC)

[English](TIMELINE.md) · [Español](TIMELINE.es.md)

Compiled from public sources, with our own lab events marked as such. The purpose is to make
the order of events checkable: several claims in circulation only make sense against it.

| Date/time | Event | Source |
|---|---|---|
| 2026-08-11 | Calif reports the first bug; OpenAI reports the same root cause the same day | PHP Foundation |
| 2026-08-24 | Wiz reports its findings | Wiz |
| 2026-09-21 | PHP acknowledges the reports and starts the coordinated fix | Wiz |
| 2026-10-20 15:00 | CVE ids leak with the wrong time and a CVSS 10.0 | PHP Foundation |
| 2026-10-20 19:30 | PHP moves the pre-notice up and the release from the 22nd to the 21st | php.net archive |
| 2026-10-21 03:02 | Cloudflare publishes preventive WAF rules | Cloudflare |
| 2026-10-21 07:41 | Chainguard ships images with the fix, before the release | PHP Foundation |
| 2026-10-21 07:43 | Cloudflare reports the first attacks | Sansec / Cloudflare |
| 2026-10-21 11:35 | Hadrian reports exploitation "at scale" through upload progress | Brandefense |
| 2026-10-21 14:00 | Coordinated release: 8.2.35, 8.3.36, 8.4.27, 8.5.12 | php.net |
| 2026-10-21 14:17 | NVD registers both CVEs | NVD |
| 2026-10-21 19:36 | **Our Nextcloud is remediated to 8.4.27** | this project |
| 2026-10-21 20:30 | Huntress: no exploitation in its partner base | Brandefense |
| 2026-10-21 21:03 | CISA KEV still does not list either CVE | CISA |
| 2026-10-22 | **Lab:** RCE 3/3 on `php:8.4.26-apache`, `display_errors=On`, ASLR on | this project |
| 2026-10-22 | **Lab:** RCE 3/3 with `display_errors=Off` and ASLR off | this project |
| 2026-10-22 | Amazon Threat Intelligence: first exploitation attempts on 17 Oct, four days before the patch, from anonymising networks | BleepingComputer |
| 2026-10-22 | **Lab:** the forged cookie leaks heap and narrows `libphp` to a 1.88 MB window; the session HashTable stays out of reach | this project |
| 2026-10-22 | **Lab, FPM:** chain E reproduced (cross-request `BG(unserialize)` UAF, deterministic 502); 8.4.27 closes it | this project |
| 2026-10-22 | **Lab, FPM:** 16-byte write and RIP at `zend_error_cb = &system` confirmed; the argument was still missing | this project |
| 2026-10-23 | **Lab, FPM:** full RCE — `sapi_module.ub_write = &system` runs `id` as www-data, with ASLR off and a planted 24-byte session | this project |
| 2026-10-23 | PHP publishes an informational advisory for a third issue, **CVE-2026-115560**; no fix in the emergency releases, mitigation `session.upload_progress.enabled=0` | php.net / oss-sec |
| 2026-10-24 | **Lab:** the cookie leak does not exist on FPM (A kills the worker, exit 70); on `mod_php` the leak and the dangling `BG(unserialize)` primitive are mutually exclusive — the Off + ASLR-on route is closed on both paths | this project |
| 2026-10-24 | **Lab:** `post_max_size` bypass with chunked confirmed (ikow's chain D claim): 30 MB chunked parses whole, 70 MB chunked OOMs during request startup at 128M/8M | this project |
| 2026-11-09 | Latest stable is still 8.4.27 / 8.5.12; 8.4.28 and 8.5.13 are RC1 only; CVE-2026-115560 still has no stable fix | php.net, php-src |
| 2026-10-26 | **CISA adds both CVEs to KEV**, federal due date 29 Oct | CISA |
| 2026-10-27 | Press confirms exploitation and the three-day deadline for agencies | The Register |
| 2026-10-28 | KEV adds CVE-2026-46300 (Linux kernel), documented as chainable with this pair to reach root | CISA |

## Notes

- The release was planned for 22 Oct and moved up because of the leak.
- Chainguard shipped the fix in images six hours before the release, so a binary diff was
  available while everyone else waited. That explains exploitation attempts without a validated
  public PoC.
- CVSS: 9.2 v4.0 (AC:H, AT:P) from the vendor, 9.8 v3.1 (AC:L) from NVD. Not a contradiction —
  v3.1 cannot express "attack requirements".
