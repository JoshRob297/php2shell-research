# References

## Primary

- PHP advisory archive: https://www.php.net/archive/2026.php#2026-10-21-5
- GHSA-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- GHSA-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- NVD CVE-2026-109618: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-109618
- NVD CVE-2026-109619: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-109619
- Openwall: https://www.openwall.com/lists/oss-security/2026/10/21/6
- PHP Foundation: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
- PHP 8.4.27 NEWS: https://github.com/php/php-src/blob/PHP-8.4.27/NEWS
- PR php-src #22113 (open): https://github.com/php/php-src/pull/22113
- PR php-src #22113 diff: https://github.com/php/php-src/pull/22113.diff

## Analysis and reporting

- Wiz: https://www.wiz.io/blog/php2shell-php-rce
- Calif: https://calif.io/php2shell/
- Joint site: https://www.php2shell.com/
- Sansec: https://sansec.io/research/php2shell
- CERT-EU 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018
- NCSC-NL: https://github.com/NCSC-NL/php2shell
- CISA: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Cloudflare: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
- Additional reporting: Tenable, Brandefense, watchTowr, Sophos, Abstract, Aikido, Huntress
  (timelines and exploitation status; URLs omitted to avoid stale links)

## Public PoCs

- 9bie, ASLR-bypass exploit: https://github.com/9bie/php2shell-bypass-aslr-exp
- ikow, five-chain research: https://github.com/ikow/php2shell-poc
- GoldraK, A/C/E fork and scanner: https://github.com/GoldraK/php2shell-poc
- dinosn, lab-assisted: https://github.com/dinosn/php-cve-2026-10961x-lab-poc
- php2shellbt, scanner (false positive): https://github.com/pentestershell/php2shellbt
- eness, placeholder: https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC

## Platform and configuration

- PHP session security: https://www.php.net/manual/en/session.security.ini.php
- PHP session configuration: https://www.php.net/manual/en/session.configuration.php
- phpredis 6.3.0 session handler (`PS_VALIDATE_SID_FUNC`):
  https://github.com/phpredis/phpredis/blob/6.3.0/redis_session.c
- Apache `mod_php`: https://httpd.apache.org/docs/2.4/mod/mod_php.html
- nginx request buffering: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering

## Notes

Third-party PoCs and quoted material remain under their own licenses. This repository does not
redistribute their exploit code.
