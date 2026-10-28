# Referencias y Fuentes

[English](REFERENCES.md) · [Español](REFERENCES.es.md)

---

## Fuentes Primarias

- Archivo de avisos de seguridad de PHP: https://www.php.net/archive/2026.php#2026-10-21-5
- GHSA-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- GHSA-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- NVD CVE-2026-109618: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-109618
- NVD CVE-2026-109619: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-109619
- Openwall oss-security: https://www.openwall.com/lists/oss-security/2026/10/21/6
- oss-sec, aviso informativo CVE-2026-115560: https://seclists.org/oss-sec/2026/q4/359
- The Register, tercer fallo de PHP2Shell: https://www.theregister.com/security/2026/10/23/theres-a-third-php2shell-bug-but-it-wont-get-an-emergency-fix/
- BleepingComputer, línea temporal de explotación in-the-wild: https://www.bleepingcomputer.com/news/security/amazon-says-php2shell-exploitation-began-4-days-before-patches
- Red Hat RHSB-2026-013: https://access.redhat.com/security/vulnerabilities/RHSB-2026-013
- PHP Foundation Blog: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
- PHP 8.4.27 NEWS: https://github.com/php/php-src/blob/PHP-8.4.27/NEWS
- PR php-src #22113 (abierto): https://github.com/php/php-src/pull/22113

## Informes de la Industria y Análisis

- Wiz: https://www.wiz.io/blog/php2shell-php-rce
- Calif: https://calif.io/php2shell/
- Sansec: https://sansec.io/research/php2shell
- CERT-EU 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018
- NCSC-NL: https://github.com/NCSC-NL/php2shell
- CISA Alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Cloudflare WAF: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/

## PoCs Públicas Analizadas

- 9bie, exploit con bypass de ASLR: https://github.com/9bie/php2shell-bypass-aslr-exp
- ikow, investigación de cinco cadenas: https://github.com/ikow/php2shell-poc
- Anton-Barinov, backports comunitarios para PHP 5.4-8.1: https://github.com/Anton-Barinov/php2shell-patches
- GoldraK, fork y escáner A/C/E: https://github.com/GoldraK/php2shell-poc
- dinosn, RCE asistido en lab: https://github.com/dinosn/php-cve-2026-10961x-lab-poc
- php2shellbt, escáner (falso positivo comprobado): https://github.com/pentestershell/php2shellbt

## Notas

Las PoCs de terceros y material citado permanecen bajo sus respectivas licencias. Este repositorio no redistribuye código ejecutable de las mismas.
