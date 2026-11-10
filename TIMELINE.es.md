# Cronología de la divulgación (UTC)

Compilada de fuentes públicas, con nuestros eventos de laboratorio marcados como tales. El
objetivo es que el orden sea verificable: varias afirmaciones en circulación solo tienen sentido
contra esta línea de tiempo.

| Fecha/hora | Evento | Fuente |
|---|---|---|
| 2026-08-11 | Calif reporta el primer bug; OpenAI el mismo día por la misma causa raíz | PHP Foundation |
| 2026-08-24 | Wiz reporta sus hallazgos | Wiz |
| 2026-09-21 | PHP reconoce los reportes y empieza el fix coordinado | Wiz |
| 2026-10-20 15:00 | Filtración de los IDs de CVE con hora y CVSS 10.0 incorrectos | PHP Foundation |
| 2026-10-20 19:30 | PHP adelanta el pre-aviso y mueve el release del 22 al 21 | php.net archive |
| 2026-10-21 03:02 | Cloudflare publica reglas WAF preventivas | Cloudflare |
| 2026-10-21 07:41 | Chainguard publica imágenes con el fix, antes del release | PHP Foundation |
| 2026-10-21 07:43 | Cloudflare reporta los primeros ataques | Sansec / Cloudflare |
| 2026-10-21 11:35 | Hadrian reporta explotación "a escala" vía upload progress | Brandefense |
| 2026-10-21 14:00 | Release coordinado: 8.2.35, 8.3.36, 8.4.27, 8.5.12 | php.net |
| 2026-10-21 14:17 | NVD registra ambas CVE | NVD |
| 2026-10-21 19:36 | **Nuestro Nextcloud se remedia a 8.4.27** | este proyecto |
| 2026-10-21 20:30 | Huntress: sin explotación en su base de socios | Brandefense |
| 2026-10-21 21:03 | KEV de CISA sigue sin listar ninguna de las dos | CISA |
| 2026-10-22 | **Lab:** RCE 3/3 en `php:8.4.26-apache`, `display_errors=On`, ASLR encendido | este proyecto |
| 2026-10-22 | **Lab:** RCE 3/3 con `display_errors=Off` y ASLR apagado | este proyecto |
| 2026-10-22 | Amazon Threat Intelligence: primeros intentos el 17-oct, cuatro días antes del parche, desde redes de anonimización | BleepingComputer |
| 2026-10-22 | **Lab:** la cookie forjada filtra heap y acota `libphp` a una ventana de 1.88 MB; la HashTable de sesión queda fuera de alcance | este proyecto |
| 2026-10-22 | **Lab, FPM:** cadena E reproducida (UAF cross-request de `BG(unserialize)`, 502 determinista); 8.4.27 la cierra | este proyecto |
| 2026-10-22 | **Lab, FPM:** escritura de 16 B y RIP en `zend_error_cb = &system` confirmados; faltaba el argumento | este proyecto |
| 2026-10-23 | **Lab, FPM:** RCE completa — `sapi_module.ub_write = &system` ejecuta `id` como www-data, con ASLR apagado y sesión plantada de 24 B | este proyecto |
| 2026-10-23 | PHP publica advisory informativo de un tercer issue, **CVE-2026-115560**; sin fix en las versiones de emergencia, mitigación `session.upload_progress.enabled=0` | php.net / oss-sec |
| 2026-10-24 | **Lab:** el leak de cookie no existe en FPM (A mata al worker, exit 70); en `mod_php` el leak y la primitiva de `BG(unserialize)` colgante son mutuamente excluyentes — la ruta Off + ASLR on queda cerrada por ambas vías | este proyecto |
| 2026-10-24 | **Lab:** bypass de `post_max_size` con chunked confirmado (claim de chain D de ikow): chunked 30 MB parsea completo, chunked 70 MB hace OOM en request startup con 128M/8M | este proyecto |
| 2026-11-09 | La última estable sigue siendo 8.4.27 / 8.5.12; 8.4.28 y 8.5.13 son solo RC1; CVE-2026-115560 sigue sin fix estable | php.net, php-src |

## Notas

- El release estaba previsto para el 22-oct y se adelantó por la filtración.
- Chainguard publicó el fix en imágenes seis horas antes del release: hubo diff binario
  disponible mientras los demás esperaban. Eso explica intentos de explotación sin una PoC
  pública validada.
- CVSS: 9.2 v4.0 (AC:H, AT:P) del vendor, 9.8 v3.1 (AC:L) de NVD. No es contradicción — v3.1 no
  puede expresar los "attack requirements".
