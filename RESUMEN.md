# php2shell: resumen en español

**CVE-2026-109618 / CVE-2026-109619** — investigación independiente, 2026-10-22 (actualizado
2026-10-23, v1.6).
Preparado por **JoshRob**. Análisis asistido por múltiples modelos de IA y subagentes bajo
dirección humana; cada hallazgo se validó contra comandos, salidas o fuentes públicas. Ver
`METHODOLOGY.md`.

Este repositorio documenta la verificación y el análisis de las vulnerabilidades de PHP
conocidas como **php2shell**. No contiene datos de infraestructura, hosts, credenciales ni
entornos privados.

## Hallazgos

- Dos CVEs agrupadas por una causa raíz: corrupción de estado en el arranque de la petición por
  OOM y bailout sin unwind completo.
- **CVE-2026-109618**: corrupción de estado por bailout durante el request startup.
- **CVE-2026-109619**: OOM en el decode de sesión y estado global stale.
- Los bugs de OOM/estado son pre-autenticación: ocurren antes del código PHP de la aplicación.
- En `mod_php` prefork con `session.upload_progress` habilitado y cuerpos multipart grandes, un
  atacante remoto puede abortar workers, acoplar un worker corrupto con una petición posterior,
  filtrar memoria y, en las condiciones medidas, ejecutar código como el usuario web.
- El parche 8.4.27 (y 8.3.36, 8.2.35, 8.5.12) corrige la clase OOM/estado. No corrige todas las
  cadenas request-level A/C/E que agrupan las PoCs públicas.

## Alcance de la prueba y reproducibilidad

La prueba de RCE se hizo sobre la imagen oficial `php:8.4.26-apache`. Se usó un despliegue de
prueba **Nextcloud 33.0.x con PHP 8.4.21 y `mod_php` prefork** para validar la configuración y
la versión expuestas; el RCE no se ejecutó contra ese despliegue. El bug está en el arranque de
la petición de PHP, no en el código de Nextcloud.

La explotabilidad no es universal: depende del SAPI (`mod_php` prefork vs PHP-FPM), cantidad de
workers, `session.upload_progress`, `memory_limit`/`post_max_size`, ASLR, geometría del
allocator y del kernel, flags de build y del proxy/WAF. Nota medida: `post_max_size` solo aplica
a cuerpos con `Content-Length`; en `mod_php` sin parchear (8.2.34/8.3.35/8.4.26) un multipart
chunked de ~64 MB+ agota el `memory_limit` default (128M) en request startup, mientras que
8.4.27/8.5.12 rechazan el cuerpo chunked por encima del limite y FPM no parsea chunked
(`EVIDENCE.md` seccion 12).
Otras aplicaciones PHP con la misma
configuración se esperan afectadas, pero no se probaron. No es correcto afirmar que cualquier
instancia de PHP sea explotable con la misma PoC.

## Resultados medidos

| Prueba | Resultado |
|---|---|
| 8.4.26, `display_errors=On`, ASLR on | RCE 3/3, `uid=33` |
| 8.4.26, `display_errors=Off`, ASLR off | RCE 3/3, `uid=33` |
| 8.4.26, `display_errors=Off`, ASLR on | Cookie de 4000 B dependiente del estado; sin lectura de la tabla de sesion; se divulgan punteros de heap (ver `EVIDENCE.md` seccion 11) |
| Filtracion de cookie en FPM | Sin canal: A mata al worker (`child ... exited with code 70`, 502) |
| Combinacion leak + E-OOM en `mod_php` | Mutuamente excluyentes: A limpia el estado `BG(unserialize)` que E necesita; ruta cerrada |
| `post_max_size` vs cuerpos chunked | Sin enforcement en 8.2.34/8.3.35/8.4.26 mod_php (chunked 30M parsea completo; chunked 70M OOM en startup con defaults); 8.4.27/8.5.12 lo rechazan; FPM no parsea chunked (sin `CONTENT_LENGTH`); nginx cap aplica (413) |
| Chain D (EG stale tras OOM) | OOM reproducido; `EG(objects_store)` identico antes/despues del OOM en `php_request_shutdown`; sin crash stale-EG; paso RCE no reproducido |
| 8.4.27 control | 0/5, sin abortos ni over-read |
| A/C/E en 8.4.26 / 8.4.27 / 8.5.12 | RCE con la configuración del lab |
| A con `use_only_cookies=1`, `strict=0`, SID solo en multipart | RCE en las tres versiones |
| A con `strict=1` | Bloqueado en el caso medido |
| `PS(serializer)` entre requests, FPM y `mod_php` | Sin handler stale |
| E-OOM (FPM BG stale) en 8.4.26 | DoS determinista (SIGSEGV en `var_push`, 502) en la configuración por defecto; con el struct reclamado por el buffer del campo multipart (sesión plantada de 24 B), escritura controlada de 16 B en `sapi_module.ub_write` = `&system` y ejecución de comando en el lab (ASLR off, sesión plantada); 8.4.27 estable |

## Impacto

- RCE como usuario web, antes de la autenticación de la aplicación, en la configuración
  `mod_php` prefork probada.
- Divulgación de memoria del worker (credenciales, tokens, claves) por la cookie `PHPSESSID`.
- Denial of service por abortos de workers y OOM repetidos.
- La severidad depende del despliegue: P1 si el endpoint PHP es alcanzable sin autenticación;
  P2 si un forward-auth o gate equivalente es la única barrera.

## Remediación

1. Actualizar a 8.4.27 o a la versión fija de la rama (8.3.36, 8.2.35, 8.5.12).
2. Verificar el parche con el control 8.4.27: sin `zend_mm_heap corrupted` ni abortos.
3. Configurar `session.use_strict_mode=1` y `session.use_only_cookies=1`.
4. Deshabilitar `session.upload_progress` si no se usa; si se usa, mantener `cleanup=On`.
5. Mantener buffering/límites de cuerpo, WAF y rate limiting delante de PHP. En `mod_php`
   sin parchear el bypass chunked esquiva `post_max_size`; el cap de cuerpo del proxy/WAF es
   la barrera de tamaño (nginx `client_max_body_size` aplica a chunked; Apache
   `LimitRequestBody` por defecto no limita). 8.4.27/8.5.12 ya rechazan chunked por encima
   del limite.
6. Eliminar sinks LFI, mismatches de serializer por directorio y gadgets alcanzables.
7. Monitorear OOM, abortos de worker, picos de 500 y `PHPSESSID` anómalos.
8. Por CVE-2026-115560 (advisory informativo del 23-oct, sin fix en las versiones de
   emergencia): `session.upload_progress.enabled=0` hasta el próximo release regular. La
   condición (configurar `session.serialize_handler` en `php_binary`/`php_serialize` y cambiarlo
   a `php` en runtime con `ini_set()` antes de `session_start()`) no se cumple en nuestro
   despliegue.

El parche 8.4.27 no reemplaza los controles de configuración y aplicación para A/C/E. La
explotación en la naturaleza es un hecho: Amazon reporta intentos desde el 17-oct (4 días antes
del parche) y watchTowr observa explotación desde el 21-oct; PHP Foundation no tiene evidencia
de explotación exitosa de las dos CVEs antes de la publicación.

## Límites

- Todo se midió en laboratorio, en loopback, con imágenes oficiales; no se atacó producción.
- El RCE con `display_errors=Off` y ASLR on no se logro. El canal de la cookie filtra heap
  (base del chunk del id, 47 punteros de free-list) pero nunca la tabla de sesion, y acota
  `libphp` a una ventana de 1.51 MB (~387 paginas) sin fijarla. Es de un solo uso por OOM y solo
  existe en `mod_php` (en FPM el OOM mata al worker). En pools fork-based, el layout es heredado
  entre hijos y solo cambia al reiniciar el master. En `mod_php`, el leak y la primitiva de
  `BG(unserialize)` colgante (E-OOM) son mutuamente excluyentes: A limpia el estado que E
  necesita. Ambas vias quedaron probadas y cerradas; otro build o primitiva podria cambiar la
  geometria.
- Los resultados dependen del kernel y del allocator; la misma PoC pública no reproduce en todos
  los hosts.
- La cadena FPM se reprodujo hasta el UAF (crash 502) y se midió su mecánica por defecto (el allocator recicla el run liberado como página de bin 16 y su linkage codificado sobreescribe `used_slots`): DoS determinista. La retractación previa cubría la lectura del bloque residual, no la variante controlada: con el struct reclamado por el buffer del multipart y el fake `var_dtor_entries`, la escritura de 16 B llega a `sapi_module.ub_write` = `&system` y ejecuta un comando. Ese RCE quedó en el lab con prerrequisitos locales (ASLR off, sesión plantada de 24 B, build con símbolos); la variante remota con ASLR on no se demostró.
- Las cadenas A/C/E dependen de LFI, handlers por directorio o escritura local, según el caso.
- En despliegues minimalistas sobre Nginx + PHP-FPM sin código aplicativo vulnerable (evaluado empíricamente en el reto público `stealmybitcoin.com` con PHP 8.4.26), la ruta de aplicación (Cadena A) está bloqueada por arquitectura (`cleanup = 1` y sin gadgets LFI). Sin embargo, la resolución exitosa del reto por `@killa` confirmó la viabilidad de la explotación directa en memoria (Cadena E-OOM / Zend MM): debido a que el master de FPM preserva las direcciones base por `fork()` entre generaciones de workers (0 bits de entropía), la búsqueda en el espacio de 387 páginas (1.51 MB) es finita y determinista.
- No se redistribuye código de exploit de terceros.

Nota: el código de PoC del laboratorio vive en un repositorio privado e invite-only, disponible
bajo pedido al autor; aquí solo hay documentación y enlaces.

## Documentos

- `REPORT.md`: informe técnico completo.
- `METHODOLOGY.md`: laboratorio, alcance, flujo con IA/subagentes y reproducibilidad.
- `POCS.md`: revisión de PoCs públicas y verificación independiente.
- `EVIDENCE.md`: matrices y evidencia sanitizada.
- `REMEDIATION.md`: guía de remediación y detección.
- `COVERAGE.md`: cobertura por CVE, cadena y versión.
- `REFERENCES.md`: fuentes públicas.
