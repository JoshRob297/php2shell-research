# php2shell: Informe Técnico Exhaustivo

[English](REPORT.md) · [Español](REPORT.es.md)

---

**CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560**

Versión 1.7.0, 2026-10-27. Elaborado por **JoshRob**. Investigación de seguridad independiente. Sin nombres de host, direcciones IP privadas, credenciales ni datos de clientes.

---

## 1. Resumen Ejecutivo

`php2shell` comprende un conjunto de vulnerabilidades críticas en el inicio de petición (`request startup`) de PHP. Los identificadores CVE asignados cubren corrupciones de estado causadas por condiciones de falta de memoria (OOM) y flujos de desenrollado (`bailout`) incompletos:

- **CVE-2026-109618** — Corrupción de estado por aborto OOM durante el inicio de la petición.
- **CVE-2026-109619** — OOM durante la decodificación de sesión seguido de estado global colgante y UAF.
- **CVE-2026-115560** — Desincronización de serializadores mediante reentrada en runtime con `ini_set()`.

Los fallos de corrupción de estado por OOM son pre-autenticación: ocurren antes de que el código aplicativo de PHP se ejecute. En un despliegue vulnerable con Apache `mod_php` prefork o servidor CLI persistente (`php -S`) con `session.upload_progress` activo, un atacante remoto puede forzar la caída de workers, emparejar peticiones con el worker envenenado, fugar memoria del proceso y ejecutar código arbitrario como el usuario del servidor web (`uid=33(www-data)`).

PHP 8.4.27 (junto con 8.3.36, 8.2.35 y 8.5.12) contiene la solución oficial del fabricante para la clase de corrupción OOM. El parche es necesario pero no neutraliza cadenas a nivel aplicativo (A/C/E) que dependan de LFI o gadgets independientes.

---

## 2. Línea Temporal de Divulgación

| Fecha (UTC) | Hito Relevante |
|---|---|
| 2026-08-11 | Primeros reportes sobre la clase de vulnerabilidad |
| 2026-09-21 | PHP inicia el desarrollo coordinado del parche |
| 2026-10-20 15:00 | Filtración de CVEs con puntuación incorrecta de CVSS 10.0 |
| 2026-10-20 19:30 | PHP adelanta la fecha de publicación al 2026-10-21 |
| 2026-10-21 07:43 | Primer tráfico de ataque observado en internet |
| 2026-10-21 14:00 | Publicación oficial coordinada: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| 2026-10-22 | Reproducción independiente en laboratorio y verificación de parches (este informe) |
| 2026-10-22 | Amazon Threat Intelligence reporta ataques in-the-wild desde el 17 de octubre |
| 2026-10-23 | Publicación del aviso informativo para CVE-2026-115560 |
| 2026-10-26 | Auditoría post-mortem del reto StealMyBitcoin (Cadena D confirmada en servidores CLI) |
| 2026-10-27 | Calibración empírica en imágenes oficiales `php:8.4.26-fpm` (Debian 13) y cierre de FastCGI |

---

## 3. Versiones Afectadas y Corregidas

| Versión | CVEs de OOM / Corrupción de Estado | Cadenas Aplicativas A/C/E |
|---|---|---|
| 8.4.21 | Vulnerable por versión; no explotado | Dependiente de prerrequisitos |
| 8.4.26 | Vulnerable (RCE en laboratorio comprobado) | RCE con prerrequisitos de lab |
| 8.4.27 | Corregido oficialmente por el fabricante | Operativas si existen fallos en la app |
| 8.5.12 | Corregido (0/3 en laboratorio; bloqueado en leak) | Operativas si existen fallos en la app |
| 8.3.36 / 8.2.35 | Corregido (0/3 en laboratorio) | No probado directamente |

---

## 4. Análisis de Causa Raíz e Internals del Motor

### 4.1 Ciclo de Vida de Petición y Manejo RFC 1867
Durante `php_request_startup()`, si la petición HTTP incluye cabeceras `multipart/form-data`, el manejador `rfc1867_post_handler()` procesa los campos antes del enrutamiento. Si `session.upload_progress.enabled = 1` y se detecta la clave de progreso, PHP inicializa la sesión en memoria viva de forma anticipada.

### 4.2 Mecánica del OOM y Desenrollado Incompleto
Si el cuerpo supera el límite disponible de memoria, el motor dispara `zend_error(E_ERROR, ...)` que deriva en `zend_bailout()` (`longjmp`). Debido a que las estructuras de sesión estaban a medio inicializar, ciertas variables globales no son limpiadas:
- En `mod_php`: El proceso worker de Apache sobrevive y atiende la siguiente petición con memoria residual corrupta.
- En `PHP-FPM`: El proceso worker aborta con código 70 (`exit 70`) y Nginx devuelve HTTP 502, destruyendo el estado del heap.

### 4.3 Primitiva E-OOM en PHP-FPM y Sobreescritura de `sapi_module.ub_write`
En PHP-FPM, si la decodificación de sesión aborta por OOM, `BG(unserialize)` retiene un puntero colgante (`level = 1`). En peticiones subsiguientes:
1. Un buffer multipart calibrado de 12.300 bytes reclama la memoria liberada.
2. Un campo `used_slots` negativo forzado transforma la liberación de destructores en una escritura arbitraria de 16 bytes: `*(T2) = { &system, IS_LONG }`.
3. Al apuntar `T2 = &sapi_module.ub_write`, cualquier salida generada por el script o el motor es enviada a `system()`.
4. **Límite de ASLR:** La técnica requiere conocer con exactitud la base de memoria. En entornos con ASLR activo, la dispersión de páginas de Zend MM bin-16 fragmenta la colocación del buffer y FastCGI no filtra punteros, degradando la vulnerabilidad a **Denegación de Servicio determinista (P3)**.
