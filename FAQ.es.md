# Preguntas Frecuentes (FAQ)

[English](FAQ.md) · [Español](FAQ.es.md)

---

## ¿Es suficiente actualizar a PHP 8.4.27?

Para la clase de OOM y corrupción de estado (las dos CVEs principales), sí: 8.4.27 reinicia el estado colgante de forma temprana y nuestras pruebas de control demostraron que no ocurren abortos ni sobrelecturas. No obstante, no es suficiente para las cadenas A/C/E a nivel de aplicación (que requieren controles de configuración propios), ni cubre CVE-2026-115560 (mitigación: `session.upload_progress.enabled=0` hasta el siguiente release regular).

## ¿Detiene `post_max_size` la primitiva de OOM con valores por defecto?

Para cualquier petición con cabecera `Content-Length`, sí. En versiones **sin parche** de `mod_php` (8.2.34, 8.3.35, 8.4.26) un cuerpo multipart chunked no está acotado: 30 MB se procesan enteros y 70 MB provocan OOM en el inicio de la petición con límites estándar (`memory_limit=128M`, `post_max_size=8M`). **8.4.27 y 8.5.12 rechazan peticiones chunked que excedan el límite** (`Actual POST length does not match Content-Length, and exceeds 8388608 bytes`), cerrando esta ruta. Por su parte, PHP-FPM no procesa cuerpos chunked (carece de `CONTENT_LENGTH`), y Nginx aplica `client_max_body_size` a conexiones chunked (413). Los payloads públicos de ~3.7 MB no disparan OOM con configuraciones estándar.

## ¿Corrige `session.use_strict_mode=1` la Cadena A?

Bloqueó la variante con SID fijo en nuestras pruebas sobre 8.4.26, 8.4.27 y 8.5.12: el archivo con el SID elegido por el atacante no llega a crearse. No corrige las Cadenas C ni E. Representa defensa en profundidad, no un sustituto del parche.

## ¿Es esta una vulnerabilidad de Nextcloud?

No. El fallo reside en el inicio de la petición de PHP (`request startup`), antes de que se ejecute el código aplicativo. La prueba de RCE se obtuvo sobre la imagen oficial `php:8.4.26-apache`. Se empleó una instancia de prueba de Nextcloud 33.0.x (PHP 8.4.21, `mod_php` prefork) para validar la exposición de configuración y nivel de parche, pero el RCE no se disparó contra ese despliegue.

## ¿Contiene este repositorio exploits o PoCs funcionales?

No. Este repositorio analiza PoCs públicas y enlaza a ellas (`POCS.md`), proporcionando mediciones independientes y el esquema de reproducción científica. No redistribuye código ejecutable de terceros ni scripts armamentizados. El código del laboratorio reside en un repositorio privado e invite-only, disponible bajo petición al autor para revisores autorizados.

## ¿Es fiable el escáner público `php2shellbt`?

No. Generó un falso positivo confirmado contra 8.4.27, etiqueta erróneamente los identificadores de CVE, ignora ramas completas de PHP y deshabilita la verificación de certificados TLS. Debe tomarse como una anécdota, no como evidencia de postura o parche.

## ¿Por qué no existe una PoC universal?

La explotabilidad real depende estrictamente de la arquitectura del SAPI (`mod_php` prefork vs PHP-FPM), número de workers, habilitación de `session.upload_progress`, relación entre `memory_limit` y `post_max_size`, estado de ASLR, diseño del asignador y del kernel, flags de compilación del binario y presencia de proxies o WAFs. La PoC pública de evasión de ASLR funcionó en un host y falló en otro. Las cadenas A/C/E requieren adicionalmente un LFI en la aplicación, desajuste de serializadores por directorio o capacidad de escritura local.

## ¿Cómo verifico mi propia infraestructura?

1. Aplica el parche a la versión corregida de tu rama (8.4.27, 8.3.36, 8.2.35 u 8.5.12).
2. Ejecuta el control de verificación 8.4.27 documentado en `EVIDENCE.md`.
3. Aplica las directivas de hardening indicadas en `REMEDIATION.md`.
4. Monitoriza señales de detección (registros de OOM/abortos en error_log, valores anómalos de `PHPSESSID`).
5. Re-deriva las mediciones con el arnés publicado en [`lab/`](lab/README.es.md)
   (`147 passed, 4 skipped`); se distribuye sin los módulos operativos.

## ¿Quién realizó esta investigación?

Investigación de seguridad independiente y análisis de memoria por **JoshRob**.
