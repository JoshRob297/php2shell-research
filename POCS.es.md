# Revisión y Verificación Independiente de PoCs Públicas

[English](POCS.md) · [Español](POCS.es.md)

---

Este documento analiza el material público de prueba de concepto (PoC) surgido durante la ventana de divulgación. No redistribuye código de explotación de terceros; los enlaces dirigen a los repositorios originales. Toda ejecución fue realizada en un laboratorio desechable, sobre interfaces loopback, contra imágenes oficiales de PHP.

Nota de alcance: la prueba de RCE se obtuvo sobre la imagen oficial `php:8.4.26-apache`. Se empleó una instancia de prueba de Nextcloud 33.0.x (PHP 8.4.21, `mod_php` prefork) para validar la exposición de configuración y nivel de parche; el RCE no fue disparado contra dicho despliegue. El fallo reside en el inicio de la petición de PHP (`request startup`), no en el código de Nextcloud.

El código de PoC del laboratorio reside en un repositorio privado e invite-only, disponible bajo petición al autor.

---

## Resumen de PoCs Analizadas

| Repositorio | Qué es | Resultado Independiente |
|---|---|---|
| `9bie/php2shell-bypass-aslr-exp` | Exploit Python con bypass de ASLR, solo librería estándar | Funcional en laboratorio: 8/8 con ASLR On, 5/5 con ASLR Off; dependiente de la memoria del host |
| `ikow/php2shell-poc` | Cinco cadenas; A/B/C públicas, D/E con scripts de verificación y exploits completos de pago | A/B/C analizables y evaluables; verificación de D/E pública; D/E completos privados |
| `GoldraK/php2shell-poc` | Fork del autor anterior; escáner A/C/E, laboratorio y reglas | Escáner reporta 24/24 vulnerable; mide A/C/E, no la cadena OOM |
| `dinosn/php-cve-2026-10961x-lab-poc` | Laboratorio con asignador instrumentado | Asistido en lab; emplea `USE_ZEND_ALLOC=0`; no es una PoC remota universal |
| `pentestershell/php2shellbt` | Escáner ligero en Python | Falso positivo confirmado contra 8.4.27; CVEs mal clasificados |
| `eness/php2shell-...-PoC` | Repositorio placeholder | Sin código publicado |
| `KillaBoi/StealMyBitcoin-PoC` | Exploit de 4 etapas que resuelve el reto stealmybitcoin | Confirmado 100% en lab: explota la Cadena D (`HashTable` forjada -> `zif_system`) en `php -S` con workers |

---

## Análisis Técnico Detallado

### KillaBoi: Exploit del Reto CTF StealMyBitcoin (Cadena D y Servidor CLI)
- Desarrollado en Python 3, requiere como máximo 20 peticiones HTTP estándar.
- **Desambiguación de SAPI:** Opera contra Alpine `PHP 8.4.26` corriendo el servidor de desarrollo integrado (`php -S 0.0.0.0:8000`) con múltiples workers (`PHP_CLI_SERVER_WORKERS=4`) detrás de un proxy inverso Nginx.
  - Distinción crítica: los workers del servidor CLI persisten tras los abortos OOM (de forma análoga a `mod_php`), permitiendo que la cookie filtrada devuelva punteros del heap de Zend y `zval_ptr_dtor`.
  - En PHP-FPM estándar, el worker aborta (`exit 70`), neutralizando este vector de filtración.
- **Mecánica de Explotación:**
  - **Etapa 1 (Heap Leak):** 1 productor multipart (249 KB) + 8 consumidores en pipeline -> extrae cookie de 256 B revelando la base alineada del chunk de 2 MiB de Zend MM.
  - **Etapa 2 (Code Leak):** 1 productor multipart (251 KB) + 8 consumidores en pipeline -> extrae cookie de 16 B revelando `zval_ptr_dtor`, deduciendo `zif_system`.
  - **Etapa 3 (Callback):** 1 POST (368 KB) que ubica una `HashTable` forjada solapando un call frame y el comando; la limpieza interna de PHP ejecuta `zif_system`.
  - **Exfiltración:** Escanea `/proc/self/fd/` para escribir la salida directamente al descriptor de socket de la conexión HTTP activa.
- **Verificación:** Replicado con éxito en nuestro entorno de pruebas el 2026-10-26, alcanzando ejecución de comandos como `root` (UID 0).

### 9bie: Exploit con Bypass de ASLR
- El exploit apunta a la cadena OOM/corrupción de estado e incluye bypass de ASLR para Apache `mod_php`.
- En nuestro laboratorio produjo ejecución exitosa como `uid=33(www-data)` en 8/8 corridas con ASLR activo y 5/5 con ASLR desactivado.
- Advertencia: la técnica depende de la disposición del asignador y del kernel del host; no es universal sin calibración previa de offsets.

### ikow: Repositorio de Cinco Cadenas
- **A**: inyección de nombre de archivo vía upload-progress + LFI. Requiere un fallo aplicativo de inclusión de archivos.
- **B**: primitiva local vía `/proc/self/mem`. No constituye una vulnerabilidad remota.
- **C**: desajuste de serializadores por directorio (`.htaccess`) y presencia de gadgets deserializables.
- **D y E-OOM**: cadenas de OOM y estado del motor. Los exploits completos son cerrados/comerciales.

### GoldraK: Fork y Escáner A/C/E
- El escáner evalúa únicamente las cadenas A/C/E; no mide la cadena de corrupción por OOM en request startup.
- Utiliza una configuración intencionalmente permisiva (`session.use_only_cookies=0`, `session.use_strict_mode=0`, `cleanup=Off`), lo que facilita la Cadena A pero no refleja configuraciones endurecidas de producción.
