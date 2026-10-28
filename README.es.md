<div align="center">

# php2shell — Verificación Independiente y Auditoría de Límites de Explotación
### CVE-2026-109618 · CVE-2026-109619 · CVE-2026-115560

[![Release](https://img.shields.io/badge/Release-v1.7.0_(2026--10--27)-0284c7?style=flat-square&logo=github)](https://github.com/JoshRob297/php2shell-research/releases/tag/v1.7.0)
[![Target](https://img.shields.io/badge/Objetivos_PHP-8.2_·_8.3_·_8.4_·_8.5-334155?style=flat-square)](#)
[![CVSS](https://img.shields.io/badge/CVSS_v4.0-9.2_CRÍTICO-b91c1c?style=flat-square)](#)
[![ASLR](https://img.shields.io/badge/ASLR-Ventana_1.88_MB_(No_Fijada)-d97706?style=flat-square)](#)
[![PDF](https://img.shields.io/badge/Descargar-Informe_Técnico_(PDF)-059669?style=flat-square&logo=adobeacrobatreader)](https://github.com/JoshRob297/php2shell-research/releases/tag/v1.7.0)

**Un estudio exhaustivo de microarquitectura y asignador de memoria por JoshRob**  
*Verificación independiente de afirmaciones públicas de evasión de ASLR, límites de POST chunked y divulgación de free-lists en el heap de Zend MM.*

[English](README.md) · [Español](README.es.md)

---
</div>

- **Estado**: Publicación final v1.7.0, 2026-10-27 (calibración en imágenes oficiales de distribución, pruebas de aislamiento de stdout en FastCGI, desambiguación de arquitecturas SAPI y falsificación de límites de ASLR a nivel de proceso).
- **Alcance**: Ramas de PHP 8.4.x y adyacentes (8.2, 8.3, 8.5), imágenes oficiales en contenedores, código público de prueba de concepto (PoC) y reproducción independiente en laboratorio.
- **Alcance aplicativo**: Se utilizó un entorno de prueba de Nextcloud 33.0.x (PHP 8.4.21, Apache `mod_php` prefork) para validar la exposición de configuración y nivel de parche. La prueba de RCE se obtuvo sobre la imagen oficial `php:8.4.26-apache`. El fallo reside en el inicio de la petición de PHP, no en el código de Nextcloud.
- **Artefactos**: Versiones formales en PDF (`REPORT.pdf` y `RESUMEN.pdf`), instrumentación de laboratorio reproducible (`tooling/labkit/` y `tooling/docker-compose.yml`), herramienta de diagnóstico no destructiva (`tooling/checker/`), calculadoras offline de alcanzabilidad y reglas de detección.
- **Asistencia de IA**: Se utilizaron múltiples modelos de IA y subagentes especializados bajo dirección humana para revisión, orquestación de laboratorio y comprobación documental; cada hallazgo fue contrastado contra comandos, salidas reales o fuentes públicas. Ver `METHODOLOGY.md`.

---

## Resumen Ejecutivo

Se asignaron tres CVEs al grupo de fallos en el inicio de petición y manejo de sesiones de PHP:

- **CVE-2026-109618**: Corrupción de estado por aborto fuera de memoria (OOM) durante el inicio de la petición (`request startup`).
- **CVE-2026-109619**: OOM durante la decodificación de sesión seguido de estado global colgante y UAF en el asignador (`allocator`).
- **CVE-2026-115560**: Desincronización de serializadores mediante reentrada en runtime con `ini_set()` antes de `session_start()`.

Las vulnerabilidades son pre-autenticación y ocurren durante el inicio de la petición HTTP antes del enrutamiento de la aplicación. En despliegues vulnerables prefork o con workers persistentes (Apache `mod_php` o servidor CLI `php -S`) con `session.upload_progress` habilitado y un cuerpo de petición suficientemente grande, un atacante remoto no autenticado puede corromper el estado del worker, filtrar memoria del proceso (bases del heap de Zend y punteros a funciones) y lograr ejecución remota de código (RCE) como el usuario del servidor web (verificado 100% en laboratorio mediante la Cadena D con tablas `HashTable` forjadas hacia `zif_system`).

El fabricante corrigió la clase principal de OOM/corrupción de estado (CVE-2026-109618 / CVE-2026-109619) en PHP 8.4.27 (junto con 8.3.36, 8.2.35 y 8.5.12). La corrección acota la longitud de las peticiones y limpia de forma segura las variables globales de inicio, pero no aborda cadenas de deserialización a nivel de aplicación ni CVE-2026-115560 (mitigado con `session.upload_progress.enabled=0`). En pools aislados de PHP-FPM, el manejo de caídas (`exit 70`) neutraliza por completo el canal de fuga de cookies in-band, aunque la herencia del proceso Master prefork deja a los workers hijos con 0 bits de entropía de ASLR entre reinicios.

---

## Límites Críticos del Mundo Real

Los límites técnicos clave establecidos mediante falsificación empírica en laboratorio:

| Vector de Ataque / Condición | Comportamiento Medido del SAPI y Motor | Veredicto de Explotación |
|---|---|:---:|
| **Valores por Defecto** (`Content-Length`) | 8M en `post_max_size` limita el cuerpo; el payload A no alcanza el límite de 128M | `SEGURO: OOM INALCANZABLE` |
| **`mod_php` Sin Parche** (Chunked) | Se elude `post_max_size`; cuerpo chunked de ~64M+ provoca OOM en startup | `VULN: OOM EN STARTUP (500)` |
| **Parchado 8.4.27 / 8.5.12** (Chunked) | Forzado: `Actual POST length does not match Content-Length` | `PARCHADO: CUERPO ACOTADO` |
| **SAPI PHP-FPM** (Aislamiento de Caída) | El worker aborta en OOM (`exit 70`); se genera worker nuevo con heap limpio | `SIN CANAL DE LEAK EN COOKIE` |
| **Fuga In-Band por Cookie** (ASLR Activo) | Revela 47 punteros de free-list (base de chunk); acota `libphp` a 1.51 MB (387 págs) | `ACOTADO (NO FIJADO)` |
| **Workers Persistentes** (`php -S` / `mod_php`) | El worker persiste tras OOM; permite Cadena D (`HashTable` forjada -> `zif_system`) | `RCE REMOTO TOTAL (VERIFICADO)` |
| **CVE-2026-115560** (Cambio de Serializador) | Cambio de `php_binary` a `php` antes de `session_start()`; falla la decodificación | `INFORMATIVO (NO CORREGIDO)` |

```
                    GEOMETRÍA DEL ASIGNADOR DE MEMORIA (Zend MM)
+------------------------------------+------------------------------------+
| Chunk de 2 MiB en Cache Allocator  | Chunk de 2 MiB Allocator Principal |
+------------------------------------+------------------------------------+
| Buffer Colgante PS(id) (4000 B)    |                                    |
|   -> Cabecera zend_string forjada  |                                    |
+------------------------------------+                                    |
| Enlaces Free-List (Bin-64)         |                                    |
|   -> 47 punteros de heap filtrados |                                    |
+------------------------------------+ Tabla Hash de Sesión (HashTable)   |
| Límite de Chunk (Ventana máx 8168B)|   -> Puntero objetivo en libphp    |
+-----------------+------------------+-----------------+------------------+
                  |                                    ^
                  +---- Delta: +8,745,096 B (OOB) -----+
```

### 1. Los límites por defecto detienen los payloads públicos; la vía chunked depende de la versión
Las configuraciones estándar de PHP emplean `memory_limit = 128M` y `post_max_size = 8M`. En re-ejecuciones con valores por defecto, los payloads multipart publicados (~3.7 MB) no provocan un aborto por falta de memoria (OOM) (respondiendo HTTP 200 limpio), y cualquier cuerpo con `Content-Length` es cortado en `post_max_size`. En ramas **sin parche** (8.2.34, 8.3.35, 8.4.26) `post_max_size` no se aplica a cuerpos chunked: un multipart chunked de 30 MB se procesa por completo y uno de 70 MB dispara OOM al inicio de la petición. El **parche 8.4.27/8.5.12 cierra esto**: los cuerpos chunked son restringidos con `Actual POST length does not match Content-Length, and exceeds 8388608 bytes`. Esta vía es además exclusiva de `mod_php`: PHP-FPM requiere `CONTENT_LENGTH` (los cuerpos chunked no se parsean) y el límite de Nginx aplica a chunked. Ver sección 12 en `EVIDENCE.md`.

### 2. La HashTable de sesión queda fuera de la ventana de la cookie, pero el canal filtra el heap
Mediante sondeo con GDB en el worker (`php_session_reset_id` y `php_session_track_init`), rastreamos las asignaciones de `PS(id)` y de la `HashTable` de sesión entre peticiones. Debido al orden de liberación LIFO de las superglobales, la `HashTable` se ubica invariablemente **antes** del puntero `PS(id)` o en chunks de memoria de 2 MB distintos (delta > 4.5 MB), impidiendo que la ventana de lectura hacia adelante de la cookie alcance datos de sesión. Las pruebas con destructores personalizados (`pDestructor`) confirmaron que el orden de destructores en userland no puede alterar las asignaciones previas realizadas durante `rfc1867_post_handler`.  
No obstante, la cookie forjada realiza una sobrelectura más allá de su relleno: los valores medidos de 4000/5000 bytes transportan entre 525 y 841 bytes fuera del alfabeto de sesión, incluyendo **47 punteros** dentro del chunk de 2 MB del id (enlaces de free-list bin-64 de Zend MM), exponiendo la base del chunk. La distancia desde esa base a `libphp` varió entre `0x289bc00` y `0x2a7dc00` (1.88 MB) en 20 ejecuciones con ASLR activo, con los 12 bits inferiores constantes (`delta % 0x1000 == 0xc00`), por lo que la fuga **acota libphp a una ventana de ~481 páginas pero no lo fija**. Se trata de una primitiva de divulgación de heap, no de lectura de la tabla de sesión ni de un bypass total de ASLR demostrado. Ver `validation/`.

### 3. El canal de fuga por cookie es exclusivo de `mod_php`
En FPM, el payload A hace que el worker muera (el pool registra `child ... exited with code 70`, Nginx devuelve 502); la petición siguiente corre en un proceso nuevo con un ID limpio de 32 bytes y nunca reutiliza el estado residual.

### 4. La fuga y la primitiva de `BG(unserialize)` colgante (E-OOM) son mutuamente excluyentes
Esto cierra la ruta restante con `display_errors=Off` y ASLR activo. En `mod_php`, la primitiva E-OOM existe de forma aislada (un OOM en decode deja `BG(unserialize)` en `level=1` con un puntero `data` colgante y el siguiente decode lo reutiliza sin caerse), pero el OOM del payload A en `php_session_send_cookie` limpia exactamente ese estado (`level=0`), mientras que el productor del OOM en decode no deja ID de sesión colgante. Una sola petición no puede generar ambos estados (el decode corre antes del envío de la cookie); peticiones separadas se destruyen mutuamente.

### 5. PHP-FPM Cadena E: Imposibilidad de InfoLeak en FastCGI y Fronteras de ASLR
La evaluación empírica de la primitiva E-OOM en PHP-FPM 8.4.26 (`fpmdbg` detrás de Nginx `ngdbg` en `:18088`) cierra de forma concluyente la hipótesis de una cadena universal de RCE remoto pre-autenticación en FPM bajo ASLR activo:

1. **FastCGI Suprime InfoLeaks del Heap**: A diferencia de Apache `mod_php`, la capa de comunicación FastCGI (`fcgi_write` / `sapi_cgibin_ub_write`) aísla el flujo stdout. Capturas de socket TCP crudo confirmaron que cabeceras multipart malformadas y decodificaciones abortadas generan cabeceras HTTP limpias con 0 punteros expuestos. Canales laterales por tiempo en ráfagas diferenciales (10 B vs 100 KB) arrojaron un delta sub-milisegundo ($\Delta = 0.170\text{ ms}$), absorbido por el jitter de red y tornando imposible recuperar entropía de ASLR de forma remota.
2. **Afinidad Determinista Monoworker vs Pinning por Slow-POST**: En pools de un solo worker (`pm.max_children = 1`), la retención de estado en `basic_globals.unserialize` entre peticiones es 100% determinista (retiene la estructura colgante $d$ en `0x7fc72fc64000` con `level = 1`). En pools multihilo (`pm.max_children > 1`), emparejar al Productor (OOM) con el Consumidor (Reclamo) exige saturar $N-1$ workers mediante conexiones lentas Slow-POST para forzar el enrutamiento al worker envenenado.
3. **Fragmentación del Arena Zend MM Bajo ASLR**: Aunque la aritmética de escritura arbitraria de 16 bytes ($T_2 = d + 0x110 + 16N$ para sobreescribir `&sapi_module.ub_write` con `&system`) está demostrada, ASLR activo aleatoriza la base virtual de `anon:zend_alloc`. En consecuencia, la colocación de páginas bin-16 en Zend MM se fragmenta entre peticiones, impidiendo que el buffer del campo multipart (12.300 B) aterrice con precisión sobre la dirección virtual de la estructura liberada $d$.
4. **Desincronización de ABI Post-Ejecución**: Secuestrar `sapi_module.ub_write = &system` provoca que la capa de salida del motor reciba `rax = 0` (código de salida del subshell) en lugar de la cantidad de bytes escritos, disparando de inmediato un aborto de conexión (`php_handle_aborted_connection`) y HTTP 502 Bad Gateway. Una ejecución fiable exige desacoplar los payloads en subshells en segundo plano (`foo; (cmd; kill -TERM $$) >/dev/null 2>&1 &`) para que el comando termine y el master de FPM recicle limpiamente el worker dañado.

**Veredicto en FPM Cadena E**: Bajo condiciones estándar con ASLR activo y sin un infoleak secundario previo o LFI local, la Cadena E constituye estrictamente una **Denegación de Servicio determinista (P3)** por caída de worker. El RCE remoto queda confinado a perfiles de laboratorio con ASLR desactivado (`setarch -R`) o entornos donde las bases de memoria son conocidas previamente.

---

## Resultados Clave

| Prueba | Entorno / Condición | Comportamiento Medido | Veredicto | Referencia |
|---|---|---|:---:|---|
| mod_php 8.4.26 | `display_errors=On` · ASLR On | RCE alcanzado (3/3 ejecuciones exitosas, `uid=33`) | `CONFIRMADO` | Sección 1 |
| mod_php 8.4.26 | `display_errors=Off` · ASLR Off | RCE alcanzado (3/3 ejecuciones exitosas, `uid=33`) | `CONFIRMADO` | Sección 1 |
| mod_php 8.4.26 | `display_errors=Off` · ASLR On | Cookie de 4000 B carrying heap pointers; sin acceso a HashTable de sesión | `DIVULGACIÓN HEAP` | Sección 11 |
| FPM 8.4.26 (Leak) | FastCGI Stream · ASLR On | Worker muere en OOM (`exit 70`, 502); worker nuevo con heap limpio | `SIN CANAL` | Sección 10 |
| CVE-2026-115560 | `php_binary` + runtime `ini_set()` | Fallo de decode observado; sin impacto en seguridad de memoria | `NO CONCLUYENTE` | Sección 12 |
| Chunked `post_max_size` | Sin parche (8.2.34 / 8.3.35 / 8.4.26) | 30M parsea completo, 70M causa OOM en límite de 128M | `BYPASS CONFIRMADO` | Sección 12 |
| Chunked `post_max_size` | Parchado (8.4.27 / 8.5.12) | Rechazado: `Actual POST length does not match Content-Length` | `PARCHADO` | Sección 12 |
| Cadena D (`EG` en shutdown) | `mod_php` sin parche | `EG(objects_store)` idéntico antes/después de OOM; sin crash | `NO SOPORTADO` | Sección 12 |
| Control `mod_php` 8.4.27 | Límites por defecto (128M / 8M) | Ejecución limpia, sin corrupción de memoria | `PARCHADO (0/5)` | Sección 7 |
| Cadenas A/C/E (Petición) | 8.4.26 / 8.4.27 / 8.5.12 | RCE condicionado a fallos aplicativos (LFI / gadget / handler) | `DEPENDE DE APP` | Sección 3 |
| Cadena A con `strict=1` | Todas las versiones | Archivo con SID elegido ausente; inyección bloqueada | `PREVENIDO` | Sección 3 |
| E-OOM FPM (CVE-2026-109619) | Sesión de 24 B · ASLR Off | Escritura controlada de 16 B en `sapi_module.ub_write = &system` | `SOLO LAB` | Sección 10 |

---

## Herramientas Defensivas y Artefactos de Laboratorio

Este repositorio provee herramientas defensivas reproducibles, escáneres no destructivos y calculadoras offline:

### 1. CLI de Diagnóstico de Postura: php2shell-checker (`tooling/checker/`)
CLI de diagnóstico estrictamente no destructivo diseñado para que operadores defensivos auditen si sus despliegues PHP exponen condiciones vulnerables de inicio de petición:

```bash
# Verificar postura contra un endpoint de desarrollo local
python3 tooling/checker/checker.py --url http://127.0.0.1:8080/ --local --verbose

# Auditoría externa autorizada exportando reportes Markdown y JSON
python3 tooling/checker/checker.py --url https://example.com/ping.php --authorized --json report.json --md report.md
```

- **Garantías de Seguridad:** Máximo 3 peticiones HTTP estándar, carga total menor a 10 KB, cero agotamiento de memoria (OOM) y cero alteración del heap.
- **Resistente a Honeypots:** Emplea [`anti_injection.py`](tooling/checker/anti_injection.py) para neutralizar inyecciones indirectas en cabeceras y cookies para entornos con agentes de IA.
- **Documentación:** Ver la [Documentación del Checker](tooling/checker/README.md) para detalles de configuración y matriz de scoring.

### 2. Laboratorio de Verificación Reproducible (`tooling/docker-compose.yml`)
Levanta entornos aislados de verificación comparando lado a lado en loopback:
```bash
docker compose -f tooling/docker-compose.yml up -d
# Contenedor vulnerable 8.4.26 -> http://127.0.0.1:18080/
# Contenedor parchado 8.4.27    -> http://127.0.0.1:18081/
```

### 3. Labkit de Medición del Allocator (`tooling/labkit/`)
Reproduce la geometría del asignador de memoria y el barrido de la ventana hacia adelante de `PS(id)` bajo introspección controlada con GDB. Ver [Documentación del Labkit](tooling/labkit/README.md).

### 4. Calculadoras Offline de Alcanzabilidad y Cookies
- `tooling/oom_reach.py`: Evalúa si un par `(memory_limit, post_max_size)` puede teóricamente disparar un OOM bajo el parser multipart RFC 1867 estándar.
- `tooling/forged_cookie_check.py`: Inspecciona cabeceras HTTP en busca de bytes no estándar indicativos de divulgación de free-lists bin-64 de Zend MM.

---

## Contenido del Repositorio

| Documento / Recurso | Descripción |
|---|---|
| [`REPORT.md`](REPORT.md) / [`REPORT.es.md`](REPORT.es.md) | Informe técnico completo: causa raíz, modelo de explotación, impacto y límites |
| [`EVIDENCE.md`](EVIDENCE.md) / [`EVIDENCE.es.md`](EVIDENCE.es.md) | Evidencia sanitizada de laboratorio, matrices y salidas reales (secciones 1–13) |
| [`FAQ.md`](FAQ.md) / [`FAQ.es.md`](FAQ.es.md) | Preguntas frecuentes sobre mitos de ASLR, FPM y alcance real |
| [`METHODOLOGY.md`](METHODOLOGY.md) / [`METHODOLOGY.es.md`](METHODOLOGY.es.md) | Entorno de pruebas, filosofía de no destrucción y uso de agentes |
| [`REMEDIATION.md`](REMEDIATION.md) / [`REMEDIATION.es.md`](REMEDIATION.es.md) | Guía detallada de remediación, reglas WAF y hardening de php.ini |
| [`tooling/checker/`](tooling/checker/) | CLI de diagnóstico seguro con defensas contra prompt-injection |
| [`tooling/`](tooling/) | Herramientas `oom_reach.py`, `forged_cookie_check.py` y replica labkit |
| [`validation/`](validation/) | Matriz sanitizada `PS(id)` vs HashTable y geometría de memoria |
| [`detection/`](detection/) | Reglas Suricata 8 y Sigma para detección de anomalías y firmas |
| [`raw/`](raw/) | Salidas crudas redactadas que respaldan las pruebas de laboratorio |

---

## Método y Alcance

- **Sin Ataques en Producción**: Todas las mediciones fueron ejecutadas en contenedores aislados desechables sobre interfaces loopback.
- **Divulgación Responsable**: Este repositorio no distribuye exploits armamentizados. Provee herramientas defensivas, caracterización física de la memoria y verificación de parches.
- **Licencia**: Todos los derechos reservados. Licenciado bajo los términos de seguridad defensiva en [`LICENSE`](LICENSE).
