# Matriz de Validación: `PS(id)` vs la HashTable de Sesión

[English](README.md) · [Español](README.es.md)

---

Este directorio alberga las mediciones sanitizadas que respaldan la conclusión de la Fase 2 en `REPORT.md`: bajo configuraciones con `display_errors=Off`, el canal in-band por cabecera `Set-Cookie` no divulga estructuras de datos de sesión, y bajo los límites de recursos por defecto de PHP, la primitiva de OOM que inicia las cadenas no llega a dispararse.

---

## Qué se Midió

Para cada ejecución se reinició el servidor, se asoció un probe de GDB al worker único de Apache y se emitieron dos peticiones HTTP:

- **A** — Petición multipart con `PHP_SESSION_UPLOAD_PROGRESS` y un cuerpo calibrado para acondicionamiento del heap (`heap grooming`). El cuerpo dimensiona los bins de Zend MM para que el ID de sesión sea el último bloque bin-64 liberado, provocando que `php_session_send_cookie()` aborte durante la codificación del ID.
- **B** — Petición forjada que reutiliza el chunk liberado con una cabecera `zend_string` falsa de 4000 bytes y solicita al servidor que devuelva la cookie.

El probe registró `php_session_reset_id` (puntero del id en memoria) y `php_session_track_init` (puntero de la `HashTable` de sesión). `delta = ht - id` representa la distancia entre ambas estructuras, mientras que la ventana de la cookie es de a lo sumo `8168 bytes` hacia adelante dentro del chunk de 2 MiB.

---

## Columnas de la Matriz

| Columna | Significado |
|---|---|
| `label` | Identificador de la prueba en los registros de laboratorio |
| `ini_profile` | Perfil de configuración: PHP defaults, 32M o el override de 8M del lab |
| `memory_limit`, `post_max_size` | Valores efectivos configurados en PHP |
| `id_len` | Longitud registrada en el ID de sesión en memoria durante `RESET` |
| `id_page`, `ht_page` | Offset dentro del chunk de 2 MiB (no es una dirección de memoria virtual) |
| `delta` | `ht_page - id_page`; positivo indica que la HashTable reside después del ID |
| `same_chunk` | 1 si ambas estructuras cayeron dentro del mismo chunk de 2 MiB |
| `a_resp_len`, `b_resp_len` | Longitud en bytes de las respuestas HTTP crudas |
| `leak_bytes` | Bytes fuera del alfabeto de sesión `[A-Za-z0-9,-]` en la cookie decodificada |
| `ptr_like` | Cantidad de valores little-endian de 8 bytes en el rango `0x7f...` dentro del valor decodificado |
| `note` | Interpretación y veredicto breve |

---

## Conclusiones Principales

1. **Los valores por defecto detienen los payloads publicados; la vía chunked depende de la versión y SAPI.** Con `memory_limit=128M` y `post_max_size=8M`, la petición A (~3.7 MB) devuelve HTTP 200 limpio y nunca aborta ante cualquier petición con `Content-Length`. En versiones sin parche de `mod_php`, `post_max_size` no se aplica a cuerpos chunked (70 MB causa OOM). En 8.4.27 y 8.5.12 esto fue corregido, y en PHP-FPM los cuerpos chunked son ignorados por falta de `CONTENT_LENGTH`.
2. **Inexistencia de ventana de lectura hacia adelante en el perfil de 8M.** En todas las corridas con 8M, la `HashTable` se ubicó en un chunk de 2 MiB diferente, separada por varios megabytes del ID o situada antes de él, impidiendo su lectura hacia adelante.
3. **El canal de la cookie forjada divulga memoria del heap, pero no la tabla de sesión.** La sobrelectura copia los datos adyacentes: revela **47 punteros a intervalos de 64 bytes** correspondientes a enlaces de free-list bin-64 de Zend MM del buffer anterior.
4. **La filtración acota libphp, pero no lo fija.** En 20 repeticiones, la distancia desde la base del chunk a `libphp` varió entre `0x289bc00` y `0x2a7dc00` (1.88 MB), con los 12 bits inferiores constantes (`delta % 0x1000 == 0xc00`). Esto reduce la búsqueda a ~481 páginas pero no derrota ASLR de forma determinista.
5. **El canal es de un solo disparo por OOM y exclusivo de `mod_php`.** En PHP-FPM, el OOM aborta el worker (`exit 70`), por lo que la siguiente petición es atendida por un worker nuevo con estado limpio.
6. **La fuga y la primitiva `BG(unserialize)` colgante (E-OOM) son mutuamente excluyentes.** En `mod_php`, la petición que provoca la fuga destruye el estado que la primitiva E-OOM requiere para su reutilización.
