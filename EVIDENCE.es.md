# Evidencia y Mediciones de Laboratorio

[English](EVIDENCE.md) · [Español](EVIDENCE.es.md)

---

Mediciones sanitizadas obtenidas en contenedores de laboratorio desechables sobre interfaces loopback. Nombres de host, rutas privadas y credenciales han sido omitidos; todos los comandos son reproducibles con imágenes oficiales de Docker.

---

## 1. Configuración del Laboratorio

- **Imagen vulnerable**: `php:8.4.26-apache` (y `php:8.4.26-fpm` para el diferencial A/C/E).
- **Imagen de control**: `php:8.4.27-apache` / `php:8.4.27-fpm`.
- **Pruebas adicionales**: `php:8.5.12-fpm`.
- **Apache `mpm_prefork`**: Pool acotado de workers; worker único en pruebas que requerían determinismo estricto.
- **Parámetros**: `display_errors=On`, `memory_limit=8M`, `post_max_size=64M`, `session.upload_progress.enabled=On`.
- **ASLR**: Controlado mediante `setarch -R` exclusivamente en corridas con ASLR desactivado por proceso.

---

## 2. Matriz OOM / RCE (`mod_php`, oficial `php:8.4.26-apache`)

| Perfil | Corridas | Resultado Medido |
|---|---|---|
| `display_errors=On`, ASLR on | 3 | RCE alcanzado 3/3, `uid=33(www-data)` |
| `display_errors=Off`, ASLR off | 3 | RCE alcanzado 3/3, `uid=33(www-data)` |
| `display_errors=Off`, ASLR on | 3 | Corridas controladas 0/3; cookie de 4000 B dependiente del estado; punteros de heap divulgados, sin acceso a tabla de sesión |
| `display_errors=Off`, ASLR on, intento RCE | 3 | 0/3; sin lectura de tabla de sesión ni puntero ASLR fijado; ruta cerrada |
| Control `php:8.4.27-apache` | 5 | 0/5; sin abortos ni sobrelectura (`raw/ctl-8427.txt`) |

Registros crudos asociados: `raw/evidence-vuln-8426.txt`, `raw/evidence-fixed-8427.txt`, `raw/ctl-8427.txt`.

---

## 3. Cadena E-OOM en PHP-FPM (`sapi_module.ub_write`)

Mediciones en el entorno FPM 8.4.26 (`fpmdbg` detrás de Nginx `ngdbg` en puerto 18088):

- **Línea base medida en imagen de depuración (`phpdebug:8.4.26-fpm`)**:  
  `T2 = 0x555556ae2dd0` (`&sapi_module.ub_write`), `V = 0x7ffff7070090` (`&system`).
- **Línea base medida en imagen oficial de distribución (`php:8.4.26-fpm` Debian 13 Bookworm/Trixie)**:  
  `T2 = 0x555556ae1a30` (offset exacto `+0x30` de `sapi_module` en `0x555556ae1a00`), `V = 0x7ffff7096090` (`&system`).

En ambos entornos, la condición aritmética:
$$(T2 - d - 0x110) \pmod{16} == 0$$
se cumple de forma exacta, provocando la captura del watchpoint en memoria viva:

```text
WATCH_ub_write: val=0x7ffff7096090 pc=0x5555559654d0
SYSTEM rdi=0x7ffff6202040 str=[X-Powered-By: PHP/8.4.26]
SYSTEM rdi=0x7ffff6256230 str=[Content-type: text/html; charset=UTF-8]
...
SYSTEM rdi=0x7ffff6266078 str=[read=foo;id>/tmp/pwned]
```

Y generando el artefacto de ejecución arbitraria con permisos de servidor web:
```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Prerrequisitos en laboratorio:** ASLR desactivado para el árbol de procesos mediante `setarch x86_64 -R`, sesión plantada de 24 bytes (`C|i:<V>;AAAA`) y offsets calibrados. Bajo ASLR activo sin LFI previo, el aislamiento del socket FastCGI y la fragmentación de páginas en Zend MM degradan la técnica estrictamente a **Denegación de Servicio determinista (P3)**.
