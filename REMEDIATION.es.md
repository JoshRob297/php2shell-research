# Guía de Remediación y Hardening

[English](REMEDIATION.md) · [Español](REMEDIATION.es.md)

---

Este documento detalla las soluciones técnicas para mitigar y erradicar las vulnerabilidades analizadas en despliegues PHP.

## 1. Aplicación de Parches

Actualice de inmediato a una versión oficial corregida:

| Rama PHP | Versión Corregida |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

El parche del fabricante resuelve la clase de OOM y corrupción de estado (CVE-2026-109618 / CVE-2026-109619). No corrige por sí solo las cadenas a nivel aplicativo que requieren controles adicionales de configuración (sección 3).

### Verificación del Parche

```bash
php -v
php -i | grep -E 'memory_limit|post_max_size|session.upload_progress'
```

En compilaciones desde código fuente, confirme que `ext/session/session.c` incorpora los cambios de 8.4.27:
- Reinicio temprano de variables globales de petición.
- `PS(in_rfc1867_update)` y `php_session_unserialize_init()` restringidos a clases incompletas.
- Salvaguarda `PG(modules_activated)` en el callback rfc1867.
- Limpieza de `_SESSION` tras la actualización de progreso de carga.

Ejecute la verificación de control descrita en `EVIDENCE.md`: el generador de peticiones que causa abortos en 8.4.26 no debe generar ningún `zend_mm_heap corrupted` ni señales de aborto en 8.4.27.

---

## 2. Hardening de Configuración (`php.ini`)

El parche oficial es el control primario obligatorio. Las siguientes directivas reducen la superficie de ataque y bloquean las cadenas a nivel de petición:

| Control | Riesgo que Mitiga | Consideraciones Operativas |
|---|---|---|
| `session.use_strict_mode=1` | Rechaza IDs de sesión no inicializados; bloquea la variante con SID fijo de la Cadena A | Compatible con manejadores de archivos y Redis (`phpredis`); validar flujos de login |
| `session.use_only_cookies=1` | Evita que IDs de sesión viajen en URL o POST en flujos normales | No es suficiente por sí solo para upload progress (el PR #22113 es la guardia faltante) |
| `session.upload_progress.enabled=0` | Elimina la primitiva de escritura en sesión durante cargas multipart | Deshabilitar si la aplicación no requiere barras de progreso nativas |
| `session.upload_progress.cleanup=1` | Elimina datos de progreso al finalizar la petición | Valor por defecto; reduce la ventana de carrera en Cadena A |
| Límites de cuerpo y buffering | Dificulta la saturación de workers y el emparejamiento para OOM | Balancear con límites legítimos de subida |
| Reglas en WAF / Proxy Inverso | Bloquea firmas multipart conocidas y ráfagas abusivas de peticiones chunked | Defensa en profundidad; no sustituye al parche |

Configuración recomendada de hardening:

```ini
session.use_strict_mode = 1
session.use_only_cookies = 1
session.upload_progress.enabled = 0   ; si no se requiere seguimiento de subidas
; o en caso de requerirse obligatoriamente:
; session.upload_progress.enabled = 1
; session.upload_progress.cleanup = 1
```

---

## 3. Controles a Nivel Aplicativo y de Servidor Web

- **Mitigación de LFI**: Audite llamadas dinámicas a `include`, `require` o `include_once` que reciban rutas del usuario. Sin LFI, la Cadena A queda limitada a una escritura local huérfana en `/tmp/sessions/`.
- **Enmascaramiento de Errores**: Mantenga `display_errors = Off` y `display_startup_errors = Off` en todos los entornos de producción para evitar la divulgación de punteros y rutas en cabeceras o cuerpo HTTP.
- **Configuración de Apache**: En despliegues con `mod_php`, configure `LimitRequestBody` de forma explícita para evitar que peticiones chunked sobrepasen los límites de memoria antes del procesamiento aplicativo.
- **Configuración de Nginx**: Asegure `client_max_body_size` en proxies reversos para que las peticiones que excedan la cuota sean rechazadas con HTTP 413 a nivel del proxy.
