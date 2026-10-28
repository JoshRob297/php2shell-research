# Matriz de Cobertura y Verificación

[English](COVERAGE.md) · [Español](COVERAGE.es.md)

---

Definiciones de estado:

- **fail**: la vulnerabilidad o vector tuvo éxito bajo las condiciones medidas.
- **pass**: la contramedida bloqueó el caso probado, o la versión parchada no reprodujo el fallo.
- **n/a**: el prerrequisito no aplica (ej. vectores locales en auditorías remotas).
- **not tested**: sin medición empírica independiente en ese escenario.

## 1. CVEs de OOM y Corrupción de Estado

| Prueba / Vector | 8.4.21 | 8.4.26 | 8.4.27 | 8.5.12 | Notas |
|---|---|---|---|---|---|
| Aborto OOM / Corrupción de heap | Afectado por versión; no explotado | fail | pass | pass (0/3) | Control 8.4.27: 0/5 sin abortos; ramas corregidas bloqueadas en etapa 1 |
| RCE, `display_errors=On`, ASLR On | No probado | fail (3/3) | pass (0/5) | pass (0/3) | mod_php prefork; re-ejecución de control 3/3 en el mismo arnés |
| RCE, `display_errors=Off`, ASLR Off | No probado | fail (3/3) | pass | No probado aquí | Build con offsets calibrados; ramas fijas no probadas en este perfil |
| RCE, `display_errors=Off`, ASLR On | No probado | Inestable (0/3 controlado) | pass | No probado | Reclamación 12/12 retractada; cookie dependiente del estado |
| FPM decode OOM / `BG(unserialize)` colgante | No probado | Crash UAF determinista (502) comprobado en watchpoint; con struct reclamado por multipart, escritura controlada de 16 B en `sapi_module.ub_write = &system` -> RCE en lab | No probado | No probado | CVE-2026-109619; mecanismo por defecto = enlace de free-list sobre `used_slots`; variante controlada = fake `var_dtor_entries` (ASLR off, sesión de 24 B); 8.4.27 estable |
| Divulgación de memoria vía cookie | No probado | Parcial (cookie de 4000 B revela punteros de heap; HashTable inalcanzable; libphp acotado a ~1.88 MB, no fijado) | pass | pass (0/3) | Dependiente de geometría; ramas fijadas: fuga no reproducible |
| CVE-2026-115560 (Informativo, 2026-10-23) | No probado | No probado | No corregido | No probado | Condición estrecha (config `php_binary` + `ini_set()` a `php` en runtime); mitigación `session.upload_progress.enabled=0` |

Ramas fijadas 8.3.36 y 8.2.35 (mismo arnés, 3 corridas c/u): 0/3, bloqueadas en etapa 1 (fuga de heap). Registro crudo: `raw/fixed-branches-verify.txt`.

## 2. Cadenas a Nivel de Petición

| Cadena | 8.4.26 | 8.4.27 | 8.5.12 | ¿Remota? | Notas |
|---|---|---|---|---|---|
| A: upload-progress filename + LFI | fail | fail | fail | Requiere LFI | Evaluado con `strict=0`, `cleanup=Off`, `use_only_cookies=1` |
| A con `strict=1` | pass | pass | pass | Requiere LFI | Archivo bajo el SID elegido ausente |
| A con `cleanup=On` + race | No probado | No concluyente (2 intentos) | No probado | Requiere LFI | No representa garantía formal |
| B: local `/proc/self/mem` | n/a | n/a | n/a | No | Primitiva puramente local |
| C: desajuste de handler por directorio + gadget | fail | fail | fail | Nivel aplicativo | Probado en un proceso hijo prefork en mod_php |
| D: mod_php EG stale + spray de `zend_object` forjado | No probado | No probado | No probado | Remota según análisis de `ikow` | Scripts privados/paywall; vector independiente del leak de cookie y E-OOM; no cubierto por el cierre de ruta |
| D y E-OOM: cadenas de estado/OOM | Verificación pública; E-OOM alcanzó ejecución de comandos en lab con prerrequisitos | Verificación pública | No probado | D remota, E-OOM local en arnés | D/E completos no son públicos; variante controlada en `EVIDENCE.md` sección 10 |
| `PS(serializer)` entre peticiones | pass (sin residuo; mismatch + aborto OOM: prox req usa su propio INI) | pass (sin residuo; misma prueba) | No probado | n/a | FPM y mod_php |

## 3. Estado de Parches y Salvaguardas

| Elemento | Estado | Evidencia |
|---|---|---|
| 8.4.27 incluye arreglo para OOM/corrupción | pass | `NEWS`, diff de código fuente, control 0/5 |
| 8.4.27 reinicia `PS(serializer)` | fail (no presente; sin residuo explotable: handler e INI se mantienen emparejados) | Diff de código fuente + prueba de aborto por directorio |
| 8.4.27 incluye PR #22113 (guardia de SID fijo) | fail (no presente) | PR abierto; diff de código fuente |
| `session.use_strict_mode=1` bloquea SID fijo en A | pass | Laboratorio en 8.4.26 / 8.4.27 / 8.5.12 |
| `session.use_only_cookies=1` por sí solo bloquea A | fail | A tuvo éxito con SID enviado exclusivamente en multipart |
| `session.upload_progress.enabled=0` bloquea A | No probado (bloqueo esperado) | La Cadena A exige este manejador |
| `cleanup=On` bloquea A de forma determinista | No demostrado | 2 intentos de condición de carrera fallaron; no concluyente |
| Fuga de `PS(serializer)` entre peticiones | pass (no observada) | Pruebas h1/h2 en FPM y mod_php |
| Rama 8.5 `fatal_error_backtraces` | pass (no reproducida) | Build con símbolos; zval UNDEF -> IS_ARRAY_EX válido; 0 anomalías en barridos |
| Corrupción de memoria compartida en OPcache | pass (no reproducida) | Diferencial 8.4.26 vs 8.4.27; wasted_memory=0; 8.4.27 almacena entrada válida |

## 4. Fiabilidad de PoCs Públicas

| PoC / Herramienta | Reclamación | Estado Independiente |
|---|---|---|
| 9bie | Bypass de ASLR / RCE | pass en laboratorio; dependiente de la memoria del host |
| ikow A/B/C | Cadenas | Código analizable; A/C requieren prerrequisitos; B es local |
| ikow D/E | Scripts de verificación | Públicos; exploits completos cerrados/de pago |
| GoldraK scanner A/C/E | 24/24 vulnerable | pass para A/C/E; no mide OOM; 8.4.27 omitido de la tabla |
| dinosn | RCE asistido en lab | pass como asistido en lab; no es una PoC remota universal |
| php2shellbt | Escáner | fail: falso positivo contra 8.4.27; CVEs mal etiquetados |
| eness | Placeholder | n/a |

## 5. Alcance de Despliegue

| Capa | Qué se probó | Generalización |
|---|---|---|
| Oficial `php:8.4.26-apache` | RCE 3/3 On/ASLR On; 3/3 Off/ASLR Off; 0/3 Off/ASLR On | Primitiva a nivel de motor PHP; dependiente del build/allocator |
| Oficial `php:8.4.27-apache` | 0/5 control | Parche oficial para la clase OOM |
| Nextcloud 33.0.x test, PHP 8.4.21 `mod_php` | Versión/configuración validada; RCE no ejecutado | Primitiva independiente de la app; dependiente del despliegue |
| FPM A/C/E | RCE con prerrequisitos de laboratorio | Dependiente de aplicación/configuración |
| Otras aplicaciones PHP | No probado | Esperable bajo condiciones idénticas; no demostrado |

## 6. Brechas y Conclusiones Abiertas

- La secuencia FPM con `BG(unserialize)` colgante se reprodujo hasta el crash determinista por UAF (DoS). Con el struct reclamado por el multipart, la estructura forjada permite una escritura de 16 B y alcanzó RCE en laboratorio con ASLR desactivado (`setarch x86_64 -R`), verificado tanto en compilaciones de prueba como en la imagen oficial `php:8.4.26-fpm`.
- La variante remota bajo ASLR activo en FastCGI quedó descartada debido al aislamiento de flujos stdout y la dispersión de memoria de Zend MM.
