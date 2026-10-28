# Capturas Crudas de Laboratorio

[English](README.md) · [Español](README.es.md)

---

Este directorio contiene capturas de terminal redactadas y sanitizadas provenientes de los contenedores de laboratorio desechables utilizados para el informe técnico. Las direcciones IP internas de los contenedores fueron sustituidas por `<container-ip>`; no se incluyen nombres de host, direcciones privadas, credenciales ni datos de usuarios reales.

| Archivo | Respaldo y Referencia Técnica |
|---|---|
| `evidence-vuln-8426.txt` | Evidencia de OOM/abortos en 8.4.26 (`EVIDENCE.md` sección 2) |
| `evidence-fixed-8427.txt` | Control en 8.4.27, ausencia de abortos (`EVIDENCE.md` sección 2) |
| `evidence-aslr-diff.txt` | Diferencial de fuga y pruebas con ASLR off/on (`EVIDENCE.md` sección 2) |
| `rce-on-aslr-on-8426.txt` | Validación final, RCE en 8.4.26, `display_errors=On`, ASLR on: 3/3 `uid=33` |
| `ctl-8427.txt` | Validación final, control en 8.4.27, 5 corridas: `HEAP_LEAK_FAILED`, 0 abortos |
| `ace-8427.txt` | Validación final, cadenas A/C/E en 8.4.27-fpm: RCE `uid=33` |
| `ace-8512.txt` | Validación final, cadenas A/C/E en 8.5.12-fpm: RCE `uid=33` |
| `fpm-chain-e-8426.txt` | E-OOM (FPM stale BG): evidencia GDB del UAF en `var_push` y estado envenenado |
| `fpm-chain-e-encoding-8426.txt` | E-OOM: watchpoint en la codificación de free-list sobre `used_slots` (`EVIDENCE.md` sección 10) |
| `fpm-rce-ub-write.txt` | E-OOM: watchpoint en `sapi_module.ub_write` = `&system`, 9 llamadas a `system()`, salida de `id` |
| `backtraces-8511-gdb.txt` | Rama 8.5.11 `fatal_error_backtraces`: zval UNDEF -> `IS_ARRAY_EX` válido (`EVIDENCE.md` sección 10) |
| `opcache-differential-8426-8427.txt` | Rama OPcache: diferencial de compilación con OOM, `wasted_memory=0` (`EVIDENCE.md` sección 10) |
| `fixed-branches-verify.txt` | Arnés OOM/RCE en 8.5.12 / 8.3.36 / 8.2.35: 0/3, bloqueado en etapa 1 (`EVIDENCE.md` sección 3) |

Las matrices completas y su análisis se detallan en `EVIDENCE.md` y `METHODOLOGY.md`. No se distribuye código ejecutable de terceros.
