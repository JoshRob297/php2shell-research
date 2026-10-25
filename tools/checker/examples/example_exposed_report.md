# Diagnostico Defensivo php2shell: http://127.0.0.1:8080/

## Metadatos de Auditoria
- Fecha/Hora: 2026-10-25T16:00:00+00:00
- Objetivo: http://127.0.0.1:8080/
- Modo: local_lab
- Garantia no destructiva: Cumplida: peticiones inocuas < 10 KB, sin heap grooming ni OOM
- Peticiones totales enviadas: 3

## Veredicto y Postura
- Veredicto: EXPOSED
- Indice de exposicion: 73.0%

### Desglose de Puntuacion Defensiva
| Factor | Peso | Estado Detectado | Contribucion Exposicion |
|---|---|---|---|
| Version PHP Parcheada | 25% | Version vulnerable (8.4.26 < 8.4.27) | 25.0% |
| session.use_strict_mode | 25% | Inactivo / expuesto (acepta SID arbitrario) | 25.0% |
| session.upload_progress | 20% | Activo y procesa multipart con PHP_SESSION_UPLOAD_PROGRESS | 20.0% |
| Limites de Cuerpo y Proxy | 20% | Sin limites restrictivos detectados en probe corta (< 10 KB) | 10.0% |
| Arquitectura SAPI | 10% | PHP-FPM con frontal proxy detectado | 8.0% |

## Evidencia por Modulo

### 1. Fingerprint y Version
- Servidor Web: nginx/1.24.0
- X-Powered-By: PHP/8.4.26
- Version PHP detectada: 8.4.26
- Rama de version: 8.4
- Requiere parche: Si
- Referencia parcheada: 8.4.27
- SAPI estimada: fpm-proxy

### 2. Comportamiento de Sesion (session.use_strict_mode)
- SID de prueba (sanitizado): checke...[sha256:7d8a2f1c]
- Set-Cookie recibido: Si
- SID reemplazado por servidor: No
- Evaluacion strict_mode: Servidor acepto y devolvio el SID arbitrario en Set-Cookie. session.use_strict_mode inactivo (expuesto).

### 3. Red y upload_progress
- Metodo multipart procesado: Si
- Status HTTP respuesta multipart: 200
- Soporte aparente upload_progress: Activo/Aceptado
- Limites de proxy detectados: No observados en probe corta
- Bytes transmitidos en probe: 241 bytes
- Observaciones: El servidor acepto multipart/form-data con status 200. upload_progress potencialmente activo en la ruta evaluada.

## Remediaciones Defensivas Recomendadas
- Actualizar PHP de la version 8.4.26 a 8.4.27 o superior.
- Configurar 'session.use_strict_mode = 1' en php.ini.
- Desactivar 'session.upload_progress.enabled = 0' en php.ini si no se requiere.
- Asegurar directivas 'client_max_body_size' (Nginx) o 'LimitRequestBody' (Apache) acotadas.

---
*Reporte generado automaticamente por php2shell-checker. Prohibida su utilizacion sin autorizacion expresa.*
