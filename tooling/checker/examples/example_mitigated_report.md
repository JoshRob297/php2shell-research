# Diagnostico Defensivo php2shell: https://app.example.internal/

## Metadatos de Auditoria
- Fecha/Hora: 2026-10-25T16:05:00+00:00
- Objetivo: https://app.example.internal/
- Modo: external_authorized
- Garantia no destructiva: Cumplida: peticiones inocuas < 10 KB, sin heap grooming ni OOM
- Peticiones totales enviadas: 3

## Veredicto y Postura
- Veredicto: MITIGATED
- Indice de exposicion: 13.0%

### Desglose de Puntuacion Defensiva
| Factor | Peso | Estado Detectado | Contribucion Exposicion |
|---|---|---|---|
| Version PHP Parcheada | 25% | Version parcheada o superior (8.4.27) | 0.0% |
| session.use_strict_mode | 25% | Activo (fuerza nuevo SID ante identificador no inicializado) | 0.0% |
| session.upload_progress | 20% | Bloqueado o no procesa formularios multipart | 0.0% |
| Limites de Cuerpo y Proxy | 20% | Limites defensivos activos detectados (HTTP 413) | 0.0% |
| Arquitectura SAPI | 10% | PHP-FPM con frontal proxy detectado | 8.0% |

## Evidencia por Modulo

### 1. Fingerprint y Version
- Servidor Web: nginx/1.26.2
- X-Powered-By: PHP/8.4.27
- Version PHP detectada: 8.4.27
- Rama de version: 8.4
- Requiere parche: No
- Referencia parcheada: 8.4.27
- SAPI estimada: fpm-proxy

### 2. Comportamiento de Sesion (session.use_strict_mode)
- SID de prueba (sanitizado): checke...[sha256:5a91b4e2]
- Set-Cookie recibido: Si
- SID reemplazado por servidor: Si
- Evaluacion strict_mode: Servidor rechazo SID no inicializado y emitio nuevo PHPSESSID. session.use_strict_mode activo o regeneracion forzada (mitigado).

### 3. Red y upload_progress
- Metodo multipart procesado: No
- Status HTTP respuesta multipart: 413
- Soporte aparente upload_progress: Bloqueado/No activo
- Limites de proxy detectados: Si (413 recibido)
- Bytes transmitidos en probe: 241 bytes
- Observaciones: Servidor o proxy rechazo peticion por tamano (HTTP 413: limites estrictos activos).

## Remediaciones Defensivas Recomendadas
- No se detectaron remediaciones urgentes basadas en las evidencias recolectadas.

---
*Reporte generado automaticamente por php2shell-checker. Prohibida su utilizacion sin autorizacion expresa.*
