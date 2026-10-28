# Reglas de Detección para php2shell

[English](README.md) · [Español](README.es.md)

---

Este directorio contiene firmas de detección y reglas de inspección para IDS/IPS y SIEM/EDR:

- **[`php2shell-refined.rules`](php2shell-refined.rules)**: Reglas Snort / Suricata 8 orientadas a detectar:
  - Cuerpos multipart anómalos con campos anidados de saturación.
  - Transferencias chunked que intentan evadir límites de `post_max_size`.
  - Respuestas HTTP con cabeceras `Set-Cookie` que contienen bytes no alfanuméricos y punteros de heap filtrados.
- **[`php2shell-refined.yaml`](php2shell-refined.yaml)**: Reglas Sigma para análisis de registros de servidores web (Apache/Nginx/FPM) y correlación de ráfagas de errores 500/502 provocados por abortos OOM repetidos.
