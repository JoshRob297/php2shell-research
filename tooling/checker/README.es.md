# php2shell-checker: Herramienta de Diagnóstico de Postura No Destructiva

[English](README.md) · [Español](README.es.md)

---

Una herramienta CLI de diagnóstico segura y estrictamente no destructiva diseñada para administradores de sistemas, equipos de respuesta a incidentes (DFIR/SOC) e investigadores de seguridad. Permite auditar la postura del servidor y los requisitos de configuración vinculados a las vulnerabilidades de inicio de petición en PHP (CVE-2026-109618 / CVE-2026-109619) sin provocar denegación de servicio, agotamiento de memoria (OOM) ni corrupción del heap.

---

## 1. Principios Operativos y Garantías Defensivas

- **Estrictamente No Destructivo:** No transmite payloads de explotación, no ejecuta comandos y no altera el estado del servidor.
- **Huella de Red Mínima:** Emite un máximo estricto de 3 peticiones HTTP(S) estándar por auditoría.
- **Tamaño de Petición Acotado:** Cargas útiles limitadas por debajo de 10 KB (típicamente menos de 1 KB).
- **Cumplimiento de Protocolo:** Utiliza `multipart/form-data` estándar sin transferencias anómalas por chunked ni streaming indefinido.
- **Resistente a Honeypots y Prompt-Injection:** Cabeceras y cuerpos HTTP entrantes son filtrados por heurísticas regex estrictas ([`anti_injection.py`](anti_injection.py)) para neutralizar ataques de inyección indirecta en flujos asistidos por LLM/IA.
- **Compuertas de Seguridad Integradas:**
  - Objetivos locales y en redes privadas RFC 1918 requieren el consentimiento explícito `--local`.
  - Objetivos públicos externos exigen `--authorized` confirmando autorización por escrito.
  - Soporta inspección pasiva sin tráfico de red mediante `--dry-run`.

---

## 2. Arquitectura de Archivos

```text
tooling/checker/
├── README.md           # Documentación en inglés
├── README.es.md        # Documentación en español
├── config.yaml         # Tiempos de espera, versiones parchadas y ponderación de riesgos
├── checker.py          # Orquestador CLI principal y cálculo de postura
├── fingerprint.py      # Detección pasiva de servidor, SAPI y versión de PHP
├── session.py          # Prueba no destructiva de session.use_strict_mode
├── network.py          # Sonda mínima de multipart y upload_progress (<500 bytes)
├── anti_injection.py   # Sanitizador heurístico contra payloads maliciosos en cabeceras
├── report.py           # Exportador de reportes sanitizados en JSON y Markdown
└── test_checker.py     # Suite de pruebas unitarias
```

---

## 3. Matriz de Diagnóstico y Veredictos

| Comprobación | Peso | Condición Mitigada | Condición Expuesta |
|---|---|---|---|
| **Motor PHP Parchado** | 25% | Versión >= `8.4.27`, `8.3.36`, `8.2.35`, `8.5.12` | Rama de versión vulnerable |
| **Modo de Sesión Estricto** | 25% | `session.use_strict_mode = 1` (regenera SIDs arbitrarios) | `session.use_strict_mode = 0` (acepta SIDs arbitrarios) |
| **Alcance de Upload Progress** | 20% | Deshabilitado o bloqueado por el servidor web / SAPI | Multipart upload progress aceptado con HTTP 200 |
| **Límites de Proxy / Cuerpo** | 20% | Restricciones estrictas de tamaño de cuerpo activas | Sin límites visibles de tamaño |
| **Modelo de Despliegue SAPI** | 10% | SAPI aislado con ciclo de vida de workers por defecto | Configuración permisiva de manejadores |

### Veredictos de Postura

- **`EXPOSED`**: Ejecuta una versión vulnerable con upload progress activo y sesiones no estrictas.
- **`PARTIALLY_EXPOSED`**: Versión vulnerable pero cuenta con mitigaciones arquitectónicas clave (`use_strict_mode = 1`).
- **`MITIGATED`**: Ejecuta una versión parchada o tiene `session.upload_progress.enabled = 0`.
- **`INCONCLUSIVE`**: Backend no PHP, cabeceras ofuscadas o información insuficiente.

---

## 4. Instalación y Uso Rápido

Requiere Python 3.9+ y las librerías `requests` y `PyYAML`:

```bash
pip install requests pyyaml
```

### Ejemplos de Auditoría

```bash
# Diagnóstico contra un endpoint de desarrollo local
python3 tooling/checker/checker.py --url http://127.0.0.1:8080/ --local --verbose

# Auditoría autorizada exportando reporte en JSON y Markdown
python3 tooling/checker/checker.py --url https://example.com/test.php --authorized --json resultado.json --md resultado.md
```
