# Laboratorio: arnés de medición reproducible

[English](README.md) · [Español](README.es.md)

---

Código de medición y verificación de la investigación php2shell. Este directorio contiene el
arnés que produjo los números de [`../EVIDENCE.es.md`](../EVIDENCE.es.md) y las matrices de
[`../validation/`](../validation/): sondas de geometría del heap, oráculos del asignador, barridos
de ASLR, parsers de fuga por cookie, las configuraciones de laboratorio (`php.ini`, Apache, FPM)
y la suite unitaria que fija la aritmética.

**No** es un framework de explotación. Los módulos operativos (C2, exfiltración, evasión de WAF,
forjadores de payload, anti-forense, escáner multiobjetivo y el orquestador unificado) no se
distribuyen aquí. Las copias de los módulos de cadena se incluyen como referencia y para tests
unitarios; degradan a no-op cuando falta el paquete `forge`, por lo que desde este directorio no
se puede ejecutar una cadena remota de extremo a extremo tal como se publica.

Úsese solo contra contenedores desechables en loopback. Ningún generador de peticiones de este
directorio es seguro contra un host de producción: los cuerpos multipart exceden
intencionalmente `memory_limit` y abortan workers.

## Estructura

| Ruta | Qué es |
|---|---|
| `configs/` | Apache prefork de un worker, `php.ini` (perfiles On/Off), configs de FPM + nginx y el webroot del laboratorio |
| `scripts/` | Sondas y scripts de medición: calentamiento de heap, sostenimiento de workers, volcados de fuga de etapa 1, oráculo bin-128, barrido de residuo de página, diferenciales de ramas corregidas, watchpoints GDB |
| `exploit/aslr/` | Aritmética de la ventana de ASLR, barrido de páginas y calibrador de offsets de FPM |
| `exploit/grooming/` | Oráculo de heap, oráculo del asignador, calentamiento y saturación de workers (medición) |
| `exploit/infoleak/` | Primitiva de fuga autónoma acotada, usada para medir la ventana, no para armamentizarla |
| `exploit/leak/` | Parser de fuga por cookie, extracción de la base del heap y clasificación de punteros |
| `exploit/recon.py` | Detección de SAPI, versión y ASLR; comparación de nivel de parche |
| `exploit/safety/` | Limitador de tasa y guardas de modo laboratorio (compuertas de IP privada / autorización) |
| `exploit/reporting/` | Captura de evidencia y registros estructurados de ejecución |
| `exploit/chains/` | Módulos de cadena de referencia; requieren el paquete `forge/` no distribuido para ejecutar |
| `exploit/encoding.py`, `payload_encoding.py`, `payload_wrappers.py`, `retry.py` | Utilidades de codificación y reintento usadas por las sondas |
| `tests/`, `exploit/tests/` | Suite unitaria; `147 passed, 4 skipped` tal como se publica |

## Ejecución de la suite unitaria

```bash
cd lab
python3 -m pytest tests/ exploit/tests/ -q
# 147 passed, 4 skipped
```

Los 4 saltos son los tests de cadena FPM/CLI: verifican los tamaños del payload forjado de
`ub_write`/`HashTable`, y los módulos `forge` no forman parte de este repositorio por decisión
explícita. El salto está declarado (`forge/ not distributed in the public lab`), no es un pase
silencioso.

## Reproducción de una medición

Los perfiles de laboratorio son los mismos que referencia `EVIDENCE.es.md`:

```bash
# par vulnerable / control en loopback
docker run -d --name php2shell-lab -p 18080:80 \
  -v "$PWD/configs/php.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$PWD/configs/apache.conf:/etc/apache2/conf-enabled/zz-lab.conf:ro" \
  php:8.4.26-apache

# barrido de geometría del heap (escribe las filas CSV que consume validation/)
python3 scripts/off_leak_e1.py --url http://127.0.0.1:18080/index.php --out out/e1.csv
```

Las sondas GDB requieren `CAP_SYS_PTRACE` y `--security-opt seccomp=unconfined`; el flujo con
build de depuración está en [`../tooling/labkit/README.es.md`](../tooling/labkit/README.es.md).

## Alcance y límites

- Las mediciones valen para los digests exactos de imagen listados en `EVIDENCE.es.md`. Otro
  build, asignador o kernel cambia la geometría.
- Bajo ASLR, el canal in-band de la cookie acota `libphp` a una ventana de ~1.88 MB pero no la
  fija; la vía FPM no expone fuga in-band alguna. Son límites medidos, no carencias de ajuste.
- El watchpoint de E-OOM en FPM se incluye porque es la evidencia del veredicto DoS/P3. El
  builder de payload y el bucle de ejecución automatizado no se incluyen, deliberadamente.

Términos de uso responsable en [`../SECURITY.es.md`](../SECURITY.es.md).
