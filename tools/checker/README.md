# php2shell-checker: Diagnostico Defensivo No Destructivo

Herramienta de diagnostico y auditoria de postura para servidores PHP y arquitecturas web, orientada a evaluar la susceptibilidad frente a condiciones requeridas por cadenas documentadas (tales como php2shell) sin enviar payloads daninos, sin provocar consumo anomalo de memoria (OOM) y sin realizar tecnicas de heap grooming.

---

## 1. Principios Operativos y Garantias Defensivas

- **Estrictamente No Destructivo:** No inyecta codigo, no ejecuta comandos y no altera el estado del servidor.
- **Trafico Minimo:** Realiza un maximo de 3 peticiones HTTP(S) inocuas por analisis.
- **Tamano Acotado:** El volumen de datos transmitido es inferior a 10 KB (tipicamente menor a 1 KB).
- **Sin Transfer-Encoding Anomalo:** No utiliza peticiones chunked infinitas ni patrones de saturacion.
- **Sanitizacion Integral:** Los identificadores de sesion (`PHPSESSID`), tokens y rutas internas son ofuscados mediante hashes criptograficos en los reportes resultantes.
- **Compuertas de Seguridad Obligatorias:**
  - Los destinos locales o de red privada (RFC 1918, `127.0.0.1`, `localhost`) exigen la bandera explicita `--local`.
  - Los destinos externos requieren la bandera `--authorized` confirmando autorizacion formal escrita.

---

## 2. Arquitectura de Modulos

```text
tools/checker/
├── README.md           # Documentacion tecnica, limites y alcance
├── config.yaml         # Parametros de timeout, versiones parcheadas y pesos
├── checker.py          # Orquestador CLI, compuertas de seguridad y scoring
├── fingerprint.py      # Inspeccion pasiva de cabeceras (Server, X-Powered-By, SAPI)
├── session.py          # Comprobacion de session.use_strict_mode con SID inocuo
├── network.py          # Verificacion multipart inocua de upload_progress y limites
├── report.py           # Generador de reportes sanitizados en JSON y Markdown
└── examples/           # Ejemplos de reportes para escenarios mitigados y expuestos
```

### Detalle de Funciones
1. **`fingerprint.py`**:
   - Inspecciona cabeceras `X-Powered-By`, `Server`, `Via` y `X-Backend-Server`.
   - Compara versiones semanticas contra las versiones minimas parcheadas (`8.4.27`, `8.3.36`, `8.2.35`, `8.5.12`).
   - Deduce el tipo de SAPI (PHP-FPM tras proxy inverso vs Apache `mod_php`).
2. **`session.py`**:
   - Evalua si `session.use_strict_mode` esta habilitado (`1`) o deshabilitado (`0`).
   - Envia una peticion GET con `Cookie: PHPSESSID=checker_probe_<rand>`.
   - Si el servidor emite un `Set-Cookie` con un nuevo identificador criptografico, strict_mode esta activo. Si acepta el SID o no fuerza renovacion, se clasifica la condicion de exposicion.
3. **`network.py`**:
   - Envia un formulario `multipart/form-data` minimo (< 500 bytes) conteniendo el parametro `PHP_SESSION_UPLOAD_PROGRESS=checker_probe_marker` y un archivo ficticio de 20 bytes.
   - Observa si el backend procesa formularios multipart o si el proxy frontal impone restricciones inmediatas (HTTP 413, 405).
4. **`checker.py`**:
   - Valida compuertas de seguridad de red.
   - Orquesta la ejecucion en secuencia con timeouts reducidos (por defecto 5 segundos).
   - Calcula la exposicion segun la matriz defensiva ponderada y emite el veredicto final.
5. **`report.py`**:
   - Genera salidas en JSON y Markdown estructurado, sin emojis y con datos sanitizados.

---

## 3. Matriz de Puntuacion Defensiva

| Factor Evaluado | Peso | Condicion Mitigada (0%) | Condicion Expuesta (100%) |
|---|---|---|---|
| **Version PHP** | 25% | >= 8.4.27, 8.3.36, 8.2.35, 8.5.12 | Versiones anteriores a los parches |
| **`session.use_strict_mode`** | 25% | Activo (`1`): genera nuevo SID | Inactivo (`0`): acepta SID arbitrario |
| **`session.upload_progress`** | 20% | Inactivo o bloqueado (405, 413) | Activo y acepta multipart con upload_progress |
| **Limites Proxy / Cuerpo** | 20% | Limites estrictos detectados (413) | Sin limites aparentes en probe reducida |
| **Arquitectura SAPI** | 10% | mod_php parcheado o FPM mitigado | FPM o mod_php expuesto sin barreras |

### Veredictos Posibles
- **`MITIGATED`** (Indice < 26%): El sistema implementa controles defensivos adecuados y versiones al dia.
- **`PARTIALLY_EXPOSED`** (Indice 26% - 50%): Existen configuraciones permisivas parciales (ej. upload_progress activo o version desactualizada, pero con strict_mode habilitado).
- **`EXPOSED`** (Indice >= 51%): Se conjugan multiples factores favorables a las cadenas de ataque (version vulnerable, strict_mode deshabilitado, upload_progress habilitado).
- **`INCONCLUSIVE`**: El servidor no revelo cabeceras PHP o no fue posible contrastar el comportamiento de sesiones.

---

## 4. Requisitos y Uso

### Requisitos
- Python 3.10 o superior.
- Librerias: `requests`, `pyyaml`.

```bash
pip install requests pyyaml
```

### Sintaxis de Linea de Comandos

```bash
python3 checker.py --url <URL> [opciones]
```

#### Opciones Disponibles
- `--url <URL>`: URL base del objetivo (ej. `http://127.0.0.1:8080/` o `https://lab.internal/`).
- `--local`: Autoriza explícitamente el escaneo contra localhost, loopback (`127.0.0.1`) o redes privadas (RFC 1918).
- `--authorized`: Declaracion formal de autorizacion expresa para objetivos externos.
- `--dry-run`: Imprime las peticiones que se enviarian sin emitir trafico de red.
- `--timeout <SEG>`: Tiempo limite de espera por peticion (por defecto: 5s).
- `--config <RUTA>`: Especifica un archivo `config.yaml` alternativo.
- `--json <ARCHIVO>`: Exporta el resultado en formato JSON sanitizado.
- `--md <ARCHIVO>`: Exporta el reporte en formato Markdown.

---

## 5. Ejemplos de Ejecucion

### Simulacion Dry-Run
```bash
python3 checker.py --url http://127.0.0.1:8080/ --local --dry-run
```

### Auditoria de Laboratorio Local con Exportacion
```bash
python3 checker.py \
  --url http://127.0.0.1:8080/ \
  --local \
  --json report-local.json \
  --md report-local.md
```

### Auditoria de Sistema Externo Autorizado
```bash
python3 checker.py \
  --url https://app.empresa.example/ \
  --authorized \
  --timeout 4 \
  --md report-externo.md
```

---

## 6. Remediacion General

Para mitigar los factores evaluados por esta herramienta en entornos PHP:

1. **Actualizacion de Motor PHP:**
   Actualizar a las versiones minimas que incorporan mitigaciones: PHP 8.4.27, 8.3.36, 8.2.35 u 8.5.12.
2. **Habilitar Strict Mode en Sesiones:**
   En `php.ini`:
   ```ini
   session.use_strict_mode = 1
   ```
3. **Deshabilitar Upload Progress si no se utiliza:**
   En `php.ini`:
   ```ini
   session.upload_progress.enabled = 0
   ```
4. **Acotar Limites de Peticion en Proxy Inverso:**
   - En Nginx: `client_max_body_size 8M;`
   - En Apache: `LimitRequestBody 8388608`
