# labkit: Réplica Instrumentada del Estudio del Allocator para `PS(id)`

[English](README.md) · [Español](README.es.md)

---

Este kit reproduce la medición de la Fase 2 publicada en `validation/`: dónde residen en memoria el identificador de sesión (`PS(id)`) y la tabla hash (`HashTable`) de sesión, y por qué la ventana de lectura de la cabecera `Set-Cookie` no puede alcanzar la `HashTable` bajo configuraciones con `display_errors=Off`.

**Uso exclusivo en laboratorio.** El Payload A es destructivo por diseño: aborta intencionalmente la petición con un error de memoria (OOM) dentro de `php_session_send_cookie()`. Ejecútelo únicamente contra contenedores desechables configurados para este propósito.

---

## Qué Hace

| Paso | Acción |
|---|---|
| 1 | Reinicia el contenedor (estado limpio del asignador Zend MM). |
| 2 | Asocia `psid_probe.gdb` al worker único. |
| 3 | Petición opcional de calentamiento (`warmup.py`). |
| 4 | Payload A (`make_payload_a.py`): agota los bins y páginas para abortar la codificación del ID. |
| 5 | Payload B (`b_forge.py`): reasigna el chunk liberado con una cabecera `zend_string` forjada de longitud 4000. |
| 6 | Lee el registro del probe, analiza las líneas `RESET`/`TRACK` y añade una fila al archivo CSV. |

El sondeo registra para cada petición:

```
RESET hit=N id=0x... len=... send=... chunk=0x... page=0x...
TRACK hit=N id=0x... ht=0x... ht_chunk=0x... ht_page=0x... delta=...
```

Donde `delta = ht - id` es la magnitud analizada. La cookie únicamente puede leer hacia adelante desde el puntero del id hasta el final de su chunk de 2 MiB (a lo sumo 8168 bytes desde el valor). Un delta negativo, o una ubicación en un chunk diferente, demuestra que la `HashTable` es inalcanzable.

---

## Prerrequisitos

1. **Compilación de depuración con símbolos de PHP.** La compilación de referencia es PHP 8.4.26 con Apache `apxs2`, 39 extensiones y `CFLAGS="-O2 -g3"`.
2. **Worker prefork único** (`apache-prefork.conf`). Ambas peticiones consecutivas deben ser atendidas por el mismo proceso.
3. **`CAP_SYS_PTRACE`** y perfil seccomp deshabilitado para permitir el attach de GDB:
   `docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ...`
4. **Archivo `php.ini` del laboratorio**: `display_errors=Off`, `memory_limit=8M`, `post_max_size=64M`, upload progress habilitado.

---

## Ejecución del Barrido

```bash
# 1. Comprobar el contenedor
./check_build.sh php2shell-lab

# 2. Medición calibrada (fila base_off en validation/)
python3 sweep.py \
    --container php2shell-lab \
    --url http://127.0.0.1:18080/index.php \
    --outdir out \
    --label base_off \
    --warmup 1500000 --S 63 --NB 235 --BL 15000 --X 208 --K 4 --KL 4000
```
