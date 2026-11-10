# Portabilidad: por qué la misma PoC da números distintos

Cada celda se midió en el mismo laboratorio — loopback, `php:8.4.26-apache`, tres intentos por
celda salvo que se indique — y responde una pregunta: qué condiciones **sí** condicionan la
cadena y cuáles solo lo parecen.

| Configuración | Resultado | Abortos |
|---|---|---|
| `display_errors=On`, `memory_limit=8M`, 1 worker | **8/8** | 32 (8 corridas) |
| `display_errors=Off`, `memory_limit=8M`, 1 worker | 0/3 | 12 |
| `On`, `512M`, 1 worker, campo de 12 MB | 0/3 | 0 |
| `On`, `512M`, 1 worker, campo de 480 MB | **1/1 PROOF** | 4 |
| `On`, `8M`, 4 workers, exploit estándar sin saturar | 0/3 | 0 |
| `On`, `8M`, 4 workers, saturación (retener N-1) | **6/6 PROOF** | 24 |
| `On`, `8M`, 8 workers, saturación (retener N-1) | **4/4 PROOF** | 16 |
| `On`, `8M`, 16 workers, saturación (retener N-1) | **3/3 PROOF** | 12 |
| `On`, `8M`, 4 workers, proxy nginx, buffering apagado, trickle, 64k | **3/3 PROOF** | 12 |
| `On`, `8M`, 4 workers, proxy nginx, **buffering encendido** | 0/1 | n/d |
| `On`, `8M`, 4 workers, **`KeepAlive On`** | 0/5 | 20 |
| `Off`, `8M`, 1 worker, build debug (primitivo A, oráculo bin-128) | **4/4 OOM-in-cookie** (NB=235, K=4) | n/d |
| `On`, `8M`, 1 worker, imagen oficial, ASLR encendido | **3/3 PROOF RCE** | ~12 |
| `Off`, `8M`, 1 worker, imagen oficial, warmup A+B, ASLR on/off | 15/15 cookie de 4000 B dentro de su ventana (12 on / 3 off); repetición controlada **0/3** — claim de estabilidad retirado | n/d |
| `Off`, `8M`, 1 worker, imagen oficial, ASLR **apagado**, direcciones fijas | **3/3 PROOF RCE** | n/d |
| `Off`, `8M`, 1 worker, imagen oficial, ASLR **encendido** | **0/3** — bloqueado por el leak de `libphp` | n/d |
| `On`, `8M`, 1 worker, kernel pve 7.0, ASLR encendido | 0/3 | n/d |

## Lo que dice la matriz

1. **`memory_limit` no es el candado: lo es `post_max_size`.** Con 512M/480 MB la cadena corre
   igual, porque el cuerpo cabe; con los defaults 128M/8M el A de 3.7 MB no agota la memoria y
   el primitivo no arranca. La fila 512M/480 MB es una configuración no-default (del tipo que
   corre un Nextcloud) y es con `display_errors=On`.
2. **`display_errors=Off` bloquea exactamente una cosa: el leak de `libphp`.** El primitivo A y
   el `chunk_base` sobreviven; lo que desaparece es el puntero que convierte una escritura en
   heap en un destino de código.
3. **En prefork, saturar workers es obligatorio.** Sin retener a los otros hijos, el OOM cae en
   un hijo que no es el que llevará la siguiente petición y la cadena muere en 0/3. Reteniendo
   `N-1` sale 6/6, 4/4 y 3/3 con 4, 8 y 16 workers.
4. **Un proxy tiene que dejar de bufferear.** Con buffering apagado y entrega por goteo la
   cadena sobrevive; con buffering encendido no, porque la conexión nunca queda en el estado que
   el OOM necesita.
5. **`KeepAlive On` la rompe**: 0/5. Es la mitigación más barata de la matriz y no está en PHP.
6. **Una corrida suelta no prueba nada.** La fila 15/15 fue el claim retirado de la cookie:
   dentro de su ventana reproducía, en repetición controlada dio 0/3. Cada número marcado
   `PROOF` viene de una celda repetida hasta estabilizarse.

Esta es la respuesta a "por qué la PoC pública funciona en mi máquina y en la tuya no": la
diferencia suele ser el pool de workers, el buffering del proxy o `KeepAlive`, no el build de PHP.

## Procedencia

Cada celda se midió en el laboratorio descrito en `METHODOLOGY.md`. Las filas que solo necesitan
el checker y las imágenes oficiales se reproducen con `make up`; las de saturación de workers,
proxy y `KeepAlive` se condujeron con secuencias de peticiones que llevan los cuerpos operativos,
así que esas transcripciones se quedan en el registro privado del laboratorio y no en este
repositorio. Las filas de 9bie tienen sus barridos en `raw/9bie-aslr-on-8run.txt`,
`raw/9bie-aslr-off-5run.txt` y `raw/9bie-display-off-3run.txt`.

Si un número no se reproduce en tu host, revisa en este orden el pool de workers, el modo de
buffering del proxy y `KeepAlive`: es el orden en que rompen la cadena.
