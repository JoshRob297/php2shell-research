# Cadena E — la ruta FPM, medida
[English](CHAIN-E.md) · [Español](CHAIN-E.es.md)


La cadena E es el brazo PHP-FPM del primitivo E-OOM: un fallo de memoria al deserializar deja
`BG(unserialize)` en `level=1` con el puntero `data` colgando, el siguiente decode lo reutiliza,
y una escritura controlada de 16 bytes aterriza en `&sapi_module.ub_write`, que se sustituye por
`&system`.

**Es un resultado de laboratorio, no una capacidad remota.** Bajo ASLR por defecto es una
denegación de servicio determinista (caída del worker, 502). La ejecución de comandos exige ASLR
apagado o bases ya conocidas, más una sesión plantada de 24 bytes. Todo lo de abajo es lo que
medimos, incluidas las rutas que no funcionaron.

Este documento publica el layout y los números. No publica el orquestador: el código que
tenemos es un fragmento que no corre sin nuestro arnés, y uno de sus constructores acepta una
dirección que nunca usa. Publicarlo como "cadena pública" sería publicar algo que no corre.

## La escritura

Un `var_dtor_entries` falso vive en el buffer de un campo multipart. El bucle del destructor lo
recorre y escribe una entrada por iteración, así que el desplazamiento de aterrizaje lo fija el
conteo de entradas:

```
T2 = d + 0x110 + 16·N          N = (T2 − d − 0x110) / 16
```

`T2` es `&sapi_module.ub_write`. `d` es la dirección del struct reclamado. Si
`(T2 − d − 0x110)` no es múltiplo de 16, la cadena no puede aterrizar: el constructor falla en
vez de desalinear en silencio.

Desplazamientos dentro del buffer falso de 12,300 bytes, medidos:

- `0x1000` — `entries.last` = `d + 0x38`
- `0x1008` — `entries.first_dtor` = `0`
- `0x1010` — `last_dtor` = `d + 0x100`
- `0x1038` — `entries.used_slots` = `0`
- `0x1100` — `fake.used_slots` = `N`
- `0x1108` — `fake.next` = `0`

## La sesión plantada: 24 bytes, y el contenido importa

La sesión debe medir **exactamente 24 bytes**, con la forma:

```
C|i:<V>;AAAA
```

Los dos hechos están medidos, no supuestos:

- `hello|i:<V>;` —también 24 bytes— **rompió el layout**. El arena de strings internados corrompe
  el struct `d` antes de la escritura, y el proceso muere con SEGV en `tmp_var` (solo visible
  con `WATCH`).
- La cola `AAAA` dispara un `cancel_decode` benigno. La escritura ya ocurrió en el primer par,
  así que el aviso es cosmético.

## La desincronización posterior al exec

Secuestrar `ub_write` rompe el contrato de salida del motor. PHP espera que `ub_write` devuelva
el número de bytes escritos; `system()` devuelve el estado de salida de la subshell, así que la
capa SAPI ve `rax = 0`, llama a `php_handle_aborted_connection` y el cliente recibe un 502.

El payload tiene que desacoplar: `foo; (cmd; kill -TERM $$) >/dev/null 2>&1 &`. El comando corre
en una subshell, el worker dañado se recicla y la respuesta puede morir.

## Rutas que no funcionaron

Todas fueron medidas y cerradas:

- **`PS(serializer)->decode = &system`** — la escritura aplasta `http_session_vars` en `+8`, da
  `Z_REFVAL(0x4)` y SEGV antes del segundo decode.
- **`GOT(memchr)` = `0x1600c38`** — `mod 16 = 8`, inalcanzable con slots alineados a 16.
- **Gadget `lea/mov 0x18(%rcx),%rdi; jmp exec`** — no existe en el binario. Tampoco importa
  `system`: solo `popen` / `posix_spawn` / `fork`, y `popen` exige un modo válido en `rsi`.
- **Regla re2c `"i:" iv ";"`** — verificada en fuente: el `;` es parte de la regla. `i:<V>` sin
  `;` no escribe el LONG.
- **Barrido de páginas ASLR** — ver abajo. No existe como mecanismo en nuestras herramientas.

## El barrido, medido

Teníamos un módulo llamado `aslr_sweep`, descrito como barrido determinista de páginas para FPM
remoto. Valía la pena comprobarlo, porque si funcionaba el veredicto `LAB ONLY` estaba mal.

No funciona, y estructuralmente no puede: la petición que envía es `{"page": N}` como form data,
sin cuerpo forjado y sin aritmética de direcciones. Nunca intenta un aterrizaje.

Peor: su criterio de éxito coincidía con `"OK"` en el cuerpo de la respuesta
independientemente del `marker` que se le pasara, así que contra una página que imprime `OK`
reporta éxito en la página 0.

Medido el 2026-11-09, `phpdebug:8.4.26-fpm` con `pm = static`, un worker, detrás de nginx,
`randomize_va_space = 2`:

- con el criterio del propio código: `success = True`, página 0, 0.01 s, una petición — falso
  positivo, nada se ejecutó
- con criterio estricto (`uid=` y `gid=` obligatorios): **387 páginas, 387 respuestas 200, 0
  aciertos, 0.34 s, 0 caídas**, la página sigue sirviendo, ningún payload construido

Transcripción: [`raw/chain-e-aslr-sweep-387.txt`](raw/chain-e-aslr-sweep-387.txt).

## Qué significa

`LAB ONLY` se sostiene, y ahora está cerrado por los dos lados: el bloqueo de fragmentación
bin-16 que ya teníamos, y la ausencia de cualquier barrido que lo sortee.

Si estás leyendo esto para reproducir: necesitas ASLR apagado o bases conocidas, una sesión de
exactamente 24 bytes con la forma de arriba plantada bajo el id de la víctima, una página que
llame a `session_start()`, y un worker que no se recicle entre las dos peticiones. Sin las
cuatro, esto es un 502.
