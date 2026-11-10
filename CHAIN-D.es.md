# Cadena D, medida: el object store en el shutdown
[English](CHAIN-D.md) · [Español](CHAIN-D.es.md)


Una de las cadenas que circulan para estas CVE dice que el shutdown de la petición lee un
`EG(objects_store)` obsoleto que dejó una petición muerta a medio arranque, y que la siguiente
petición en el mismo worker puede consumirlo. Medimos ese paso. No se comporta así.

Este documento dice exactamente hasta dónde llega la medición, porque la afirmación vecina —el
arreglo de buckets de objetos liberado y reutilizado— es otra cosa y **no** se aborda aquí.

## Lo que se midió

`php:8.4.26-apache`, mod_php, prefork, 128M, un worker (pid 17), breakpoint en
`php_request_shutdown` (`main/main.c:1891`). Tres peticiones en ese mismo worker:

1. un GET de calentamiento → 200
2. un cuerpo chunked de 70 MB que muere al arrancar la petición con
   `Allowed memory size of 134217728 bytes exhausted` → 500
3. un GET después del OOM → 200, el worker sigue vivo

En el breakpoint, una observación por petición:

```
SHUTDOWN ob=0x7f1b30451000 top=1 size=1024 flh=-1 err=30719
0x7f1b30451000: 0x0000000000000000  0x0000000000000000
SHUTDOWN ob=0x7f1b30451000 top=1 size=1024 flh=-1 err=30719
0x7f1b30451000: 0x0000000000000000  0x0000000000000000
SHUTDOWN ob=0x7f1b30451000 top=1 size=1024 flh=-1 err=30719
0x7f1b30451000: 0x0000000000000000  0x0000000000000000
```

El puntero del store, el siguiente slot libre, la capacidad y la cabeza de la lista libre son
idénticos en las tres. `top=1` con el handle 0 reservado significa que no hay objetos vivos en el
shutdown, y las dos primeras entradas de buckets leen cero. `current_execute_data`, la cima y el
final de `vm_stack` también son idénticos.

O sea: la cabecera del object store en el shutdown es la misma, haya muerto o no la petición
durante el arranque. El encuadre de "store obsoleto que queda para la siguiente petición" no se
sostiene.

Transcripción: [`raw/chain-d-eg-shutdown.txt`](raw/chain-d-eg-shutdown.txt).

## Dónde se detiene esto

Dos límites, y pesan más que el resultado:

- Medimos la **cabecera del store y sus primeras entradas** de buckets, no el arreglo completo de
  1024.
- Las tres observaciones se hicieron con el store **vacío en el shutdown**. Una petición que llega
  al shutdown con objetos vivos es otro estado, y esta medición no dice nada de él.

## Lo que dice el trabajo de otros

El material publicado no afirma todo lo mismo, y la diferencia decide si sobrevive a esta
medición:

- **segfo** confirma un use-after-free de `object_buckets` con caída, y marca el RCE como no
  demostrado. Es el arreglo de buckets, no la cabecera del store: fuera de lo que medimos.
- **cookie-bakery** publica una cadena completa: OOM, un bucket marcado `IS_OBJECT`,
  `zend_objects_store_del`, un pivote por `free_obj`, ROP y `system`. Corre con ASLR apagado y su
  propia documentación pide leaks para funcionar bajo ASLR. Una cadena funcional con ASLR off y
  nuestro resultado de cabecera idéntica no están en conflicto: hablan de memoria distinta.
- **ikow** describe "stale `EG()` / object store" como RCE sin dependencias. El repositorio trae
  exploits de las cadenas A, B y C; el código de la D no está publicado ahí.
- El parche que reinicia `object_buckets` durante el shutdown es consistente con la variante de
  buckets. No es evidencia de una cabecera obsoleta.

## La conclusión

"Cadena D funciona porque `EG(objects_store)` está obsoleto" es la versión que no se sostiene. La
versión que vale la pena perseguir es el arreglo de buckets, que alguien ya llevó a código con
ASLR apagado y que necesita un leak para cruzar a ASLR encendido.

Es un resultado negativo sobre un paso concreto, publicado porque una matriz que solo lista
aciertos no es una matriz. También cambia nuestra propia fila de `UNSUPPORTED` a algo más
estrecho: no sostenido **como afirmación de store obsoleto**, con la variante de buckets
explícitamente abierta.
