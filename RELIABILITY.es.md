# Fiabilidad — cuántas veces dispara de verdad
[English](RELIABILITY.md) · [Español](RELIABILITY.es.md)


Una corrida exitosa no es un resultado. Estas son las condiciones que deciden si la cadena con
`display_errors=Off` y ASLR encendido dispara o no, y con qué frecuencia, medidas sobre targets
nuevos.

## Geometría: 128M y `php.ini-production`, o nada

La cadena `pure/` del upstream está calibrada para la geometría stock: `memory_limit=128M`, el
`php.ini-production` oficial y el pool de workers tal como lo trae la imagen.

- 128M, un worker, imagen oficial → **3/3**
- 8M, un worker, misma imagen → **0/3**

El fallo a 8M es **calibración, no el disparador**. A1 sí dispara a 8M: nuestra cadena anterior
da **8/8** ahí con `display_errors=On` (ver `PORTABILITY.es.md`). Lo que se rompe son la
aritmética de offsets y la ventana del leak, ambas dimensionadas para la arena de 128M.

Esto importa porque circula la frase de que bajar `memory_limit` no ayuda, porque el atacante
dimensiona el OOM al límite que haya. **Las dos afirmaciones son ciertas y hablan de cadenas
distintas.** En la cadena de cookie de mod_php el atacante elige el tamaño del cuerpo y el
límite no lo frena. En la cadena `pure/` del upstream las constantes están fijas para 128M, así
que un target de 8M falla por una razón que no tiene nada que ver con el control del cuerpo.

## El `php.ini` del target decide más que la versión

Nuestro propio `tooling/docker-compose.yml` **no** reproduce el 10/10. El servicio `vuln-8426` no
carga ningún `php.ini`:

```
Loaded Configuration File => (none)
display_errors => STDOUT
```

Añadir `display_errors=Off` encima de `hardening-off.ini` da **0/3**, porque eso es un overlay de
`conf.d`, no `php.ini-production`. La cadena necesita el archivo que trae la imagen, no una
directiva que se le parezca.

## El arranque en frío no está caracterizado

Target nuevo, primera corrida: **0/3**, con `no heap pointers in leak window`. El mismo target
tras `docker restart`: **3/3**. El resultado de diez corridas en
`raw/9bie-pure-off-aslr-on-10run.txt` reinicia el target antes de cada corrida exactamente por
esto.

No hemos caracterizado el fallo de la primera corrida: puede ser calentamiento del pool, estado
del allocator o residencia de páginas. Es una incógnita conocida, escrita en vez de promediada.

## Lo que no está medido

- **FPM**: el brazo E-OOM es `LAB ONLY` y está en `CHAIN-E.es.md`. Sin resultado remoto con ASLR
  encendido.
- **CVE-2026-115560**: sin arreglo estable al momento de escribir; nuestro intento fue
  inconcluso.
- **Carga sostenida**: todas las corridas son de segundos a minutos. Nada de aquí dice nada sobre
  el comportamiento tras horas de carga.

Si un número de este repositorio no está en este archivo ni en una transcripción de `raw/`, no es
una medición: es una cita.
