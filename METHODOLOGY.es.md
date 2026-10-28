# Metodología de Investigación

[English](METHODOLOGY.md) · [Español](METHODOLOGY.es.md)

---

## Entorno de Laboratorio

Todos los experimentos fueron ejecutados en interfaces loopback sobre contenedores desechables e imágenes oficiales de PHP en Docker Hub. Ningún sistema en producción fue tocado. Las cadenas a nivel de petición fueron ejercitadas con un arnés de PoC en pools PHP-FPM monohilo; la cadena OOM/RCE fue validada contra imágenes oficiales `php:8.4.26-apache` y `php:8.4.27-apache` en un pool de workers prefork.

El estado de ASLR fue controlado mediante `setarch x86_64 -R` únicamente en ejecuciones con ASLR desactivado por proceso. Se utilizó una compilación de depuración con idénticos flags de configuración para introspección de símbolos; las imágenes oficiales no exponen símbolos internos para calibración estática.

## Despliegue Aplicativo

Se empleó una **instancia de prueba de Nextcloud 33.0.x** corriendo **PHP 8.4.21 bajo Apache `mod_php` prefork** para validar la exposición de configuración y el nivel de parche. La prueba de RCE se obtuvo sobre la imagen oficial `php:8.4.26-apache`, no ejecutando el exploit contra el entorno de Nextcloud. Esta distinción es fundamental: el fallo ocurre en el inicio de la petición de PHP (`request startup`), antes del código de la aplicación. Por tanto, el nombre de la aplicación no es la primitiva; la arquitectura SAPI, el modelo de workers, los límites de cuerpo, las directivas de sesión y el camino de red definen la verdadera alcanzabilidad.

## Flujo de Trabajo Asistido por IA

Esta investigación se llevó a cabo integrando modelos de IA y subagentes especializados bajo estricta dirección humana:

- Un modelo orquestador central para planificación, seguimiento de evidencia y revisión final.
- Subagentes para revisión de literatura, auditoría de PoCs públicas, análisis estático diferencial de código fuente, orquestación de laboratorio y comprobación documental.
- Re-verificación independiente de conclusiones de alto impacto con modelos analíticos alternativos.

Las salidas de los modelos fueron tratadas como hipótesis de trabajo, nunca como evidencia válida por sí mismas. Cada hallazgo documentado en este repositorio está respaldado por comandos ejecutados, respuestas HTTP crudas, volcados de GDB o referencias al código fuente oficial de PHP. Las afirmaciones no reproducibles quedaron catalogadas como hipótesis, limitaciones o no concluyentes. Ninguna IA figura como autor; la autoría humana corresponde a **JoshRob**.

## Reglas de Evidencia

- Ningún hallazgo existe sin comando, petición, registro de logcat/GDB o línea de código fuente exacta.
- Resultados exclusivos de laboratorio se etiquetan explícitamente como tales.
- Las afirmaciones de PoCs públicas se separan estrictamente de mediciones independientes reproducibles.
- Las versiones de software, SAPI, directivas clave de `php.ini` y el estado de ASLR se registran con cada prueba.
- Prohibida la redistribución de código ejecutable armamentizado de terceros.

## Criterios de Reproducibilidad

La primitiva a nivel del motor PHP es reproducible en imágenes oficiales bajo las configuraciones documentadas. La explotabilidad no es universal: depende de la arquitectura del SAPI (`mod_php` prefork vs PHP-FPM), cantidad de workers, directiva `session.upload_progress`, relación entre `memory_limit` y `post_max_size`, estado de ASLR, diseño del asignador y del kernel, flags del binario y presencia de proxies o WAFs. La PoC pública de evasión de ASLR funcionó en un host y falló en otro. Las cadenas A/C/E dependen además de fallos aplicativos previos (LFI, desajuste de serializadores por directorio o capacidad de escritura local).

No debe interpretarse "vulnerabilidad a nivel de PHP" como "todo despliegue PHP es explotable con la misma PoC". Debe interpretarse como: "el código aplicativo no es la causa raíz; las condiciones de arquitectura del despliegue determinan si la primitiva de memoria es alcanzable y explotable de forma fiable".
