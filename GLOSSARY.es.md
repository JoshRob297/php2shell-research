# Glosario Técnico

[English](GLOSSARY.md) · [Español](GLOSSARY.es.md)

---

**ASLR** — *Address Space Layout Randomization*. Técnica de seguridad del sistema operativo que aleatoriza las direcciones base de memoria para dificultar la ejecución arbitraria de código.

**Bailout** — El mecanismo interno de PHP (`zend_bailout()` / `longjmp`) utilizado para abortar la ejecución ante errores fatales o límites de memoria. Si el desenrollado de estado (`unwind`) es incompleto, variables globales por petición pueden sobrevivir en el worker.

**LFI** — *Local File Inclusion*. Vulnerabilidad en la aplicación web que permite a un atacante incluir y ejecutar archivos locales controlados dentro del servidor.

**mod_php** — Módulo de Apache que incrusta el intérprete de PHP directamente dentro del proceso del servidor web.

**OOM** — *Out Of Memory*. Condición en la cual el asignador de PHP aborta la petición al superarse la directiva `memory_limit`.

**PHPSESSID** — Nombre por defecto de la cookie o parámetro identificador de sesión en PHP.

**POP gadget** — Clase PHP que implementa métodos mágicos (`__destruct`, `__wakeup`, `__unserialize`) susceptible de encadenarse mediante deserialización de objetos para ejecutar código.

**prefork** — Módulo de multiprocesamiento (MPM) de Apache que atiende cada conexión en un proceso hijo independiente. El estado del worker persiste entre peticiones dentro del mismo hijo.

**PHP-FPM** — *FastCGI Process Manager*. Arquitectura que ejecuta un pool de workers PHP aislados e independientes del servidor web (Nginx/Apache) comunicados mediante sockets FastCGI.

**Session upload progress** — Característica nativa de PHP (`session.upload_progress.*`) que rastrea subidas multipart dentro de la sesión. Se ejecuta durante el inicio de la petición (`request startup`), antes de cualquier lógica de la aplicación.

**UAF** — *Use-After-Free*. Fallo de seguridad de memoria donde un puntero es referenciado o desreferenciado después de que su bloque asignado ha sido liberado por el asignador.

**Zend MM** — *Zend Memory Manager*. Asignador interno de memoria de PHP. Su geometría de chunks (páginas de 2 MiB, bins y free-lists) determina qué estructuras pueden ser alcanzadas por sobrelecturas fuera de límites (OOB).
