# Glossary

**ASLR** — Address Space Layout Randomization. Randomizes memory addresses to make code
execution harder.

**Bailout** — PHP's `zend_bailout()`/`longjmp` path used to abort execution on fatal errors. If
the unwind is incomplete, per-request state can survive in the worker.

**LFI** — Local File Inclusion. An application sink that includes a file path controlled by the
attacker.

**mod_php** — Apache module that embeds the PHP interpreter in the web server process.

**OOM** — Out of memory. PHP's allocator aborts the request when `memory_limit` is exceeded.

**PHPSESSID** — Default PHP session cookie/parameter name.

**POP gadget** — A class with magic methods (`__destruct`, `__wakeup`, `__unserialize`) that can
be chained through deserialization to perform an action.

**prefork** — Apache MPM that serves each connection in a separate child process. Worker state
persists across requests in the same child.

**PHP-FPM** — FastCGI Process Manager. A pool of PHP workers separate from the web server.

**Session upload progress** — PHP feature (`session.upload_progress.*`) that tracks multipart
uploads in the session. It runs during request startup, before application code.

**UAF** — Use-after-free. A memory-safety bug where a pointer is used after its allocation has
been released.

**Zend MM** — PHP's internal memory manager. Its chunk geometry influences what an OOB read can
reach.
