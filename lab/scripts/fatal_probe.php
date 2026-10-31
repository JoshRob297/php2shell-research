<?php
/*
 * fatal_probe.php - triggers de error fatal con presion de memoria controlada.
 *
 * Lanzar en el webroot del laboratorio. Dos modos:
 *
 *   ?n=<bytes>   str_repeat de n bytes y luego funcion indefinida (fatal).
 *                Con n > memory_limit el OOM ocurre dentro de str_repeat.
 *   ?k=<bytes>   llena con asignaciones de 1 KB hasta memory_limit - k y luego
 *                funcion indefinida. Barre la frontera donde el fetch del
 *                backtrace puede quedarse sin memoria.
 *
 * Uso tipico (php.ini con memory_limit=32M y fatal_error_backtraces=1):
 *   curl 'http://127.0.0.1:PORT/fatal_probe.php?n=33000000'
 *   curl 'http://127.0.0.1:PORT/fatal_probe.php?k=8000'
 */

$limit = ini_get('memory_limit');
$bytes = (int)$limit * 1024 * 1024;

if (isset($_GET['k'])) {
    $k = (int)$_GET['k'];
    $chunks = [];
    while (memory_get_usage(true) < $bytes - $k) {
        $chunks[] = str_repeat("A", 1024);
    }
} else {
    $n = (int)($_GET['n'] ?? 0);
    $buf = str_repeat("A", $n);
}

missing_func_php2shell();
