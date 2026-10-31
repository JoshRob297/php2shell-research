# backtraces_8511_probe.gdb - brazo fatal_error_backtraces (PHP 8.5.11 con simbolos)
#
# Verifica el estado de EG(last_fatal_error_backtrace) durante el manejo de un
# error fatal con fatal_error_backtraces=1.
#
# Uso:
#   gdb -p <pid> -batch -x backtraces_8511_probe.gdb
#   mientras corre: curl 'http://host/fatal_probe.php?n=<bytes>' con n mayor
#   que memory_limit (OOM real) para forzar el fetch durante la exhaustion.
#
# Lectura esperada (8.5.11):
#   - antes del fetch: type=0 (UNDEF) con un value residual (guarda Z_ISUNDEF)
#   - despues del fetch: type=0x307 (IS_ARRAY_EX) con HashTable valida
#   - zend_trace_to_string recibe esa HashTable desde php_error_cb (main.c:1390)
#   - bailout normal de E_ERROR (main.c:1540); sin estado parcial ni UAF.

set pagination off
set confirm off

break zend_fetch_debug_backtrace
commands
  silent
  printf "FETCH entry:\n"
  x/2gx &executor_globals.last_fatal_error_backtrace
  continue
end

break php_error_cb
commands
  silent
  printf "ERRCB:\n"
  x/2gx &executor_globals.last_fatal_error_backtrace
  bt 3
  continue
end

break zend_trace_to_string
commands
  silent
  printf "TRACE ht=%p\n", $rdi
  bt 3
  continue
end

continue
