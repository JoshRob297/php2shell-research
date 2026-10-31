# fpm_chain_e_probe.gdb - observacion de la cadena E en FPM (PHP 8.4.26 con simbolos)
#
# Requiere un build con simbolos (-O1 -g3) y ASLR deshabilitado en el contenedor
# (setarch -R), para que las direcciones sean estables por generacion de worker.
#
# Uso:
#   1. Ejecutar el productor (decode OOM de una sesion de ~28 MB).
#   2. Leer d y la direccion del bloque dtor:
#        gdb -p <pid> -batch -ex 'p/x basic_globals.unserialize.data' \
#            -ex 'p/x ((void**)basic_globals.unserialize.data)[2]'
#   3. Ajustar $d y $dtor abajo y correr:
#        gdb -p <pid> -batch -x fpm_chain_e_probe.gdb
#   4. Lanzar el consumer (POST multipart con PHP_SESSION_UPLOAD_PROGRESS).
#
# Evidencia esperada: el primer write sobre d+0x38 viene del allocator
# (zend_mm_alloc_small_slow, bswap de un puntero de free-list), y var_push
# escribe fuera de mapa -> SIGSEGV.

set pagination off
set confirm off

set $d = 0x7ffff6264000
set $dtor = 0x7ffff6267000

printf "d=%p dtor=%p\n", $d, $dtor

# Estado del struct colgante antes del consumer
x/6gx $d
x/4gx $dtor

# used_slots (d+0x38): quien escribe y con que valor
watch *(long long*)($d+0x38)
commands
  silent
  printf "W38: new=%p pc=%p\n", *(void**)($d+0x38), $pc
  bt 2
  continue
end

# crash: registros + backtrace
handle SIGSEGV stop print nopass
continue
printf "SEGV pc=%p\n", $pc
info registers rax rdx rsi rdi
x/28gx $d
bt 8
detach
