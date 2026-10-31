#!/usr/bin/env bash
# verify_fixed_branches.sh - verificacion de la clase OOM/state-corruption en ramas fijadas
# (8.5.12, 8.3.36, 8.2.35) contra el molde de 8.4.26/8.4.27.
#
# Monta un contenedor apache+mod_php por version con la config del lab (prefork de 1 worker,
# display_errors=On, memory_limit=8M, upload_progress On) y corre los dos perfiles de la
# cadena OOM:
#   A) display_errors=On, ASLR on   -> esperado 0/N en todas las fijadas
#   B) display_errors=Off, ASLR off -> ejecutar el exploit (9bie) contra cada una
#
# Uso:
#   ./verify_fixed_branches.sh <dir_pocs_privado> <perfil:on|off>
#
# Requisitos: docker, imagenes php:8.4.26-apache, php:8.4.27-apache, php:8.5.12-apache,
# php:8.3.36-apache, php:8.2.35-apache, y el repo de 9bie clonado junto al privado.

set -u
POCS="${1:?dir del repo privado}"
PROFILE="${2:-on}"
PORT=18110

declare -A IMG=(
  [8426]="php:8.4.26-apache"
  [8427]="php:8.4.27-apache"
  [8512]="php:8.5.12-apache"
  [8336]="php:8.3.36-apache"
  [8235]="php:8.2.35-apache"
)
ORDER=(8426 8427 8512 8336 8235)

if [ "$PROFILE" = "off" ]; then
  INI="$POCS/configs/display_errors_off/php.ini"
  EXTRA="--security-opt seccomp=unconfined --cap-add SYS_PTRACE"
else
  INI="$POCS/configs/php.ini"
  EXTRA=""
fi

for v in "${ORDER[@]}"; do
  name="lab-$v-$PROFILE"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" -p "127.0.0.1:$PORT:80" $EXTRA \
    -v "$INI:/usr/local/etc/php/conf.d/zz.ini:ro" \
    -v "$POCS/configs/apache.conf:/etc/apache2/conf-enabled/zz.conf:ro" \
    "${IMG[$v]}" >/dev/null
  sleep 1
  echo "== $v (${IMG[$v]}) puerto $PORT =="
  curl -s -o /dev/null -w 'probe=%{http_code}\n' -m 8 "http://127.0.0.1:$PORT/index.php"
  PORT=$((PORT+1))
done

echo
echo "Siguiente: para cada puerto, correr el perfil con el arnes del exploit"
echo "(warmup.py, hold.py, stage1_dump.py / 9bie segun perfil) y registrar 0/N o N/N."
echo "Los contenedores quedan vivos para inspeccion; borrar con: docker rm -f lab-*-$PROFILE"
