#!/usr/bin/env bash
# opcache_differential.sh - diferencial de OPcache 8.4.26 vs 8.4.27 con OOM de compilacion.
#
# Requiere dos contenedores con opcache (zend_extension=opcache) y memory_limit=32M.
# El trigger es un archivo que no compila dentro del limite (60000 asignaciones).
#
# Uso:
#   ./opcache_differential.sh <puerto_8426> <puerto_8427>
#
# Resultado esperado:
#   8.4.26: "Fatal error ... exhausted" en cada corrida; big.php nunca entra a la cache.
#   8.4.27: fatal en la primera corrida; "big-ok" despues; big.php cacheado y valido.

set -u
P826="${1:?puerto 8.4.26}"
P827="${2:?puerto 8.4.27}"

python3 - <<'PY'
lines = ["<?php"] + [f"$v{i} = {i};" for i in range(60000)] + ["echo 'big-ok';"]
open("/tmp/big.php", "w").write("\n".join(lines))
PY

for label in 8426:"$P826" 8427:"$P827"; do
  name=${label%%:*}; port=${label##*:}
  echo "== $name (puerto $port) =="
  for i in 1 2 3 4; do
    code=$(curl -s -o /tmp/out -w '%{http_code}' -m 20 "http://127.0.0.1:$port/big.php")
    sig=$(grep -oE 'Fatal error|big-ok' /tmp/out | head -1)
    echo "run $i: $code $sig"
  done
  echo "cache:"
  curl -s -m 8 "http://127.0.0.1:$port/osl.php" | grep -E "big.php|sin big" || echo "(sin big.php)"
done

echo
echo "Nota: el listado de cache requiere osl.php en el webroot (opcache_get_status)."
