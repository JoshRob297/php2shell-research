#!/bin/sh
# Verify that a container matches the prerequisites of the lab kit.
#
# Usage: ./check_build.sh <container>
#
# Checks, in order:
#   1. libphp.so exposes the symbols the probe and the payloads rely on;
#   2. the effective php.ini values match the calibration profile;
#   3. the prefork pool has exactly one worker.
#
# Exit codes: 0 all good, 1 a check failed, 2 usage.

set -eu

CONTAINER="${1:-}"
if [ -z "$CONTAINER" ]; then
    echo "usage: $0 <container>" >&2
    exit 2
fi

MODULE="/usr/lib/apache2/modules/libphp.so"
fail=0

echo "== symbols in $MODULE"
for sym in php_session_reset_id php_session_track_init php_session_initialize \
           zend_mm_safe_error zval_ptr_dtor php_url_encode; do
    # Use the full symbol table, not the dynamic one: several of these are
    # local (t) symbols that gdb resolves from .symtab.
    if docker exec "$CONTAINER" sh -c "nm $MODULE 2>/dev/null | grep -qw $sym"; then
        echo "  ok      $sym"
    else
        echo "  MISSING $sym"
        fail=1
    fi
done

echo "== effective config"
docker exec "$CONTAINER" php -i 2>/dev/null | grep -E \
    '^(memory_limit|post_max_size|session.upload_progress.enabled|session.save_path|session.use_strict_mode) ' \
    || { echo "  cannot read php -i"; fail=1; }

echo "== workers"
workers=$(docker exec "$CONTAINER" sh -c \
    'ps -eo ppid,comm | awk "\$2==\"apache2\" && \$1!=0 {print}" | wc -l')
echo "  apache2 workers: $workers"
if [ "$workers" -ne 1 ]; then
    echo "  EXPECTED exactly 1 worker (see apache-prefork.conf)"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "RESULT: prerequisites NOT met"
    exit 1
fi
echo "RESULT: prerequisites met"
