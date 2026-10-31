# off_leak_e1.gdb — barrido de la ventana bajo display_errors=Off
#
# Uso (desde el host, el driver lo copia al contenedor y lo pasa con -x):
#   docker cp off_leak_e1.gdb <contenedor>:/tmp/e1.gdb
#   docker exec <contenedor> gdb -q -batch -nx -p <pid_worker> -x /tmp/e1.gdb
#
# Que mide (plan E0-E3, PR #22; base PR #34):
#   Lee la ventana completa desde idval = PS(id)+0x18 (byte 0 de la cookie)
#   hasta el fin del chunk de 2 MB del id, y clasifica cada qword.
#
# Clases:
#   DTOR      == &zval_ptr_dtor (residuo pDestructor de bloque bin-56)
#   libphp    valor dentro de [base, end) de las mappingas de libphp.so
#   chunk     puntero al mismo chunk del id (freelist next de MM)
#   heap      2 MiB-aligned en otro chunk
#   np        resto de datos no nulos
#   zero      0x0000000000000000
#
# Pre-requisitos:
#   - phpdebug:official (simbolos T de zval_ptr_dtor) o pasar
#     GDB_E1_DTOR_OFFSET=<hex> al docker exec para completar la direccion.
#   - contenedor con SYS_PTRACE y seccomp unconfined.
#   - el worker debera estar detenido por attach; es solo lectura, sin
#     breakpoints ni escritura de memoria.

set pagination off
set confirm off
python

import os
import re
import gdb


class E1Error(Exception):
    pass


def dtor_from_env():
    raw = (os.environ.get('GDB_E1_DTOR_OFFSET') or '').strip()
    if not raw:
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def e1_main():
    # --- 1. rango de mapeos de libphp.so
    rows = []
    mtxt = gdb.execute('info proc mappings', to_string=True)
    for line in mtxt.splitlines():
        if 'libphp.so' not in line:
            continue
        hx = re.findall(r'0x[0-9a-fA-F]+', line)
        if len(hx) >= 2:
            rows.append((int(hx[0], 16), int(hx[1], 16)))
    if not rows:
        raise E1Error('no se encontraron mappings de libphp.so')
    base = min(r[0] for r in rows)
    end = max(r[1] for r in rows)

    # --- 2. direccion de zval_ptr_dtor (simbolo, o env con offset)
    dtor = None
    dtor_src = 'none'
    try:
        dtor = int(gdb.parse_and_eval('&zval_ptr_dtor'))
        dtor_src = 'symbol'
    except gdb.error:
        off = dtor_from_env()
        if off is not None:
            dtor = base + off
            dtor_src = 'env(GDB_E1_DTOR_OFFSET)'
    if dtor is None:
        print('E1_NOTE: dtor no resuelto; clase DTOR desactivada')

    # --- 3. id de sesion y ventana hasta fin de chunk
    idp = int(gdb.parse_and_eval('ps_globals.id'))
    if idp == 0:
        raise E1Error('ps_globals.id == 0 (correr A antes del attach)')
    val = idp + 0x18
    chunk_base = idp & ~(0x200000 - 1)
    chunk_end = chunk_base + 0x200000
    n = chunk_end - val
    if n <= 0:
        raise E1Error('ventana invalida id=0x%x' % idp)

    buf = bytes(gdb.selected_inferior().read_memory(val, n))

    # --- 4. clasificacion de qwords
    counts = {}
    hits = []
    # Barrido byte a byte: un puntero puede quedar desalineado dentro de una
    # estructura; el barrido alineado a 8 perderia esos casos.
    total_pos = n - 7
    for i in range(0, n - 7):
        qw = int.from_bytes(buf[i:i + 8], 'little')
        if qw == 0:
            cls = 'zero'
        elif dtor is not None and qw == dtor:
            cls = 'DTOR'
        elif base <= qw < end:
            cls = 'libphp'
        elif (qw & ~(0x200000 - 1)) == chunk_base:
            cls = 'chunk'
        elif (qw & (0x200000 - 1)) == 0:
            cls = 'heap'
        else:
            cls = 'np'
        counts[cls] = counts.get(cls, 0) + 1
        if cls in ('DTOR', 'libphp'):
            hits.append((i, cls, qw))

    # --- 5. reporte
    print('===E1_BEGIN===')
    print('hdr,libphp_base,0x%x,libphp_end,0x%x,dtor,%s,dtor_src,%s'
          % (base, end,
             ('0x%x' % dtor) if dtor else 'none', dtor_src))
    print('hdr,id,0x%x,idval,0x%x,page_off,0x%x,chunk,0x%x,scan_len,%d'
          % (idp, val, idp & (0x200000 - 1), chunk_base, n))
    for pos, cls, qw in hits:
        print('hit,pos,%d,cls,%s,qw,0x%016x,align56,%d,align64,%d'
              % (pos, cls, qw, pos % 56, pos % 64))
    print('counts,dtor,%d,libphp,%d,chunk,%d,heap,%d,np,%d,zero,%d,total,%d'
          % (counts.get('DTOR', 0), counts.get('libphp', 0),
             counts.get('chunk', 0), counts.get('heap', 0),
             counts.get('np', 0), counts.get("zero", 0), total_pos))
    print('===E1_END===')


try:
    e1_main()
except E1Error as exc:
    print('===E1_ERROR=== %s' % exc)
except Exception as exc:
    print('===E1_ERROR=== %r' % exc)

end
quit
