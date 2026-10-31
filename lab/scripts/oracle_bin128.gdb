set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/oracle_g.log
set logging overwrite on
set logging enabled on
python
import gdb


def heap():
    return gdb.parse_and_eval("(zend_mm_heap*)zend_mm_get_heap()")


def total_free(h):
    c = h['main_chunk']
    m = c
    pages = 0
    chunks = 0
    while True:
        pages += int(c['free_pages'])
        chunks += 1
        c = c['next']
        if int(c) == int(m):
            break
    return pages, chunks


def id_len():
    idp = gdb.parse_and_eval("ps_globals.id")
    if not int(idp):
        return -1
    try:
        return int(idp.dereference()['len'])
    except Exception:
        return -2


class ResetBP(gdb.Breakpoint):
    def __init__(self):
        super(ResetBP, self).__init__("php_session_reset_id")

    def stop(self):
        try:
            h = heap()
            pages, chunks = total_free(h)
            gdb.write(
                "ORACLE_STATE free_pages=%d chunks=%d fs11=%s sc=%d len=%d size=%d real=%d\n" % (
                    pages, chunks,
                    hex(int(h['free_slot'][11])),
                    int(gdb.parse_and_eval("ps_globals.send_cookie")),
                    id_len(), int(h['size']), int(h['real_size'])))
        except Exception as exc:
            gdb.write("ORACLE_ERR %r\n" % (exc,))
        return False


class SafeErrBP(gdb.Breakpoint):
    def __init__(self):
        super(SafeErrBP, self).__init__("zend_mm_safe_error")

    def stop(self):
        try:
            gdb.write("ORACLE_OOM sc=%d len=%d\n" % (
                int(gdb.parse_and_eval("ps_globals.send_cookie")), id_len()))
        except Exception as exc:
            gdb.write("ORACLE_OOM_ERR %r\n" % (exc,))
        return False


ResetBP()
SafeErrBP()
end
continue
