# psid_probe.gdb - locate PS(id) and the session HashTable in a live worker.
#
# Read-only probe. Installs breakpoints on php_session_reset_id and
# php_session_track_init, records the allocator state and continues.
#
# Struct offsets were verified with `ptype /o` on the reference debug build
# (PHP 8.4.26, -O1 -g3):
#   zend_mm_heap:  free_slot[30] @40, main_chunk @320, cached_chunks @328
#   zend_mm_chunk: next @8, free_pages @24, free_tail @28, num @32,
#                  free_map @544 (64 B, 1 bit per page)
#   zend_string:   len @16, val @24
#
# Re-verify the offsets for any other PHP build before trusting the output:
#   gdb -q -batch -ex 'ptype /o zend_mm_heap' -ex 'ptype /o zend_mm_chunk' \
#       -ex 'ptype /o struct _zend_string' /path/to/libphp.so
#
# Usage (one worker, inside the container):
#   docker cp psid_probe.gdb <container>:/tmp/psid_probe.gdb
#   docker exec -d <container> gdb -q -batch -nx -p <worker_pid> -x /tmp/psid_probe.gdb
#   ... send payload A and payload B ...
#   docker exec <container> cat /tmp/psid_probe.log
#
# The probe writes RESET and TRACK lines plus heap dumps to /tmp/psid_probe.log.
# If a struct offset is wrong the reads fail and the line carries readerr=...;
# a silent empty log usually means the worker never hit the breakpoints.

set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/psid_probe.log
set logging overwrite on
set logging enabled on

python

import gdb
import struct

CHUNK_SIZE = 0x200000
CHUNK_MASK = ~(CHUNK_SIZE - 1)
HEAP_MAIN = 320
HEAP_FS = 40
CH_NEXT = 8
CH_FREE_PAGES = 24
CH_FREE_TAIL = 28
CH_NUM = 32
CH_FREE_MAP = 544
STR_LEN = 16


def _inf():
    return gdb.selected_inferior()


def u64(addr):
    return struct.unpack('<Q', _inf().read_memory(addr, 8).tobytes())[0]


def u32(addr):
    return struct.unpack('<I', _inf().read_memory(addr, 4).tobytes())[0]


def heap_ptr():
    try:
        return int(gdb.parse_and_eval('alloc_globals.mm_heap'))
    except gdb.error:
        return 0


def walk_chunks(hp):
    if hp == 0:
        return 0, []
    main = u64(hp + HEAP_MAIN)
    out = []
    c = main
    for _ in range(16):
        if c == 0:
            break
        out.append(c)
        nxt = u64(c + CH_NEXT)
        if nxt == main or nxt == 0:
            break
        c = nxt
    return main, out


def free_map_stats(c):
    raw = _inf().read_memory(c + CH_FREE_MAP, 64).tobytes()
    words = struct.unpack('<8Q', raw)
    zeros = 0
    best0 = cur0 = 0
    best1 = cur1 = 0
    for i in range(512):
        used = (words[i // 64] >> (i % 64)) & 1
        if used == 0:
            zeros += 1
            cur0 += 1
            if cur0 > best0:
                best0 = cur0
            cur1 = 0
        else:
            cur1 += 1
            if cur1 > best1:
                best1 = cur1
            cur0 = 0
    return zeros, best0, best1


def walk_bin(hp, idx, limit=256):
    head = u64(hp + HEAP_FS + idx * 8)
    out = []
    seen = set()
    b = head
    while b and b not in seen and len(out) < limit:
        out.append(b)
        seen.add(b)
        try:
            b = u64(b)
        except gdb.error:
            break
    return out


def dump_heap(tag):
    hp = heap_ptr()
    main, chunks = walk_chunks(hp)
    gdb.write('%s heap=0x%x main=0x%x chunks=%d\n'
              % (tag, hp, main, len(chunks)))
    for c in chunks:
        try:
            zeros, run0, run1 = free_map_stats(c)
            gdb.write('CHUNK addr=0x%x num=%d fp=%d ft=%d zeros=%d run0=%d run1=%d\n'
                      % (c, u32(c + CH_NUM), u32(c + CH_FREE_PAGES),
                         u32(c + CH_FREE_TAIL), zeros, run0, run1))
        except gdb.error as exc:
            gdb.write('CHUNK addr=0x%x readerr=%s\n' % (c, exc))
    if hp:
        for idx in (6, 7):
            slot = u64(hp + HEAP_FS + idx * 8)
            gdb.write('BIN idx=%d head=0x%x chunk=0x%x page=0x%x\n'
                      % (idx, slot, slot & CHUNK_MASK, slot & (CHUNK_SIZE - 1)))
            chain = walk_bin(hp, idx)
            gdb.write('BINWALK idx=%d n=%d pages=%s\n'
                      % (idx, len(chain),
                         ','.join('0x%x' % (b & (CHUNK_SIZE - 1))
                                  for b in chain)))
    return hp, main, chunks


def psid():
    try:
        return int(gdb.parse_and_eval('ps_globals.id'))
    except gdb.error:
        return 0


def send_cookie():
    try:
        return int(gdb.parse_and_eval('ps_globals.send_cookie'))
    except gdb.error:
        return -1


class ResetBP(gdb.Breakpoint):
    def __init__(self):
        super(ResetBP, self).__init__('php_session_reset_id')
        self.hits = 0

    def stop(self):
        self.hits += 1
        pid = psid()
        if pid == 0:
            gdb.write('RESET hit=%d id=0x0\n' % self.hits)
            return False
        try:
            length = u64(pid + STR_LEN)
        except gdb.error:
            length = -1
        gdb.write('RESET hit=%d id=0x%x len=%d send=%d chunk=0x%x page=0x%x\n'
                  % (self.hits, pid, length, send_cookie(),
                     pid & CHUNK_MASK, pid & (CHUNK_SIZE - 1)))
        dump_heap('RESET_STATE')
        return False


class TrackBP(gdb.Breakpoint):
    def __init__(self):
        super(TrackBP, self).__init__('php_session_track_init')
        self.hits = 0

    def stop(self):
        self.hits += 1
        pid = psid()
        hp = heap_ptr()
        head = u64(hp + HEAP_FS + 6 * 8) if hp else 0
        gdb.write('TRACK hit=%d id=0x%x ht=0x%x ht_chunk=0x%x ht_page=0x%x delta=%d\n'
                  % (self.hits, pid, head, head & CHUNK_MASK,
                     head & (CHUNK_SIZE - 1),
                     (head - pid) if (head and pid) else 0))
        dump_heap('TRACK_STATE')
        return False


ResetBP()
TrackBP()
gdb.write('ATTACHED\n')

end

continue
