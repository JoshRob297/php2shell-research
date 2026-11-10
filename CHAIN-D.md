# Chain D, measured: the object store at shutdown
[English](CHAIN-D.md) · [Español](CHAIN-D.es.md)


One of the chains circulating for these CVEs says the request shutdown reads a stale
`EG(objects_store)` left behind by a request that died mid-startup, and that the next request
on the same worker can consume it. We measured that step. It does not behave that way.

This document says exactly how far the measurement goes, because the neighbouring claim — the
object bucket array being freed and reused — is a different thing and is **not** addressed here.

## What was measured

`php:8.4.26-apache`, mod_php, prefork, 128M, one worker (pid 17), breakpoint at
`php_request_shutdown` (`main/main.c:1891`). Three requests on that same worker:

1. a warmup GET → 200
2. a chunked 70 MB body that dies at request startup with
   `Allowed memory size of 134217728 bytes exhausted` → 500
3. a GET after the OOM → 200, the worker is still alive

At the breakpoint, one observation per request:

```
SHUTDOWN ob=0x7f1b30451000 top=1 size=1024 flh=-1 err=30719
0x7f1b30451000: 0x0000000000000000  0x0000000000000000
SHUTDOWN ob=0x7f1b30451000 top=1 size=1024 flh=-1 err=30719
0x7f1b30451000: 0x0000000000000000  0x0000000000000000
SHUTDOWN ob=0x7f1b30451000 top=1 size=1024 flh=-1 err=30719
0x7f1b30451000: 0x0000000000000000  0x0000000000000000
```

The store pointer, the next-free slot, the capacity and the free-list head are identical in all
three. `top=1` with handle 0 reserved means no live objects at shutdown, and the first two
bucket entries read as zero. `current_execute_data`, `vm_stack` top and end are identical too.

So: the object store header at shutdown is the same whether or not the request died during
startup. The "stale store left behind for the next request" framing is not supported.

Transcript: [`raw/chain-d-eg-shutdown.txt`](raw/chain-d-eg-shutdown.txt).

## Where this stops

Two limits, and they matter more than the result:

- We measured the store **header and its first bucket entries**, not the whole 1024-entry array.
- All three observations were made with the store **empty at shutdown**. A request that reaches
  shutdown holding live objects is a different state, and this measurement says nothing about it.

## What the other work says

The published material does not all make the same claim, and the difference decides whether it
survives this measurement:

- **segfo** confirms a use-after-free of `object_buckets` with a crash, and marks RCE unproven.
  That is the bucket array, not the store header — outside what we measured.
- **cookie-bakery** publishes a full chain: OOM, a bucket marked `IS_OBJECT`,
  `zend_objects_store_del`, a `free_obj` pivot, ROP and `system`. It runs with ASLR off and its
  own documentation asks for leaks to work under ASLR. A working ASLR-off chain and our
  identical-header result are not in conflict: they are about different memory.
- **ikow** describes "stale `EG()` / object store" as dependency-free RCE. The repository ships
  exploits for chains A, B and C; the chain D code is not published there.
- The patch that resets `object_buckets` during shutdown is consistent with the bucket variant.
  It is not evidence for a stale store header.

## The takeaway

"Chain D works because `EG(objects_store)` is stale" is the version that does not hold. The
version worth pursuing is the bucket array, which someone has already taken to code with ASLR
off, and which needs a leak to cross into ASLR on.

This is a negative result about a specific step, published because a matrix that only lists
successes is not a matrix. It also changes our own row from `UNSUPPORTED` to something narrower:
unsupported **as a stale-store claim**, with the bucket variant explicitly still open.
