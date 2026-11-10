# Chain E — the FPM path, measured
[English](CHAIN-E.md) · [Español](CHAIN-E.es.md)


Chain E is the PHP-FPM arm of the E-OOM primitive: a decode out-of-memory leaves
`BG(unserialize)` at `level=1` with a dangling `data` pointer, the next decode reuses it, and a
controlled 16-byte write lands on `&sapi_module.ub_write`, which is replaced with `&system`.

**It is a lab result, not a remote capability.** Under default ASLR it is a deterministic
denial of service (worker crash, 502). Command execution requires ASLR off or already-known
bases, plus a planted 24-byte session. Everything below is what we measured, including the
paths that did not work.

This document publishes the layout and the numbers. It does not publish the orchestrator: the
code we have is a fragment that cannot run without our harness, and one of its builders accepts
an address it never uses. Shipping that as a "public chain" would be shipping something that
does not run.

## The write

A fake `var_dtor_entries` sits in a multipart field buffer. The destructor loop walks it and
writes one entry per iteration, so the landing offset is set by the entry count:

```
T2 = d + 0x110 + 16·N          N = (T2 − d − 0x110) / 16
```

`T2` is `&sapi_module.ub_write`. `d` is the address of the reclaimed struct. If
`(T2 − d − 0x110)` is not a multiple of 16 the chain cannot land at all — the builder refuses
rather than silently misaligning.

Field offsets inside the 12,300-byte fake entries buffer, as measured:

- `0x1000` — `entries.last` = `d + 0x38`
- `0x1008` — `entries.first_dtor` = `0`
- `0x1010` — `last_dtor` = `d + 0x100`
- `0x1038` — `entries.used_slots` = `0`
- `0x1100` — `fake.used_slots` = `N`
- `0x1108` — `fake.next` = `0`

## The planted session: 24 bytes, and the contents matter

The session must be **exactly 24 bytes**, of the form:

```
C|i:<V>;AAAA
```

Both facts are measured, not assumed:

- `hello|i:<V>;` — also 24 bytes — **broke the layout**. The interned-strings arena corrupts
  struct `d` before the write, and the process dies with SEGV in `tmp_var` (only visible under
  `WATCH`).
- The trailing `AAAA` triggers a benign `cancel_decode` warning. The write has already happened
  in the first pair, so the warning is cosmetic.

## The post-exec desynchronisation

Hijacking `ub_write` breaks the engine's output contract. PHP expects `ub_write` to return the
number of bytes written; `system()` returns the subshell's exit status, so the SAPI layer sees
`rax = 0`, calls `php_handle_aborted_connection`, and the client gets a 502.

The payload has to decouple: `foo; (cmd; kill -TERM $$) >/dev/null 2>&1 &`. The command runs in
a subshell, the damaged worker is recycled, and the response is allowed to die.

## Paths that did not work

Each of these was measured and closed:

- **`PS(serializer)->decode = &system`** — the write crushes the neighbouring `http_session_vars`
  at `+8`, giving `Z_REFVAL(0x4)` and a SEGV before the second decode.
- **`GOT(memchr)` = `0x1600c38`** — `mod 16 = 8`, unreachable with 16-byte-aligned slots.
- **Gadget `lea/mov 0x18(%rcx),%rdi; jmp exec`** — does not exist in the binary. It does not
  import `system` either, only `popen` / `posix_spawn` / `fork`, and `popen` needs a valid mode
  string in `rsi`.
- **re2c rule `"i:" iv ";"`** — verified in source: the `;` is part of the rule. `i:<V>` without
  `;` does not write the LONG at all.
- **ASLR page sweep** — see below. It does not exist as a mechanism in our tooling.

## The sweep, measured

We had a module called `aslr_sweep` described as a deterministic page sweep for remote FPM. It
was worth checking, because if it worked, the `LAB ONLY` verdict would be wrong.

It does not work, and structurally cannot: the request it sends is `{"page": N}` as form data,
with no forged body and no address arithmetic. It never attempts a landing.

Worse, its success check matched `"OK"` in the response body regardless of any marker passed in,
so against a page that prints `OK` it reports success on page 0.

Measured on 2026-11-09, `phpdebug:8.4.26-fpm` with `pm = static`, one worker, behind nginx,
`randomize_va_space = 2`:

- with the code's own criterion: `success = True`, page 0, 0.01 s, one request — a false
  positive, nothing executed
- with a strict criterion (`uid=` and `gid=` required): **387 pages, 387 responses 200, 0 hits,
  0.34 s, 0 crashes**, page still serving, no payload ever built

Transcript: [`raw/chain-e-aslr-sweep-387.txt`](raw/chain-e-aslr-sweep-387.txt).

## What this means

`LAB ONLY` stands, and now it is closed from both sides: the bin-16 fragmentation blocker we
already had, and the absence of any sweep that bypasses it.

If you are reading this to reproduce: you need ASLR off or known bases, a session of exactly
24 bytes in the shape above planted under the victim's id, a page that calls `session_start()`,
and a worker that does not recycle between the two requests. Without all four, this is a 502.
