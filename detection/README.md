# Detection

Refined, additive rules that complement the ecosystem's rule set (Suricata SIDs
2026100-2026116, Sigma, ModSecurity and Lua modules distributed separately; no
SID overlaps). These rules encode artifacts measured in this project; see
`REPORT.md`, `EVIDENCE.md` section 11 and `validation/`.

| File | Format | Contents |
|---|---|---|
| `php2shell-refined.rules` | Suricata 7/8 | 4 rules: forged cookie with NUL bytes, oversized cookie, two groom signatures |
| `php2shell-refined.yaml` | Sigma | 2 rules: forged cookie in proxy logs, heap-corruption abort burst |

## The two highest-value signals

**Response cookie with NUL bytes.** A genuine `PHPSESSID` is 22-48 characters
from `[A-Za-z0-9,-]`. The forged id produced by the measured chain is a
4000-byte value that decodes to filler, NUL runs and, depending on heap state,
pointer-like bytes. A percent-encoded `%00` in the cookie is impossible in a
legitimate id, which makes SID 2026120 the lowest-false-positive post-compromise
signal in this set.

**Cookie length.** Values of 128 characters or more are either forged or come
from a deliberately oversized `session.sid_length` (PHP allows up to 256). Treat
SID 2026121 as suspicious, not conclusive, and correlate with 2026120 and with
worker aborts.

## Groom signatures (2026122, 2026123)

The analyzed payload allocates filler fields with 103-byte names and values
(`f0000`, `g0000`, ...), 231-byte trimmer values and 15000-byte blocks. Rules
2026122/2026123 match the 103-byte `V` run and the 231-byte `X` run. They catch
reuse of this specific chain and provide intelligence value; a re-groomed
payload with different lengths evades them. Do not treat a miss as absence of
attempts.

## Deployment notes

- Enable request-body inspection in Suricata (`request-body-limit`; the default
  in many builds is 0). The attack bodies are megabytes, so body rules only work
  if the limit covers at least the first inspected bytes and the match does not
  depend on the tail; the groom signatures appear early in the body.
- Many WAFs inspect only the first 64 KB of a body. The analyzed chain pads past
  that window, so WAF-side body rules are not a primary control.
- Response rules (2026120, 2026121) are the reliable layer: they fire on the
  artifact that reaches the client regardless of request padding.

## Verifying the rules

```bash
suricata -T -S php2shell-refined.rules -c /etc/suricata/suricata.yaml
sigma check php2shell-refined.yaml   # or sigma-cli convert to your backend
```

Both files in this directory were syntax-checked with Suricata 8.0.7 and
PyYAML/Sigma parsing before publication.
