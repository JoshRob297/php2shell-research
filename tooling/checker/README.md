# php2shell-checker: Non-Destructive Posture Diagnostic Tool

A safe, non-destructive diagnostic CLI designed for systems administrators, incident responders, and security researchers to audit server posture and configuration requirements related to request startup vulnerabilities (CVE-2026-109618 / CVE-2026-109619) without triggering denial of service, memory exhaustion (OOM), or heap corruption.

---

## 1. Operating Principles & Defensive Guarantees

- **Strictly Non-Destructive:** Transmits zero exploit payloads, executes no commands, and causes no persistent state changes.
- **Minimal Network Footprint:** Emits a maximum of 3 standard HTTP(S) requests per audit run.
- **Bounded Request Size:** Request payloads are capped strictly below 10 KB (typically under 1 KB).
- **Standard Protocol Compliance:** Employs standard `multipart/form-data` without chunked transfer anomalies or unbounded streaming.
- **Honeypot & Prompt-Injection Resistant:** Incoming HTTP headers and response bodies are filtered through strict regex heuristics (`anti_injection.py`) to prevent indirect prompt-injection attacks targeting automated LLM-assisted workflows.
- **Built-in Safety Guards:**
  - Local and RFC 1918 private network targets require explicit `--local` consent.
  - External public targets require explicit `--authorized` acknowledgment confirming written authorization.
  - Safe local inspection is supported via `--dry-run`.

---

## 2. Architecture & File Layout

```text
tooling/checker/
├── README.md           # Documentation, boundaries, and ethical usage
├── config.yaml         # Configurable timeouts, patched version benchmarks, scoring weights
├── checker.py          # Main CLI orchestrator, safety gates, and posture scoring
├── fingerprint.py      # Passive server, SAPI, and PHP version inference
├── session.py          # Non-destructive session.use_strict_mode probe
├── network.py          # Minimal multipart/form-data & upload_progress probe (<500 bytes)
├── anti_injection.py   # Heuristic sanitizer against malicious/honeypot header payloads
├── report.py           # Sanitized JSON and Markdown report export
├── test_checker.py     # Comprehensive unit tests (100% pass)
└── examples/           # Sample sanitized outputs for exposed and mitigated environments
```

---

## 3. Diagnostic Matrix & Posture Scoring

The tool evaluates targets across four independent defensive dimensions:

| Check | Weight | Mitigated Condition | Exposed Condition |
|---|---|---|---|
| **Patched PHP Engine** | 25% | Version >= `8.4.27`, `8.3.36`, `8.2.35`, `8.5.12` | Unpatched version branch |
| **Strict Session Mode** | 25% | `session.use_strict_mode = 1` (regenerates arbitrary SID) | `session.use_strict_mode = 0` (accepts arbitrary SID) |
| **Upload Progress Scope** | 20% | Disabled or rejected by web server / SAPI | Multipart upload progress accepted with status 200 |
| **Proxy / Body Limits** | 20% | Strict upstream body size restrictions enforced | No visible body size limitations |
| **SAPI Deployment Model** | 10% | Isolated SAPI with default worker lifecycle controls | Exposed or permissive handler configuration |

### Composite Posture Verdicts

- **`EXPOSED`**: Target runs an unpatched engine release with active upload progress and non-strict session handling.
- **`PARTIALLY_EXPOSED`**: Target engine is unpatched but key architectural mitigations (such as `use_strict_mode = 1`) are active.
- **`MITIGATED`**: Target runs a verified patched PHP release or has disabled `session.upload_progress.enabled`.
- **`INCONCLUSIVE`**: Non-PHP backend, obscured headers, or insufficient diagnostic response data.

---

## 4. Installation & Requirements

- Python 3.9+
- Standard libraries plus `requests` and `PyYAML`:

```bash
pip install requests pyyaml
```

Run test suite to verify module integrity:

```bash
python3 -m unittest test_checker.py
```

---

## 5. Usage & Examples

### Basic Diagnostic Run against Local Test Lab

```bash
python3 checker.py --url http://127.0.0.1:8080/ --local --verbose
```

### Auditing Authorized External Deployment with Exported Reports

```bash
python3 checker.py --url https://example.com/ping.php \
  --authorized \
  --json report.json \
  --md report.md \
  --verbose
```

### Dry Run (Simulates safety gate validation without network traffic)

```bash
python3 checker.py --url https://example.com/ --dry-run
```

---

## 6. Ethical Scope & Responsible Use

`php2shell-checker` is published exclusively for defensive verification, configuration hardening, and incident response triage. It does not provide weaponization, code execution, or exploitation capabilities. Always obtain proper written authorization before testing systems outside your own infrastructure.
