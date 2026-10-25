#!/usr/bin/env python3
"""
anti_injection.py - Sanitizacion estricta contra Prompt Injections / Honeypots.

Protege al orquestador y analista contra payloads en cabeceras o respuestas HTTP
disenados para inyectar instrucciones a modelos de lenguaje (LLMs).
"""

from __future__ import annotations
import re

# Patrones tipicos de prompt injection o intentos de evasion / comando
SUSPICIOUS_PROMPT_PATTERNS = re.compile(
    r'(?i)(ignore\s+(all\s+)?(previous\s+)?instructions|'
    r'disregard\s+(all\s+)?(previous\s+)?instructions|'
    r'system\s+prompt|new\s+instruction|assistant\s+must|'
    r'you\s+are\s+now|override\s+system|'
    r'print\s+all\s+secrets|dump\s+environment|'
    r'cat\s+/etc/|rm\s+-rf|curl\s+http|wget\s+http|bash\s+-i)'
)

def sanitize_header_text(val: str | None, max_length: int = 120) -> str:
    """
    Sanitiza el valor de una cabecera HTTP eliminando caracteres no imprimibles,
    truncando longitud y neutralizando prompt injections conocidos.
    """
    if not val:
        return ""
    
    val_str = str(val).strip()
    
    # 1. Deteccion de patrones maliciosos / honeypot injection
    if SUSPICIOUS_PROMPT_PATTERNS.search(val_str):
        return "[HONEYPOT_MALFORMED_HEADER_BLOCKED]"
    
    # 2. Truncar longitud
    truncated = val_str[:max_length]
    
    # 3. Solo permitir caracteres alfanumericos y puntuacion segura de cabeceras
    clean = re.sub(r'[^\w\s\.\-\/\:\,\;\=\+\_\(\)]', '', truncated).strip()
    return clean

def extract_safe_version_string(val: str | None) -> str:
    """
    Extrae estrictamente una version numerica (ej. '8.4.26') neutralizando
    cualquier payload anexo en la cabecera.
    """
    if not val:
        return ""
    val_str = str(val).strip()
    if SUSPICIOUS_PROMPT_PATTERNS.search(val_str):
        return ""
    m = re.search(r'\b(\d+\.\d+(?:\.\d+)?)\b', val_str)
    return m.group(1) if m else ""
