#!/usr/bin/env python3
"""
session.py - Evaluacion no destructiva de session.use_strict_mode.

Envia una peticion inocua con un identificador de sesion inexistente
(PHPSESSID=checker_probe_<rand>) para observar si el servidor rechaza
el identificador no inicializado emitiendo un nuevo Set-Cookie (strict_mode=1)
o si acepta el valor arbitrario (strict_mode=0).
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, List, Optional
import requests

from anti_injection import sanitize_header_text


def sanitize_cookie_val(val: str) -> str:
    """Sanitiza el valor de cookie para evitar fuga en reportes."""
    if not val:
        return ""
    prefix = val[:6] if len(val) >= 6 else val
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}...[sha256:{digest}]"


def parse_set_cookies(response: requests.Response) -> List[Dict[str, str]]:
    """Extrae cookies emitidas en Set-Cookie sin alterar el estado."""
    extracted = []
    # requests agrupa en response.cookies o headers
    raw_cookies = []
    if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist"):
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    elif "Set-Cookie" in response.headers:
        raw_cookies = [response.headers["Set-Cookie"]]

    for cookie_header in raw_cookies:
        parts = cookie_header.split(";")
        if not parts:
            continue
        first = parts[0].strip()
        if "=" in first:
            name, value = first.split("=", 1)
            raw_val = sanitize_header_text(value.strip(), max_length=64)
            extracted.append({
                "name": sanitize_header_text(name.strip(), max_length=32),
                "value_sanitized": sanitize_cookie_val(raw_val),
                "raw_value": raw_val,
            })
    return extracted


def check_session_strict_mode(
    target_url: str,
    session: requests.Session,
    cookie_name: str = "PHPSESSID",
    timeout: int = 5,
    user_agent: str = "php2shell-checker/1.0",
    verify_ssl: bool = True
) -> Dict[str, Any]:
    """
    Envia un GET inocuo con un identificador no inicializado para evaluar use_strict_mode.
    Total de datos transferidos: < 1 KB.
    """
    random_suffix = secrets.token_hex(8)
    probe_sid = f"checker_probe_{random_suffix}"

    headers = {
        "User-Agent": user_agent,
        "Cookie": f"{cookie_name}={probe_sid}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    }

    result: Dict[str, Any] = {
        "probe_sid_sent": sanitize_cookie_val(probe_sid),
        "status_code": None,
        "set_cookie_received": False,
        "session_cookie_replaced": False,
        "use_strict_mode_detected": None,  # True (mitigado), False (expuesto), None (inconcluso)
        "details": "",
        "error": None,
    }

    try:
        resp = session.get(
            target_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=verify_ssl
        )
        result["status_code"] = resp.status_code
        cookies_emitted = parse_set_cookies(resp)

        # Buscar si el servidor emitio el cookie de sesion
        target_emitted = [c for c in cookies_emitted if c["name"].lower() == cookie_name.lower()]

        if target_emitted:
            result["set_cookie_received"] = True
            new_val = target_emitted[0]["raw_value"]
            if new_val != probe_sid:
                # El servidor genero un nuevo SID, rechazando el identificador arbitrario
                result["session_cookie_replaced"] = True
                result["use_strict_mode_detected"] = True
                result["details"] = (
                    f"Servidor rechazo SID no inicializado y emitio nuevo {cookie_name}. "
                    "session.use_strict_mode activo o regeneracion forzada (mitigado)."
                )
            else:
                # El servidor confirmo o devolvio el mismo SID enviado
                result["session_cookie_replaced"] = False
                result["use_strict_mode_detected"] = False
                result["details"] = (
                    f"Servidor acepto y devolvio el SID arbitrario en Set-Cookie. "
                    "session.use_strict_mode inactivo (expuesto)."
                )
        else:
            # No se recibio Set-Cookie para PHPSESSID
            # Puede deberse a use_strict_mode = 0 (acepto el ID sin modificarlo)
            # o a que el endpoint no llama a session_start()
            result["use_strict_mode_detected"] = None
            result["details"] = (
                f"No se recibio cabecera Set-Cookie para {cookie_name}. "
                "Posible session_start() inactivo en la ruta raiz o use_strict_mode=0 silencioso."
            )

    except requests.RequestException as exc:
        result["error"] = f"Fallo de conexion en session check: {type(exc).__name__}"
        result["details"] = "No fue posible contactar al endpoint de sesion."

    return result
