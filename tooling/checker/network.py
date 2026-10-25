#!/usr/bin/env python3
"""
network.py - Evaluacion no destructiva de upload_progress y limites de proxy.

Envia una peticion multipart/form-data minima (< 1 KB) con el parametro
PHP_SESSION_UPLOAD_PROGRESS para determinar si el servidor procesa
formularios multipart de subida y como gestiona los limites de peticion.

Reglas estrictas de seguridad:
- Tamano maximo de body: estrictamente < 10 KB (tipicamente ~400 bytes).
- Sin chunked forzado. Sin payloads extensos. Sin ciclos de grooming.
"""

from __future__ import annotations

import io
import secrets
from typing import Any, Dict
import requests


def check_upload_progress_posture(
    target_url: str,
    session: requests.Session,
    cookie_name: str = "PHPSESSID",
    timeout: int = 5,
    user_agent: str = "php2shell-checker/1.0",
    verify_ssl: bool = True
) -> Dict[str, Any]:
    """
    Envia un multipart minimo inocuo con PHP_SESSION_UPLOAD_PROGRESS.
    Tamano total < 500 bytes.
    """
    rand_sid = f"checker_net_{secrets.token_hex(6)}"
    probe_marker = "checker_probe_marker"

    # Datos multipart estrictamente reducidos
    data = {
        "PHP_SESSION_UPLOAD_PROGRESS": probe_marker,
    }
    # Archivo simulado minimo (20 bytes)
    dummy_file_content = b"checker_probe_content\n"
    files = {
        "file": ("checker_probe.txt", io.BytesIO(dummy_file_content), "text/plain")
    }

    headers = {
        "User-Agent": user_agent,
        "Cookie": f"{cookie_name}={rand_sid}",
        "Accept": "*/*",
        "Connection": "close",
    }

    result: Dict[str, Any] = {
        "status_code": None,
        "multipart_accepted": False,
        "body_limit_detected": False,
        "proxy_buffering_hint": None,
        "upload_progress_supported": None,
        "details": "",
        "bytes_sent": len(dummy_file_content) + len(probe_marker) + 200,  # Aprox con boundaries
        "error": None,
    }

    try:
        resp = session.post(
            target_url,
            headers=headers,
            data=data,
            files=files,
            timeout=timeout,
            allow_redirects=False,
            verify=verify_ssl
        )
        result["status_code"] = resp.status_code

        # Analizar codigos de estado
        if resp.status_code in (200, 204, 301, 302, 303):
            result["multipart_accepted"] = True
            result["upload_progress_supported"] = True
            result["details"] = (
                f"El servidor acepto multipart/form-data con status {resp.status_code}. "
                "upload_progress potencialmente activo en la ruta evaluada."
            )
        elif resp.status_code == 413:
            result["multipart_accepted"] = False
            result["body_limit_detected"] = True
            result["upload_progress_supported"] = False
            result["details"] = "Servidor o proxy rechazo peticion por tamano (HTTP 413: limites estrictos activos)."
        elif resp.status_code in (405, 501):
            result["multipart_accepted"] = False
            result["upload_progress_supported"] = False
            result["details"] = f"Metodo POST o multipart rechazado (HTTP {resp.status_code})."
        elif resp.status_code in (400, 403):
            result["multipart_accepted"] = False
            result["details"] = f"Servidor devolvio HTTP {resp.status_code} ante formulario multipart de diagnostico."
        else:
            result["details"] = f"Respuesta HTTP {resp.status_code} ante peticion multipart."

        # Inspeccion de cabeceras de proxy y buffering
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        if "x-accel-buffering" in resp_headers_lower:
            result["proxy_buffering_hint"] = resp_headers_lower["x-accel-buffering"]
        if "via" in resp_headers_lower or "x-cache" in resp_headers_lower:
            result["proxy_present"] = True

    except requests.RequestException as exc:
        result["error"] = f"Fallo de conexion en multipart probe: {type(exc).__name__}"
        result["details"] = "No se pudo completar el envio de comprobacion multipart."

    return result
