#!/usr/bin/env python3
"""
fingerprint.py - Identificacion pasiva de version, servidor y SAPI.

Inspecciona cabeceras HTTP (X-Powered-By, Server, Via) para determinar:
- Version de PHP y si se encuentra por debajo de versiones parcheadas.
- Servidor web frontal (Nginx, Apache, Caddy, etc.).
- Tipo de SAPI probable (FPM/FastCGI vs mod_php).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
import requests

from anti_injection import sanitize_header_text, extract_safe_version_string


def parse_semver(version_str: str) -> Optional[Tuple[int, ...]]:
    """Extrae tupla numerica de version (ej. '8.4.26' -> (8, 4, 26))."""
    match = re.search(r"(\d+(?:\.\d+)+)", version_str)
    if not match:
        return None
    try:
        return tuple(int(x) for x in match.group(1).split("."))
    except ValueError:
        return None


def is_version_vulnerable(
    version_str: str,
    patched_versions: Dict[str, str]
) -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    """
    Compara la version detectada contra la tabla de ramas parcheadas.
    Retorna: (is_vulnerable, branch_found, patched_reference)
    """
    ver_tuple = parse_semver(version_str)
    if not ver_tuple or len(ver_tuple) < 2:
        return None, None, None

    branch = f"{ver_tuple[0]}.{ver_tuple[1]}"
    if branch not in patched_versions:
        # Si la version mayor es inferior a 8.2, es EOL y susceptible si aplica
        if ver_tuple[0] < 8 or (ver_tuple[0] == 8 and ver_tuple[1] < 2):
            return True, branch, ">= 8.2.35 (rama EOL anterior)"
        # Si es superior a las conocidas, asumimos parcheada
        return False, branch, "Version posterior conocida"

    target_patched = patched_versions[branch]
    patched_tuple = parse_semver(target_patched)
    if not patched_tuple:
        return None, branch, target_patched

    is_vuln = ver_tuple < patched_tuple
    return is_vuln, branch, target_patched


def detect_sapi(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Infiere el tipo probable de SAPI a partir de cabeceras Server y X-Powered-By.
    """
    server = headers.get("Server", "").strip()
    powered_by = headers.get("X-Powered-By", "").strip()

    sapi_type = "unknown"
    confidence = "low"
    evidence = []

    # mod_php suele aparecer embebido en Server: Apache/2.4.x (Unix) PHP/8.x.x
    if "php" in server.lower():
        sapi_type = "mod_php"
        confidence = "high"
        evidence.append(f"Server header embebe firma PHP: {server}")
    elif "nginx" in server.lower() or "caddy" in server.lower():
        # Nginx/Caddy no integran mod_php; usan fastcgi_pass hacia FPM u otro proxy
        if "php" in powered_by.lower():
            sapi_type = "fpm-proxy"
            confidence = "high"
            evidence.append(f"Frontal {server} con backend PHP via cabecera X-Powered-By")
        else:
            sapi_type = "reverse-proxy"
            confidence = "medium"
            evidence.append(f"Frontal {server} detectado")
    elif "apache" in server.lower():
        if "php" in powered_by.lower():
            # Podria ser FPM via mod_proxy_fcgi o mod_php sin firma en Server
            sapi_type = "apache-fpm_or_modphp"
            confidence = "medium"
            evidence.append("Apache con backend PHP identificado")

    return {
        "sapi_hint": sapi_type,
        "confidence": confidence,
        "evidence": evidence,
    }


def analyze_fingerprint(
    target_url: str,
    session: requests.Session,
    timeout: int = 5,
    user_agent: str = "php2shell-checker/1.0",
    patched_versions: Optional[Dict[str, str]] = None,
    verify_ssl: bool = True
) -> Dict[str, Any]:
    """
    Realiza GET inicial sobre el target para extraer cabeceras y postura de version.
    No envia payloads; unicamente lectura de cabeceras pasivas.
    """
    if patched_versions is None:
        patched_versions = {
            "8.2": "8.2.35",
            "8.3": "8.3.36",
            "8.4": "8.4.27",
            "8.5": "8.5.12",
        }

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    }

    result: Dict[str, Any] = {
        "status_code": None,
        "is_php": False,
        "server": None,
        "x_powered_by": None,
        "via": None,
        "php_version": None,
        "php_branch": None,
        "is_unpatched_version": None,
        "patched_target": None,
        "sapi": {},
        "raw_headers": {},
        "error": None,
    }

    try:
        resp = session.get(
            target_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl
        )
        result["status_code"] = resp.status_code
        # Sanitizar cabeceras a minusculas o formato estandar
        resp_headers = {k: v for k, v in resp.headers.items()}
        result["raw_headers"] = {
            k: v for k, v in resp_headers.items()
            if k.lower() in {
                "server", "x-powered-by", "via", "x-backend-server",
                "content-type", "x-frame-options", "strict-transport-security"
            }
        }

        raw_server = resp.headers.get("Server")
        raw_x_powered = resp.headers.get("X-Powered-By")
        raw_via = resp.headers.get("Via")

        result["server"] = sanitize_header_text(raw_server)
        result["x_powered_by"] = sanitize_header_text(raw_x_powered)
        result["via"] = sanitize_header_text(raw_via)

        # Intentar extraer version PHP de X-Powered-By o Server
        version_raw = None
        if raw_x_powered and "php" in raw_x_powered.lower():
            version_raw = extract_safe_version_string(raw_x_powered)
            result["is_php"] = True
        elif raw_server and "php" in raw_server.lower():
            version_raw = extract_safe_version_string(raw_server)
            result["is_php"] = True

        if version_raw:
            match = re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+[\w\-]*)", version_raw, re.IGNORECASE)
            detected_ver = match.group(1) if match else version_raw
            if detected_ver:
                result["php_version"] = detected_ver
                result["is_php"] = True
                is_vuln, branch, target_patch = is_version_vulnerable(detected_ver, patched_versions)
                result["is_unpatched_version"] = is_vuln
                result["php_branch"] = branch
                result["patched_target"] = target_patch

        result["sapi"] = detect_sapi(resp.headers)

    except requests.RequestException as exc:
        result["error"] = f"Error de conexion en fingerprint: {type(exc).__name__}"

    return result
