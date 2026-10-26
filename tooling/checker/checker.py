#!/usr/bin/env python3
"""
checker.py - Orquestador principal de diagnostico no destructivo php2shell.

Evalua la postura de configuracion de un servidor PHP ante requisitos
de las cadenas documentadas de php2shell sin enviar payloads destructivos,
sin generar OOM y sin forzar heap grooming.

Peticiones estrictamente inocuas (< 10 KB total).
Directiva Clean UI: cero emojis en consola y reportes.
"""

from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")

import argparse
import datetime
import ipaddress
import os
import socket
import sys
import time
from urllib.parse import urlparse
import yaml
import requests

from fingerprint import analyze_fingerprint
from session import check_session_strict_mode
from network import check_upload_progress_posture
from report import generate_json_report, generate_markdown_report, sanitize_target_name


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")


def load_config(config_path: str | None = None) -> dict:
    """Carga configuracion YAML o aplica valores predeterminados seguros."""
    target_path = config_path or DEFAULT_CONFIG_PATH
    if os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            sys.stderr.write(f"[WARN] No se pudo leer {target_path}: {e}. Usando defaults.\n")

    return {
        "general": {
            "user_agent": "php2shell-checker/1.0 (+defensive-audit; non-destructive)",
            "timeout_seconds": 5,
            "max_body_bytes": 8192,
            "verify_ssl": True,
        },
        "patched_versions": {
            "8.2": "8.2.35",
            "8.3": "8.3.36",
            "8.4": "8.4.27",
            "8.5": "8.5.12",
        },
        "weights": {
            "patched_version": 0.25,
            "session_strict_mode": 0.25,
            "upload_progress": 0.20,
            "body_limits": 0.20,
            "sapi_architecture": 0.10,
        },
        "thresholds": {
            "exposed_min": 0.51,
            "partially_exposed_min": 0.26,
            "mitigated_max": 0.25,
        },
    }


def is_private_or_loopback(hostname: str) -> bool:
    """Verifica si el hostname o IP pertenece a rangos loopback o privados RFC 1918."""
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local
    except ValueError:
        # Resolver nombre DNS para verificar la IP subyacente
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(resolved_ip)
            return ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local
        except (socket.error, ValueError):
            return False


def validate_target_guard(target_url: str, is_local_flag: bool, is_authorized_flag: bool) -> tuple[bool, str]:
    """
    Compuerta de seguridad y autorizacion estricta.
    - Entornos locales/privados requieren --local explicitamente.
    - Entornos externos requieren --authorized para confirmar alcance.
    """
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return False, f"Esquema no permitido '{parsed.scheme}'. Solo http:// o https://."

    if not parsed.hostname:
        return False, "URL invalida: falta hostname."

    hostname = parsed.hostname
    is_private = is_private_or_loopback(hostname)

    if is_private and not is_local_flag:
        return (
            False,
            f"El objetivo '{hostname}' es una direccion de red privada/loopback. "
            "Se requiere la bandera '--local' para autorizar ejecucion en laboratorio local."
        )

    if not is_private and not is_authorized_flag:
        return (
            False,
            f"El objetivo '{hostname}' es un host externo. "
            "Por directiva defensiva, debe proporcionarse la bandera '--authorized' "
            "declarando autorizacion escrita para auditar el sistema."
        )

    return True, "Guard verificado correctamente."


def evaluate_scoring(
    fp: dict,
    sess: dict,
    net: dict,
    config: dict
) -> tuple[str, float, dict, list[str]]:
    """
    Calcula el puntaje de exposicion y veredicto segun la matriz del plan.
    Retorna: (veredicto, score_pct, breakdown, remediations)
    """
    weights = config.get("weights", {})
    w_ver = weights.get("patched_version", 0.25)
    w_sess = weights.get("session_strict_mode", 0.25)
    w_upl = weights.get("upload_progress", 0.20)
    w_lim = weights.get("body_limits", 0.20)
    w_sapi = weights.get("sapi_architecture", 0.10)

    breakdown = {}
    remediations = []
    total_score = 0.0

    # 1. Version parcheada (peso 25%)
    if fp.get("is_unpatched_version") is True:
        ver_exp = 1.0
        ver_state = f"Version vulnerable ({fp.get('php_version')} < {fp.get('patched_target')})"
        remediations.append(
            f"Actualizar PHP de la version {fp.get('php_version')} a {fp.get('patched_target')} o superior."
        )
    elif fp.get("is_unpatched_version") is False:
        ver_exp = 0.0
        ver_state = f"Version parcheada o superior ({fp.get('php_version')})"
    else:
        # Version no revelada o no parseable
        ver_exp = 0.5
        ver_state = "Version no revelada por cabeceras (pasivo neutro)"
    
    total_score += w_ver * ver_exp
    breakdown["patched_version"] = {
        "name": "Version PHP Parcheada",
        "weight": w_ver,
        "state": ver_state,
        "exposure_contribution": w_ver * ver_exp,
    }

    # 2. session.use_strict_mode (peso 25%)
    strict_det = sess.get("use_strict_mode_detected")
    if strict_det is True:
        sess_exp = 0.0
        sess_state = "Activo (fuerza nuevo SID ante identificador no inicializado)"
    elif strict_det is False:
        sess_exp = 1.0
        sess_state = "Inactivo / expuesto (acepta SID arbitrario)"
        remediations.append("Configurar 'session.use_strict_mode = 1' en php.ini.")
    else:
        sess_exp = 0.5
        sess_state = "Inconcluso (ruta no emitio cookies de sesion)"

    total_score += w_sess * sess_exp
    breakdown["session_strict_mode"] = {
        "name": "session.use_strict_mode",
        "weight": w_sess,
        "state": sess_state,
        "exposure_contribution": w_sess * sess_exp,
    }

    # 3. upload_progress (peso 20%)
    upl_supp = net.get("upload_progress_supported")
    if upl_supp is True:
        upl_exp = 1.0
        upl_state = "Activo y procesa multipart con PHP_SESSION_UPLOAD_PROGRESS"
        remediations.append("Desactivar 'session.upload_progress.enabled = 0' en php.ini si no se requiere.")
    elif upl_supp is False:
        upl_exp = 0.0
        upl_state = "Bloqueado o no procesa formularios multipart"
    else:
        upl_exp = 0.5
        upl_state = "Inconcluso / no concluyente"

    total_score += w_upl * upl_exp
    breakdown["upload_progress"] = {
        "name": "session.upload_progress",
        "weight": w_upl,
        "state": upl_state,
        "exposure_contribution": w_upl * upl_exp,
    }

    # 4. Limites cuerpo / proxy (peso 20%)
    if net.get("body_limit_detected"):
        lim_exp = 0.0
        lim_state = "Limites defensivos activos detectados (HTTP 413)"
    else:
        # En una peticion menor a 1 KB no se dispara 413 habitualmente, pero si no hay proteccion explicita
        lim_exp = 0.5
        lim_state = "Sin limites restrictivos detectados en probe corta (< 10 KB)"
        remediations.append("Asegurar directivas 'client_max_body_size' (Nginx) o 'LimitRequestBody' (Apache) acotadas.")

    total_score += w_lim * lim_exp
    breakdown["body_limits"] = {
        "name": "Limites de Cuerpo y Proxy",
        "weight": w_lim,
        "state": lim_state,
        "exposure_contribution": w_lim * lim_exp,
    }

    # 5. SAPI conocido (peso 10%)
    sapi_hint = fp.get("sapi", {}).get("sapi_hint", "unknown")
    if sapi_hint == "fpm-proxy":
        sapi_exp = 0.9
        sapi_state = "PHP-FPM con frontal proxy detectado (Master hereda ASLR a workers)"
        if fp.get("is_unpatched_version"):
            remediations.append(
                "ADVERTENCIA DE ARQUITECTURA (PHP-FPM): Los workers heredan el layout virtual del Master (0 bits de entropia). "
                "Aunque la aplicacion carezca de LFI/gadgets, el motor permanece expuesto a corrupcion en Request Startup (E-OOM). "
                "Aplicar parche de vendor >= 8.4.27 de inmediato."
            )
    elif sapi_hint == "cli-server":
        sapi_exp = 1.0
        sapi_state = "PELIGRO CRITICO: PHP Built-in CLI Server expuesto (reuso persistente de workers tras OOM / Chain D)"
        remediations.append(
            "CRITICO: No exponer 'php -S' (CLI server) a redes de produccion o trafico no confiable. "
            "Migrar de inmediato a un entorno aislado con PHP-FPM o Apache con workers descartables."
        )
    elif sapi_hint == "mod_php":
        sapi_exp = 0.8
        sapi_state = "Apache mod_php detectado (reuso directo de workers en el mismo proceso)"
    else:
        sapi_exp = 0.3
        sapi_state = f"SAPI {sapi_hint} / no concluyente"

    total_score += w_sapi * sapi_exp
    breakdown["sapi_architecture"] = {
        "name": "Arquitectura SAPI",
        "weight": w_sapi,
        "state": sapi_state,
        "exposure_contribution": w_sapi * sapi_exp,
    }

    # Veredicto
    thresholds = config.get("thresholds", {})
    exp_min = thresholds.get("exposed_min", 0.51)
    part_min = thresholds.get("partially_exposed_min", 0.26)

    # Si ninguna peticion respondio correctamente o no se detecta PHP
    if fp.get("error") and sess.get("error") and net.get("error"):
        verdict = "INCONCLUSIVE"
    elif not fp.get("is_php") and sess.get("use_strict_mode_detected") is None:
        verdict = "INCONCLUSIVE"
        remediations.clear()
        remediations.append("El objetivo no expone cabeceras PHP ni comportamiento concluyente de sesiones PHP.")
    elif total_score >= exp_min:
        verdict = "EXPOSED"
    elif total_score >= part_min:
        verdict = "PARTIALLY_EXPOSED"
    else:
        verdict = "MITIGATED"

    score_pct = total_score * 100
    return verdict, score_pct, breakdown, remediations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="php2shell-checker: diagnostico no destructivo de postura PHP."
    )
    parser.add_argument("--url", required=True, help="URL base del objetivo (ej. http://127.0.0.1:8080/)")
    parser.add_argument("--local", action="store_true", help="Autorizar ejecucion contra loopback o red privada RFC 1918")
    parser.add_argument("--authorized", action="store_true", help="Declarar autorizacion formal escrita para host externo")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout maximo por peticion en segundos (default: 5)")
    parser.add_argument("--config", default=None, help="Ruta a archivo config.yaml personalizado")
    parser.add_argument("--dry-run", action="store_true", help="Simular sin enviar peticiones HTTP reales")
    parser.add_argument("--json", dest="json_out", default=None, help="Ruta para guardar reporte en formato JSON")
    parser.add_argument("--md", dest="md_out", default=None, help="Ruta para guardar reporte en formato Markdown")
    parser.add_argument("--verbose", action="store_true", help="Mostrar salida detallada en consola")

    args = parser.parse_args()

    # 1. Cargar configuracion
    config = load_config(args.config)
    gen_conf = config.get("general", {})
    timeout = args.timeout or gen_conf.get("timeout_seconds", 5)
    user_agent = gen_conf.get("user_agent", "php2shell-checker/1.0")
    verify_ssl = gen_conf.get("verify_ssl", True)

    # 2. Guard de seguridad y autorizacion
    is_valid, msg = validate_target_guard(args.url, args.local, args.authorized)
    if not is_valid:
        sys.stderr.write(f"[ERROR COMPUERTA DE SEGURIDAD] {msg}\n")
        return 2

    print(f"[*] Objetivo: {args.url}")
    print(f"[*] Modo: {'Local / Lab' if args.local else 'Externo Autorizado'}")
    print(f"[*] Garantia: No destructivo, cuerpo < 10 KB, max 3 peticiones.")

    if args.dry_run:
        print("\n--- MODO DRY-RUN: Simulacion de peticiones ---")
        print("1. GET / [Fingerprint pasivo de cabeceras Server y X-Powered-By]")
        print("2. GET / [Evaluacion de session.use_strict_mode con Cookie: PHPSESSID=checker_probe_<rand>]")
        print("3. POST / [Comprobacion inocua multipart con PHP_SESSION_UPLOAD_PROGRESS y archivo < 500 bytes]")
        print("[*] Dry-run finalizado exitosamente. No se emitio trafico.")
        return 0

    # 3. Inicializar sesion HTTP
    http_session = requests.Session()
    total_requests = 0

    # 4. Fase 1: Fingerprint
    print("[*] Ejecutando Fase 1: Fingerprint de version y SAPI...")
    fp_res = analyze_fingerprint(
        args.url,
        http_session,
        timeout=timeout,
        user_agent=user_agent,
        patched_versions=config.get("patched_versions"),
        verify_ssl=verify_ssl
    )
    total_requests += 1

    time.sleep(1)

    # 5. Fase 2: Session strict mode
    print("[*] Ejecutando Fase 2: Evaluacion de session.use_strict_mode...")
    sess_res = check_session_strict_mode(
        args.url,
        http_session,
        timeout=timeout,
        user_agent=user_agent,
        verify_ssl=verify_ssl
    )
    total_requests += 1

    time.sleep(1)

    # 6. Fase 3: Network / upload_progress probe
    print("[*] Ejecutando Fase 3: Evaluacion de upload_progress y limites multipart...")
    net_res = check_upload_progress_posture(
        args.url,
        http_session,
        timeout=timeout,
        user_agent=user_agent,
        verify_ssl=verify_ssl
    )
    total_requests += 1

    # 7. Correlacion y scoring
    verdict, score_pct, breakdown, remediations = evaluate_scoring(
        fp_res, sess_res, net_res, config
    )

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report_data = {
        "metadata": {
            "target": args.url,
            "timestamp": now_iso,
            "mode": "local_lab" if args.local else "external_authorized",
            "non_destructive_guarantee": "Cumplida: peticiones inocuas < 10 KB, sin heap grooming ni OOM",
            "total_requests": total_requests,
        },
        "verdict": verdict,
        "exposure_score_pct": score_pct,
        "score_breakdown": breakdown,
        "fingerprint": fp_res,
        "session": sess_res,
        "network": net_res,
        "remediations": remediations,
    }

    # 8. Mostrar resumen por consola
    print("\n================ RESULTADOS DEL DIAGNOSTICO ================")
    print(f"Veredicto:          {verdict}")
    print(f"Indice Exposicion:  {score_pct:.1f}%")
    print(f"Version PHP:        {fp_res.get('php_version') or 'No revelada'}")
    print(f"Servidor Web:       {fp_res.get('server') or 'No revelado'}")
    print(f"SAPI Estimada:      {fp_res.get('sapi', {}).get('sapi_hint', 'desconocido')}")
    print(f"Strict Mode:        {sess_res.get('details', 'N/A')}")
    print(f"Upload Progress:    {net_res.get('details', 'N/A')}")
    print("============================================================\n")

    # 9. Guardar reportes si fueron especificados
    if args.json_out:
        generate_json_report(report_data, args.json_out)
        print(f"[+] Reporte JSON guardado en: {args.json_out}")

    if args.md_out:
        generate_markdown_report(report_data, args.md_out)
        print(f"[+] Reporte Markdown guardado en: {args.md_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
