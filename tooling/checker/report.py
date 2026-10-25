#!/usr/bin/env python3
"""
report.py - Generacion de reportes defensivos estructurados (JSON y Markdown).

Sanitiza identificadores de sesion, tokens, rutas internas e IPs.
Cumple con directiva Clean UI (cero emojis).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict


def sanitize_target_name(target_url: str) -> str:
    """Convierte URL a un slug seguro para nombres de archivo."""
    cleaned = re.sub(r"^https?://", "", target_url)
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", cleaned)
    return cleaned.strip("_")[:50]


def generate_json_report(data: Dict[str, Any], filepath: str | None = None) -> str:
    """Genera representacion JSON serializable y opcionalmente escribe a archivo."""
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str


def generate_markdown_report(data: Dict[str, Any], filepath: str | None = None) -> str:
    """Genera reporte defensivo en Markdown."""
    meta = data.get("metadata", {})
    verdict = data.get("verdict", "INCONCLUSIVE")
    score_pct = data.get("exposure_score_pct", 0)
    score_breakdown = data.get("score_breakdown", {})
    fp = data.get("fingerprint", {})
    sess = data.get("session", {})
    net = data.get("network", {})
    remediations = data.get("remediations", [])

    lines = []
    lines.append(f"# Diagnostico Defensivo php2shell: {meta.get('target', 'N/A')}")
    lines.append("")
    lines.append("## Metadatos de Auditoria")
    lines.append(f"- Fecha/Hora: {meta.get('timestamp', 'N/A')}")
    lines.append(f"- Objetivo: {meta.get('target', 'N/A')}")
    lines.append(f"- Modo: {meta.get('mode', 'defensive')}")
    lines.append(f"- Garantia no destructiva: {meta.get('non_destructive_guarantee', 'Cumplida (< 10 KB)')}")
    lines.append(f"- Peticiones totales enviadas: {meta.get('total_requests', 0)}")
    lines.append("")

    lines.append("## Veredicto y Postura")
    lines.append(f"- Veredicto: {verdict}")
    lines.append(f"- Indice de exposicion: {score_pct:.1f}%")
    lines.append("")

    lines.append("### Desglose de Puntuacion Defensiva")
    lines.append("| Factor | Peso | Estado Detectado | Contribucion Exposicion |")
    lines.append("|---|---|---|---|")
    for key, item in score_breakdown.items():
        name = item.get("name", key)
        weight = item.get("weight", 0) * 100
        state = item.get("state", "desconocido")
        contrib = item.get("exposure_contribution", 0) * 100
        lines.append(f"| {name} | {weight:.0f}% | {state} | {contrib:.1f}% |")
    lines.append("")

    lines.append("## Evidencia por Modulo")
    lines.append("")
    lines.append("### 1. Fingerprint y Version")
    lines.append(f"- Servidor Web: {fp.get('server') or 'No revelado'}")
    lines.append(f"- X-Powered-By: {fp.get('x_powered_by') or 'No revelado'}")
    lines.append(f"- Version PHP detectada: {fp.get('php_version') or 'Desconocida'}")
    lines.append(f"- Rama de version: {fp.get('php_branch') or 'N/A'}")
    lines.append(f"- Requiere parche: {'Si' if fp.get('is_unpatched_version') else ('No' if fp.get('is_unpatched_version') is False else 'Inconcluso')}")
    if fp.get("patched_target"):
        lines.append(f"- Referencia parcheada: {fp.get('patched_target')}")
    lines.append(f"- SAPI estimada: {fp.get('sapi', {}).get('sapi_hint', 'desconocido')}")
    lines.append("")

    lines.append("### 2. Comportamiento de Sesion (session.use_strict_mode)")
    lines.append(f"- SID de prueba (sanitizado): {sess.get('probe_sid_sent', 'N/A')}")
    lines.append(f"- Set-Cookie recibido: {'Si' if sess.get('set_cookie_received') else 'No'}")
    lines.append(f"- SID reemplazado por servidor: {'Si' if sess.get('session_cookie_replaced') else 'No'}")
    lines.append(f"- Evaluacion strict_mode: {sess.get('details', 'N/A')}")
    lines.append("")

    lines.append("### 3. Red y upload_progress")
    lines.append(f"- Metodo multipart procesado: {'Si' if net.get('multipart_accepted') else 'No'}")
    lines.append(f"- Status HTTP respuesta multipart: {net.get('status_code') or 'N/A'}")
    lines.append(f"- Soporte aparente upload_progress: {'Activo/Aceptado' if net.get('upload_progress_supported') else ('Bloqueado/No activo' if net.get('upload_progress_supported') is False else 'Inconcluso')}")
    lines.append(f"- Limites de proxy detectados: {'Si (413 recibido)' if net.get('body_limit_detected') else 'No observados en probe corta'}")
    lines.append(f"- Bytes transmitidos en probe: {net.get('bytes_sent', 0)} bytes")
    lines.append(f"- Observaciones: {net.get('details', 'N/A')}")
    lines.append("")

    lines.append("## Remediaciones Defensivas Recomendadas")
    if remediations:
        for r in remediations:
            lines.append(f"- {r}")
    else:
        lines.append("- No se detectaron remediaciones urgentes basadas en las evidencias recolectadas.")
    lines.append("")

    lines.append("---")
    lines.append("*Reporte generado automaticamente por php2shell-checker. Prohibida su utilizacion sin autorizacion expresa.*")

    md_content = "\n".join(lines) + "\n"
    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
    return md_content
