#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Diagnóstico de salud del escaneo.

Analiza el resultado de las APIs de threat intelligence y el estado de las
herramientas externas (subfinder, Docker, Tor, searchsploit) para informar de:
  - Qué APIs funcionaron, cuáles no tienen clave, cuáles tienen la clave
    caducada/inválida y cuáles han agotado la cuota.
  - Cómo solucionar cada problema (URL para renovar la clave / comando de
    instalación de la herramienta).

El escaneo NUNCA se detiene por estos fallos: simplemente se documentan para
que el usuario los corrija y vuelva a lanzar la herramienta.
"""

import os
import shutil
import socket
import subprocess
from typing import Dict, List

from .utils import get_logger

log = get_logger()

# Metadatos de cada API: variable(s) de entorno y URL para renovar la clave.
API_META = {
    "virustotal": {"name": "VirusTotal", "env": ["VIRUSTOTAL_API_KEY"], "renew": "https://www.virustotal.com/gui/my-apikey"},
    "shodan": {"name": "Shodan", "env": ["SHODAN_API_KEY"], "renew": "https://account.shodan.io"},
    "censys": {"name": "Censys", "env": ["CENSYS_PAT"], "renew": "https://platform.censys.io"},
    "alienvault": {"name": "AlienVault OTX", "env": ["ALIENVAULT_API_KEY"], "renew": "https://otx.alienvault.com/settings"},
    "ipinfo": {"name": "IPinfo", "env": ["IPINFO_API_KEY"], "renew": "https://ipinfo.io/account/token"},
    "ipdata": {"name": "IPdata", "env": ["IPDATA_API_KEY"], "renew": "https://ipdata.co/sign-up.html"},
    "hunter": {"name": "Hunter.io", "env": ["HUNTER_API_KEY"], "renew": "https://hunter.io/api-keys"},
    "urlscan": {"name": "urlscan.io", "env": ["URLSCAN_API_KEY"], "renew": "https://urlscan.io/user/profile/"},
    "abuseipdb": {"name": "AbuseIPDB", "env": ["ABUSEIPDB_API_KEY"], "renew": "https://www.abuseipdb.com/account/api"},
    "github": {"name": "GitHub", "env": ["GITHUB_TOKEN"], "renew": "https://github.com/settings/tokens"},
    "gitlab": {"name": "GitLab", "env": ["GITLAB_TOKEN"], "renew": "https://gitlab.com/-/profile/personal_access_tokens"},
}

# Estados normalizados y su presentación
STATUS_LABEL = {
    "ok": "OK",
    "no_api_key": "Sin clave",
    "invalid_key": "Clave inválida / caducada",
    "quota_exceeded": "Cuota agotada",
    "error": "Error",
}


def _normalize_status(api_result: Dict) -> str:
    """Reduce el resultado de una API a uno de los estados normalizados."""
    if not isinstance(api_result, dict):
        return "error"
    status = api_result.get("status")
    if status == "ok":
        return "ok"
    if status == "no_api_key":
        return "no_api_key"
    if status == "error":
        return api_result.get("error_type") or "error"
    return "error"


def analyze_apis(threat_results: Dict) -> List[Dict]:
    """
    Devuelve una lista de diagnósticos por API:
      {key, name, status, label, message, action, env, renew}
    Ordenada para que los problemas accionables aparezcan primero.
    """
    rows = []
    for key, meta in API_META.items():
        result = threat_results.get(key, {})
        status = _normalize_status(result)
        message = result.get("message", "") if isinstance(result, dict) else ""

        if status == "ok":
            action = ""
        elif status == "no_api_key":
            action = f"Añade {'/'.join(meta['env'])} en .env (regístrate en {meta['renew']})"
        elif status == "invalid_key":
            action = f"⚠️ Renueva {'/'.join(meta['env'])} en {meta['renew']} y actualiza .env"
        elif status == "quota_exceeded":
            action = f"Cuota agotada: espera o mejora tu plan en {meta['renew']}"
        else:
            action = f"Revisa {'/'.join(meta['env'])} ({meta['renew']})"

        rows.append({
            "key": key,
            "name": meta["name"],
            "status": status,
            "label": STATUS_LABEL.get(status, status),
            "message": message,
            "action": action,
            "env": meta["env"],
            "renew": meta["renew"],
        })

    priority = {"invalid_key": 0, "quota_exceeded": 1, "error": 2, "no_api_key": 3, "ok": 4}
    rows.sort(key=lambda r: (priority.get(r["status"], 9), r["name"]))
    return rows


# ------------------------------------------------------------
# Herramientas externas
# ------------------------------------------------------------
def _tor_running(host: str = "127.0.0.1", port: int = 9050) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            return s.connect_ex((host, port)) == 0
    except Exception:  # noqa: BLE001
        return False


def _docker_running() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=8).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def analyze_tools() -> List[Dict]:
    """
    Comprueba la disponibilidad de las herramientas externas opcionales y
    devuelve su estado + cómo instalarlas/activarlas. Ninguna es obligatoria.
    """
    subfinder = shutil.which("subfinder") is not None
    searchsploit = shutil.which("searchsploit") is not None
    docker = _docker_running()
    tor = _tor_running()

    return [
        {
            "tool": "Subfinder", "ok": subfinder, "impact": "Más subdominios",
            "fix": "brew install subfinder  |  apt install subfinder",
        },
        {
            "tool": "Docker", "ok": docker, "impact": "Fingerprinting (Wappalyzer)",
            "fix": "Instala/arranca Docker Desktop · https://www.docker.com/",
        },
        {
            "tool": "searchsploit", "ok": searchsploit, "impact": "Exploits (Exploit-DB)",
            "fix": "brew install exploitdb  |  apt install exploitdb",
        },
        {
            "tool": "Tor (127.0.0.1:9050)", "ok": tor, "impact": "Dark web",
            "fix": "brew services start tor  |  systemctl start tor",
        },
    ]


def build(threat_results: Dict, include_tools: bool = True) -> Dict:
    """Construye el bloque de diagnóstico completo para UI e informes."""
    apis = analyze_apis(threat_results)
    tools = analyze_tools() if include_tools else []

    keys_to_fix = [a for a in apis if a["status"] in ("invalid_key", "quota_exceeded")]
    if keys_to_fix:
        for a in keys_to_fix:
            log.warning(f"   [!] {a['name']}: {a['label']} → {a['action']}")

    return {
        "apis": apis,
        "tools": tools,
        "apis_ok": sum(1 for a in apis if a["status"] == "ok"),
        "apis_total": len(apis),
        "keys_to_fix": keys_to_fix,
        "tools_missing": [t for t in tools if not t["ok"]],
    }
