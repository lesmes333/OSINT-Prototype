#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modo monitorización: compara el escaneo actual con el anterior del mismo dominio.

Busca el informe JSON previo (`activos_<dominio>_<fecha>.json`) en la carpeta de
salida y calcula qué ha cambiado desde entonces:

  - Subdominios nuevos / desaparecidos.
  - CVEs nuevos (identificadores CVE-XXXX-XXXX que no estaban antes).
  - Puertos abiertos nuevos (de los datos de Shodan, si están disponibles).

Pensado para ejecutar la herramienta de forma periódica (p. ej. con cron) y
detectar de un vistazo la nueva superficie de exposición. No modifica nada:
solo lee informes previos y devuelve un resumen de cambios.
"""

import glob
import json
import os
import re
from typing import Dict, Optional

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _find_previous_report(output_dir: str, dominio_slug: str) -> Optional[str]:
    """Devuelve la ruta del informe JSON (activos) más reciente del dominio, o None.

    Busca tanto el layout actual (un escaneo = una subcarpeta
    `<dominio>_<fecha>/<dominio>_activos_<fecha>.json`) como los nombres planos
    antiguos en la raíz, y tolera ambos órdenes de nombre (dominio-primero y el
    formato heredado `activos_<dominio>_*`).

    El nombre de archivo ya NO se asume cronológicamente ordenable (la fecha es
    europea dd-mm-aaaa), así que se ordena por FECHA DE MODIFICACIÓN del fichero,
    que sí es fiable independientemente del formato del nombre.
    """
    patrones = [
        # Layout actual: una subcarpeta por escaneo.
        os.path.join(output_dir, "*", f"{dominio_slug}_activos_*.json"),
        os.path.join(output_dir, "*", f"activos_{dominio_slug}_*.json"),
        # Nombres planos en la raíz (compatibilidad con escaneos antiguos).
        os.path.join(output_dir, f"{dominio_slug}_activos_*.json"),
        os.path.join(output_dir, f"activos_{dominio_slug}_*.json"),
    ]
    ficheros = set()
    for patron in patrones:
        ficheros.update(glob.glob(patron))
    if not ficheros:
        return None
    # El más recientemente escrito es el escaneo anterior.
    return max(ficheros, key=os.path.getmtime)


def _extract_snapshot(data: Dict) -> Dict[str, set]:
    """Reduce un informe completo a los conjuntos que queremos comparar."""
    discovery = data.get("discovery", {}) or {}
    threat = data.get("threat_intel", {}) or {}

    subdominios = {s for s in discovery.get("subdomains", []) if isinstance(s, str)}

    # CVEs: los extraemos por expresión regular sobre todo el bloque de
    # vulnerabilidades para no depender de la estructura interna exacta.
    vulnerabilities = threat.get("vulnerabilities", {})
    cves = {m.upper() for m in CVE_RE.findall(json.dumps(vulnerabilities, default=str))}

    # Puertos abiertos (Shodan): "ip:puerto" para distinguir por host.
    puertos = set()
    shodan = threat.get("shodan", {})
    if isinstance(shodan, dict):
        ip = shodan.get("ip") or data.get("dominio_analizado", "")
        for p in shodan.get("ports", []) or []:
            puertos.add(f"{ip}:{p}")

    return {"subdominios": subdominios, "cves": cves, "puertos": puertos}


def compute(current_data: Dict, output_dir: str, dominio_slug: str) -> Dict:
    """
    Compara el escaneo actual con el informe previo más reciente.

    Devuelve un dict con la forma:
      {
        "status": "ok" | "sin_referencia",
        "previo": <ruta del informe anterior>,
        "previo_timestamp": <timestamp del informe anterior>,
        "subdominios_nuevos": [...], "subdominios_eliminados": [...],
        "cves_nuevos": [...], "puertos_nuevos": [...],
        "hay_cambios": bool,
      }
    """
    previo_path = _find_previous_report(output_dir, dominio_slug)
    if not previo_path:
        return {"status": "sin_referencia", "hay_cambios": False}

    try:
        with open(previo_path, encoding="utf-8") as fh:
            previo = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"status": "sin_referencia", "hay_cambios": False}

    ant = _extract_snapshot(previo)
    act = _extract_snapshot(current_data)

    subs_nuevos = sorted(act["subdominios"] - ant["subdominios"])
    subs_fuera = sorted(ant["subdominios"] - act["subdominios"])
    cves_nuevos = sorted(act["cves"] - ant["cves"])
    puertos_nuevos = sorted(act["puertos"] - ant["puertos"])

    hay_cambios = bool(subs_nuevos or subs_fuera or cves_nuevos or puertos_nuevos)

    return {
        "status": "ok",
        "previo": previo_path,
        "previo_timestamp": previo.get("timestamp", ""),
        "subdominios_nuevos": subs_nuevos,
        "subdominios_eliminados": subs_fuera,
        "cves_nuevos": cves_nuevos,
        "puertos_nuevos": puertos_nuevos,
        "hay_cambios": hay_cambios,
    }
