#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pivoting OSINT sobre los IOCs hallados en la primera pasada de dark web.

Idea: la 1ª pasada busca el DOMINIO. Si encuentra IOCs (emails comprometidos,
credenciales/combos, dominios o .onion relacionados), el pivoting RELANZA la
búsqueda usando esos IOCs como nuevas queries. Así se destapan foros y dumps
donde el dominio no se nombra pero sí aparece un email o una credencial suya.

Profundidad 1 y con LÍMITES estrictos (máx. N semillas por tipo) para no
explotar en tiempo ni en ruido. 100% pasivo: solo lectura de contenido público.

Nota: los hits de pivoting se reportan en su propia sección y NO escalan
automáticamente el nivel de riesgo (el matching por subcadena puede dar falsos
positivos); es el analista quien valida.
"""

import os
from typing import Dict, List

from .utils import get_logger

log = get_logger()

# Límite de semillas por tipo (email/credencial/dominio). Ajustable por entorno.
PIVOT_MAX_PER_TYPE = int(os.getenv("PIVOT_MAX_PER_TYPE", "3"))


def _dedup_cap(items: List[str], cap: int) -> List[str]:
    """Elimina duplicados preservando orden y recorta a `cap` elementos."""
    out: List[str] = []
    seen = set()
    for x in items:
        x = (x or "").strip()
        if not x or x.lower() in seen:
            continue
        seen.add(x.lower())
        out.append(x)
        if len(out) >= cap:
            break
    return out


def collect_pivot_seeds(summary: Dict, domain: str, breaches: Dict = None,
                        max_per_type: int = PIVOT_MAX_PER_TYPE) -> Dict[str, List[str]]:
    """
    Recoge las semillas de pivot de la 1ª pasada:
      · emails        → emails (del dominio y otros) hallados en leaks
      · credenciales  → pares user:pass / email:pass (combolists)
      · dominios      → dominios y .onion RELACIONADOS (no el propio objetivo)
    """
    domain = (domain or "").lower().strip()

    # `summary['iocs']` puede ser {tipo:[...]} o el envoltorio {iocs:{...},...}.
    iocs = (summary or {}).get("iocs", {}) or {}
    if isinstance(iocs.get("iocs"), dict):
        iocs = iocs["iocs"]

    emails = list(iocs.get("emails_dominio", []) or [])
    for e in (iocs.get("emails", []) or []):
        if e not in emails:
            emails.append(e)
    # Emails de la capa de brechas (tolerante a distintos nombres de clave).
    if isinstance(breaches, dict):
        for key in ("compromised_email_list", "emails", "compromised_emails"):
            val = breaches.get(key)
            if isinstance(val, list):
                for e in val:
                    if isinstance(e, str) and "@" in e and e not in emails:
                        emails.append(e)

    creds = list(iocs.get("credenciales", []) or [])

    # Dominios/.onion RELACIONADOS: excluye el propio objetivo y sus subdominios.
    dominios: List[str] = []
    for d in (iocs.get("dominios", []) or []):
        d = d.lower()
        if domain and (d == domain or d.endswith("." + domain)):
            continue
        dominios.append(d)
    for o in (iocs.get("onion", []) or []):
        dominios.append(o.lower())

    return {
        "emails":       _dedup_cap(emails, max_per_type),
        "credenciales": _dedup_cap(creds, max_per_type),
        "dominios":     _dedup_cap(dominios, max_per_type),
    }


def run_pivot(domain: str, summary: Dict, breaches: Dict = None,
              use_tor: bool = False, max_per_type: int = PIVOT_MAX_PER_TYPE) -> Dict:
    """
    Ejecuta el pivoting: recoge semillas y relanza la búsqueda en foros y, si Tor
    está activo, en motores .onion. Devuelve {status, seeds, hits, total}.
    """
    seeds = collect_pivot_seeds(summary, domain, breaches, max_per_type)
    todas = seeds["emails"] + seeds["credenciales"] + seeds["dominios"]

    result = {"status": "success", "seeds": seeds, "hits": [],
              "total": 0, "seeds_usadas": len(todas)}
    if not todas:
        result["status"] = "sin_semillas"
        log.info("   [*] Pivoting: no hay IOCs accionables para pivotar.")
        return result

    log.info("   [*] Pivoting sobre %d semilla(s): %d email · %d cred · %d dominio/.onion",
             len(todas), len(seeds["emails"]), len(seeds["credenciales"]), len(seeds["dominios"]))

    hits: List[Dict] = []

    # 1) Foros del registro (incluye los .onion configurados en darkweb_onions.json).
    try:
        from .darkweb_forums import search_all_forums
        fr = search_all_forums(domain, terms=todas)
        for h in (fr.get("hits", []) or []):
            h["pivot"] = True
            hits.append(h)
    except Exception as e:  # noqa: BLE001
        log.debug("pivot forums: %s", e)

    # 2) Motores .onion (búsqueda literal de cada semilla) — solo con Tor.
    if use_tor:
        try:
            from .darkweb_sources import search_terms_in_tor_engines
            for h in search_terms_in_tor_engines(todas, max_terms=len(todas)):
                h["pivot"] = True
                hits.append(h)
        except Exception as e:  # noqa: BLE001
            log.debug("pivot tor_engines: %s", e)

    # Dedup por (fuente, extracto/url).
    vistos = set()
    unicos: List[Dict] = []
    for h in hits:
        clave = (h.get("fuente") or h.get("foro", ""),
                 (h.get("extracto") or h.get("url") or "")[:120])
        if clave in vistos:
            continue
        vistos.add(clave)
        unicos.append(h)

    result["hits"] = unicos
    result["total"] = len(unicos)
    log.info("   [=] Pivoting: %d hit(s) nuevos a partir de IOCs", len(unicos))
    return result
