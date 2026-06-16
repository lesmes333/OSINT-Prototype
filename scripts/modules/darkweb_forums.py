#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Registro data-driven de foros y mercados de la dark web para monitorización.

Por qué data-driven y no direcciones .onion hardcodeadas:
  Los foros de leaks cambian de dirección .onion con MUCHA frecuencia (incautaciones,
  rebrandings, mirrors). Hardcodear una dirección que mañana estará caída solo
  genera timeouts silenciosos y una falsa sensación de cobertura. Por eso:

    · Los METADATOS estables (nombre, idioma, tipo, mirror clearnet, search path)
      viven aquí, en FORUM_REGISTRY.
    · Las DIRECCIONES .onion (volátiles) se cargan desde un archivo externo
      editable —darkweb_onions.json— que el operador rellena con las direcciones
      verificadas actuales. Ese archivo está en .gitignore: nunca se sube.
    · Para los foros sin dirección conocida, se descubren menciones vía los
      motores .onion (Ahmia/Torch) buscando "<dominio>" + nombre del foro.

Todo el acceso es pasivo: solo búsquedas GET de lectura sobre contenido público.
No se interactúa con logins ni formularios.
"""

import json
import os
import re
from typing import Dict, List, Optional

from bs4 import BeautifulSoup

from .utils import get_logger
from .tor_utils import tor_session, clearnet_session, request_with_retry
from .ioc_extractor import extract_iocs

log = get_logger()

# Archivo externo (gitignored) con direcciones .onion verificadas y actuales.
# Se puede sobreescribir su ruta con la variable de entorno DARKWEB_ONIONS_FILE.
ONIONS_CONFIG_ENV = "DARKWEB_ONIONS_FILE"
ONIONS_CONFIG_DEFAULT = "darkweb_onions.json"


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRO DE FOROS / MERCADOS  (metadatos estables, NO direcciones volátiles)
# ─────────────────────────────────────────────────────────────────────────────
# Campos:
#   key            identificador interno (se usa para casar con darkweb_onions.json)
#   name           nombre legible
#   lang           idioma principal (en/ru/es/mixto)
#   content        qué tipo de leaks/contenido predomina
#   clearnet       URL de mirror clearnet con búsqueda, o "" si no hay/known-stable
#   search_path    plantilla de búsqueda ({q} = término), relativa al host
#   method         "search"   → tiene endpoint de búsqueda (clearnet u .onion)
#                  "discover" → solo se busca por menciones en motores .onion
#   requires_login si la búsqueda real necesita cuenta (afecta la fiabilidad)
#   cloudflare     si suele tener challenge JS (un GET simple puede fallar)
#
# Las direcciones .onion NO van aquí: se inyectan desde darkweb_onions.json.
FORUM_REGISTRY: List[Dict] = [
    {
        "key": "darkforums", "name": "DarkForums", "lang": "en",
        "content": "Leaks masivos, databases, stealer logs",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "search", "requires_login": True, "cloudflare": True,
    },
    {
        "key": "dread", "name": "Dread", "lang": "en",
        "content": "Discusiones estilo Reddit, leaks, market intel",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "discover", "requires_login": False, "cloudflare": False,
    },
    {
        "key": "xss", "name": "XSS.is", "lang": "ru/en",
        "content": "Exploits, accesos iniciales, leaks",
        "clearnet": "https://xss.is", "search_path": "/search/?q={q}",
        "method": "search", "requires_login": True, "cloudflare": True,
    },
    {
        "key": "exploit", "name": "Exploit.in", "lang": "ru",
        "content": "Exploits, accesos, leaks antiguos",
        "clearnet": "https://exploit.in", "search_path": "/search?q={q}",
        "method": "search", "requires_login": True, "cloudflare": True,
    },
    {
        "key": "breachforums", "name": "BreachForums", "lang": "en",
        "content": "Grandes dumps y reventa de bases",
        "clearnet": "", "search_path": "/search?q={q}&action=results",
        "method": "search", "requires_login": False, "cloudflare": True,
    },
    {
        "key": "bhf", "name": "BHF (BlackHatForums)", "lang": "ru",
        "content": "Cybercrime general",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "search", "requires_login": True, "cloudflare": True,
    },
    {
        "key": "damagelib", "name": "DamageLib", "lang": "en/ru",
        "content": "Malware, exploits, leaks (ex-mods de XSS)",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "discover", "requires_login": True, "cloudflare": False,
    },
    {
        "key": "cracked", "name": "Cracked.io", "lang": "en",
        "content": "Cracking, leaks, tools",
        "clearnet": "https://cracked.io", "search_path": "/search?q={q}",
        "method": "search", "requires_login": False, "cloudflare": True,
    },
    {
        "key": "nulled", "name": "Nulled.to", "lang": "en",
        "content": "Cracking, leaks, tools",
        "clearnet": "https://www.nulled.to",
        "search_path": "/search/index.php?app=core&module=search&do=search&keywords={q}",
        "method": "search", "requires_login": False, "cloudflare": True,
    },
    # ── Mercados de credenciales (orientados a venta; solo descubrimiento) ──────
    {
        "key": "russianmarket", "name": "Russian Market", "lang": "ru/en",
        "content": "Venta de logs/credenciales/stealer",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "discover", "requires_login": True, "cloudflare": False,
    },
    {
        "key": "briansclub", "name": "Brian's Club", "lang": "en",
        "content": "Venta de tarjetas (carding)",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "discover", "requires_login": True, "cloudflare": False,
    },
    {
        "key": "styx", "name": "STYX Market", "lang": "en/ru",
        "content": "Fraude financiero, credenciales",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "discover", "requires_login": True, "cloudflare": False,
    },
    {
        "key": "abacus", "name": "Abacus Market", "lang": "en",
        "content": "Marketplace general (incl. datos)",
        "clearnet": "", "search_path": "/search?q={q}",
        "method": "discover", "requires_login": True, "cloudflare": False,
    },
]


def load_forum_targets() -> List[Dict]:
    """
    Devuelve el registro de foros con las direcciones .onion inyectadas desde el
    archivo externo darkweb_onions.json (si existe).

    Formato esperado del JSON (todas las claves opcionales):
        {
          "darkforums": {"onion": "http://xxxx.onion", "clearnet": "https://..."},
          "dread":      {"onion": "http://yyyy.onion"},
          ...
        }
    El override puede aportar tanto la .onion (lo habitual) como corregir/añadir
    la URL clearnet. Las claves deben coincidir con el campo "key" del registro.
    """
    overrides = _read_onions_config()
    targets: List[Dict] = []
    for forum in FORUM_REGISTRY:
        item = dict(forum)
        ov = overrides.get(forum["key"], {})
        if ov.get("onion"):
            item["onion"] = ov["onion"].rstrip("/")
        if ov.get("clearnet"):
            item["clearnet"] = ov["clearnet"].rstrip("/")
        item.setdefault("onion", "")
        targets.append(item)
    return targets


def _read_onions_config() -> Dict[str, Dict]:
    """Lee darkweb_onions.json (o el indicado por DARKWEB_ONIONS_FILE). Tolerante a fallos."""
    path = os.getenv(ONIONS_CONFIG_ENV, ONIONS_CONFIG_DEFAULT)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            n = sum(1 for v in data.values() if isinstance(v, dict) and v.get("onion"))
            log.info("   [*] darkweb_onions.json cargado: %d direcciones .onion", n)
            return data
    except (OSError, ValueError) as e:
        log.debug("darkweb_onions config: %s", e)
    return {}


def _domain_search_terms(domain: str) -> List[str]:
    """Términos a buscar dentro de un foro (dominio y nombre base)."""
    base = domain.split(".")[0]
    return list(dict.fromkeys([domain, f"@{domain}", base]))


def _extract_forum_hits(html: str, terms: List[str], forum: Dict,
                        url: str, via_tor: bool, domain: str) -> List[Dict]:
    """Busca los términos en el HTML, extrae extractos y los IOCs de cada uno."""
    hits: List[Dict] = []
    soup = BeautifulSoup(html, "html.parser")
    text_full = html.lower()
    for term in terms:
        if term.lower() not in text_full:
            continue
        for el in soup.find_all(["div", "li", "article", "tr", "p", "span", "a"]):
            text = el.get_text()
            if term.lower() in text.lower() and 20 < len(text) < 2000:
                extracto = re.sub(r"\s+", " ", text.strip())[:300]
                hit = {
                    "foro":     forum["name"],
                    "idioma":   forum["lang"],
                    "termino":  term,
                    "url":      url,
                    "extracto": extracto,
                    "via_tor":  via_tor,
                    # Cada hit pasa por el extractor de IOCs.
                    "iocs":     {k: sorted(v) for k, v in
                                 extract_iocs(extracto, domain).items() if v},
                }
                hits.append(hit)
                if len(hits) >= 5:
                    return hits
    return hits


def search_forum(forum: Dict, domain: str) -> List[Dict]:
    """
    Busca el dominio en un foro concreto del registro.

    Prioriza la dirección .onion (si está configurada en darkweb_onions.json);
    si no, usa el mirror clearnet. Los foros method="discover" sin .onion
    configurada se omiten aquí (se cubren por descubrimiento en motores .onion).
    """
    terms = _domain_search_terms(domain)
    onion = forum.get("onion", "")
    clearnet = forum.get("clearnet", "")

    # Elegir base + sesión: .onion (Tor) tiene prioridad sobre clearnet.
    if onion:
        base_url, via_tor = onion, True
        sess = tor_session(timeout=25)
    elif clearnet and forum.get("method") == "search":
        base_url, via_tor = clearnet, False
        sess = clearnet_session()
    else:
        return []  # sin endpoint accesible → se descubre vía motores .onion

    for term in terms[:2]:
        from urllib.parse import quote_plus
        url = base_url + forum["search_path"].format(q=quote_plus(term))
        r = request_with_retry(sess, url, timeout=25, retries=2,
                               rotate_circuit_on_fail=via_tor,
                               accept_status=(200,))
        if r is None:
            continue
        hits = _extract_forum_hits(r.text, [term], forum, url, via_tor, domain)
        if hits:
            log.info("   [+] %s: %d menciones de %s", forum["name"], len(hits), domain)
            return hits
    return []


def search_all_forums(domain: str, max_workers: int = 8) -> Dict:
    """
    Busca el dominio en todos los foros del registro que tengan endpoint
    accesible (.onion configurada o mirror clearnet con búsqueda).

    Devuelve {hits, buscados, sin_endpoint} donde `sin_endpoint` lista los foros
    que requieren una dirección .onion en darkweb_onions.json para activarse.
    """
    from .utils import run_parallel

    targets = load_forum_targets()
    accesibles = [f for f in targets
                  if f.get("onion") or (f.get("clearnet") and f.get("method") == "search")]
    sin_endpoint = [f["name"] for f in targets
                    if not f.get("onion")
                    and not (f.get("clearnet") and f.get("method") == "search")]

    log.info("   [*] Foros con endpoint accesible: %d | pendientes de .onion: %d",
             len(accesibles), len(sin_endpoint))

    all_hits: List[Dict] = []
    for _, result in run_parallel(lambda f: search_forum(f, domain),
                                  accesibles, max_workers=max_workers,
                                  label="forums"):
        if isinstance(result, list):
            all_hits.extend(result)

    return {
        "status":       "success",
        "hits":         all_hits,
        "buscados":     len(accesibles),
        "sin_endpoint": sin_endpoint,
    }
