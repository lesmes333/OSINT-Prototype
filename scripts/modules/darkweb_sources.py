#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fuentes de dark web conocidas para monitorización de exposición.

Implementa búsqueda activa en:
  A) Leak sites de grupos de ransomware (via API ransomware.live + ransomlook)
  B) Foros de credenciales / brechas conocidos (.onion via Tor + clearnet)
  C) Motores de búsqueda Tor (.onion directo)
  D) Servicios de inteligencia de credenciales (APIs gratuitas)
  E) Paste sites y fuentes de filtración pública
  F) Canales Telegram públicos de brechas/leaks

Todos los accesos son pasivos y defensivos: solo se lee contenido público
indexado. No se interactúa con sistemas objetivo ni formularios de login.
"""

import re
import time
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup

from .utils import get_logger, run_parallel, run_named_parallel

log = get_logger()

# ── Proxy Tor ─────────────────────────────────────────────────────────────────
TOR_PROXIES = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
TOR_UA = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

# ── APIs clearnet de threat intelligence (gratuitas sin clave) ────────────────
HUDSON_ROCK     = "https://cavalier.hudsonrock.com/api/json/v2"
RANSOMWARE_LIVE = "https://api.ransomware.live"
RANSOMLOOK      = "https://www.ransomlook.io"
PULSEDIVE_API   = "https://pulsedive.com/api/info.php"

# ── Foros y fuentes .onion conocidas ─────────────────────────────────────────
DARK_SOURCES = {
    # ── Foros de credenciales / brechas ──────────────────────────────────────
    "breachforums": {
        "url":   "http://breachforumsrqjwoyf3qlhcbmrv6srgabxmyxrbhbzqkgwxhkscjkxad.onion",
        "type":  "forum",
        "desc":  "Foro principal de brechas y credenciales (sucesor RaidForums)",
        "search": "/search?q={q}&action=results",
        "requires_login": False,
    },
    "breachforums_clearnet": {
        "url":   "https://breachforums.st",
        "type":  "forum",
        "desc":  "BreachForums mirror clearnet",
        "search": "/search?q={q}&action=results",
        "requires_login": False,
    },
    # ── Motores de búsqueda .onion ────────────────────────────────────────────
    "ahmia": {
        "url":   "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "type":  "search",
        "desc":  "Ahmia .onion — índice curado de servicios Tor",
        "search": "/search/?q={q}",
        "requires_login": False,
    },
    "onionland": {
        "url":   "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion",
        "type":  "search",
        "desc":  "OnionLand Search — motor de búsqueda .onion general",
        "search": "/search?q={q}",
        "requires_login": False,
    },
    "haystak": {
        "url":   "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion",
        "type":  "search",
        "desc":  "Haystak — buscador dark web con millones de páginas indexadas",
        "search": "/?q={q}",
        "requires_login": False,
    },
    "torch": {
        "url":   "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion",
        "type":  "search",
        "desc":  "Torch — uno de los motores de búsqueda .onion más antiguos",
        "search": "/torch/search?query={q}&action=Search",
        "requires_login": False,
    },
    # ── Paste sites .onion ────────────────────────────────────────────────────
    "deepaste": {
        "url":   "http://depastedihrn3jtw.onion",
        "type":  "paste",
        "desc":  "DeepPaste — paste site anónimo en Tor",
        "search": "/search.php?md5=&string={q}",
        "requires_login": False,
    },
}

# ── Canales Telegram públicos conocidos por publicar brechas/leaks ────────────
# Acceso vía web: t.me/s/{channel} (solo lectura, sin login)
TELEGRAM_LEAK_CHANNELS = [
    "leakbase",         # Leakbase breach notifications
    "combolistfree",    # Combolists free
    "breachleaks",      # Breach & leaks channel
    "databreachs",      # Data breaches
    "exposeddatabases", # Exposed DB dumps
    "hacknews_en",      # Hack news
    "cybersecurity365", # Cybersecurity alerts
]

# ── Paste sites clearnet con contenido de brechas ─────────────────────────────
PASTE_SITES_CLEARNET = [
    ("Ghostbin",      "https://ghostbin.co/search?q={q}"),
    ("Pastes.io",     "https://pastes.io/search?q={q}"),
    ("Rentry.co",     "https://rentry.co/search?q={q}"),
    ("paste.ee",      "https://paste.ee/search/{q}"),
    ("Justpaste.it",  "https://justpaste.it/find/{q}"),
]

PASTE_SITES_ONION = [
    ("DeepPaste",     "http://depastedihrn3jtw.onion/search.php?md5=&string={q}"),
    ("Paste Onion",   "http://pastes7vcb5sxkq7.onion/search?q={q}"),
    ("SecretPaste",   "http://qpjqlf3himlsl7kp.onion/search?q={q}"),
]

# ── Foros clearnet relacionados con filtraciones ──────────────────────────────
CLEARNET_FORUMS = [
    ("XSS.is",       "https://xss.is/search?q={q}",         False),
    ("Nulled.to",    "https://www.nulled.to/search/index.php?app=core&module=search&do=search&keywords={q}", False),
    ("Cracked.io",   "https://cracked.io/search?q={q}",     False),
    ("exploit.in",   "https://exploit.in/search?q={q}",     False),
]


# ─────────────────────────────────────────────────────────────────────────────
# Utilidades comunes
# ─────────────────────────────────────────────────────────────────────────────

def _tor_session(timeout: int = 25) -> requests.Session:
    s = requests.Session()
    s.proxies.update(TOR_PROXIES)
    s.headers["User-Agent"] = TOR_UA
    s.headers["Accept-Language"] = "en-US,en;q=0.5"
    return s


def _domain_variants(domain: str) -> List[str]:
    """Genera variantes de búsqueda para maximizar cobertura."""
    base = domain.split(".")[0]
    tld  = ".".join(domain.split(".")[1:])
    return list(dict.fromkeys([
        domain,           # zunder.com
        f"@{domain}",     # @zunder.com  (dumps de credenciales)
        base,             # zunder       (menciones sin TLD)
        f"@{base}",       # @zunder      (user handles)
    ]))


def _extract_hits(html: str, variants: List[str], fuente: str,
                  url: str, via_tor: bool = False) -> List[Dict]:
    """Busca variantes en HTML y extrae extractos de contexto."""
    hits = []
    soup = BeautifulSoup(html, "html.parser")
    text_full = html.lower()
    for variant in variants:
        if variant.lower() not in text_full:
            continue
        for el in soup.find_all(["div", "li", "article", "tr", "p", "span"]):
            text = el.get_text()
            if variant.lower() in text.lower() and 20 < len(text) < 2000:
                clean = re.sub(r"\s+", " ", text.strip())[:250]
                hits.append({
                    "fuente":   fuente,
                    "variante": variant,
                    "url":      url,
                    "extracto": clean,
                    "via_tor":  via_tor,
                })
                if len(hits) >= 5:
                    return hits
    return hits


# ═══════════════════════════════════════════════════════════════════════════════
# A) LEAK SITES DE RANSOMWARE — acceso directo via Tor + APIs
# ═══════════════════════════════════════════════════════════════════════════════

def get_ransomware_onion_sites() -> List[Dict]:
    """Obtiene la lista actualizada de leak sites .onion de ransomware.live."""
    try:
        r = requests.get(f"{RANSOMWARE_LIVE}/groups", timeout=15)
        if r.status_code != 200:
            return []
        sites = []
        for group in r.json():
            for loc in group.get("locations", []):
                if (loc.get("available")
                        and loc.get("fqdn")
                        and ".onion" in loc.get("fqdn", "")):
                    sites.append({
                        "group": group.get("name", ""),
                        "onion": loc["fqdn"],
                        "url":   f"http://{loc['fqdn']}",
                        "type":  loc.get("type", "DLS"),
                    })
        log.info("   [*] %d leak sites .onion activos de ransomware.live", len(sites))
        return sites
    except Exception as e:  # noqa: BLE001
        log.debug("ransomware.live groups: %s", e)
        return []


def check_ransomlook_victims(domain: str) -> List[Dict]:
    """
    RansomLook API — alternativa/complemento a ransomware.live.
    Busca víctimas recientes por nombre de dominio/empresa.
    API pública gratuita.
    """
    hits = []
    base = domain.split(".")[0].lower()
    try:
        r = requests.get(f"{RANSOMLOOK}/api/recent", timeout=15)
        if r.status_code != 200:
            return []
        for victim in r.json():
            name = str(victim.get("post_title", "")).lower()
            desc = str(victim.get("description", "")).lower()
            if base in name or domain.lower() in name or domain.lower() in desc:
                hits.append({
                    "grupo":    victim.get("group_name", ""),
                    "victima":  victim.get("post_title", ""),
                    "fecha":    victim.get("published", "")[:10],
                    "url":      victim.get("post_url", ""),
                    "fuente":   "ransomlook",
                })
    except Exception as e:  # noqa: BLE001
        log.debug("RansomLook: %s", e)
    return hits


def search_ransomware_leaksite(site: Dict, domain: str, variants: List[str]) -> List[Dict]:
    """Accede directamente al leak site .onion de un grupo de ransomware via Tor."""
    ts = _tor_session(timeout=12)
    try:
        r = ts.get(site["url"], timeout=12)
        if r.status_code not in (200, 206):
            return []
        text_lower = r.text.lower()
        for variant in variants:
            if variant.lower() in text_lower:
                idx = text_lower.find(variant.lower())
                context = r.text[max(0, idx - 100): idx + 200].strip()
                context_clean = re.sub(r"<[^>]+>", " ", context).strip()
                context_clean = re.sub(r"\s+", " ", context_clean)[:200]
                return [{
                    "grupo":    site["group"],
                    "onion":    site["onion"],
                    "variante": variant,
                    "contexto": context_clean,
                    "fuente":   "ransomware_leaksite_direct",
                }]
    except Exception as e:  # noqa: BLE001
        log.debug("Leaksite %s: %s", site.get("group", "?"), str(e)[:60])
    return []


def scan_all_ransomware_leaksites(domain: str, max_sites: int = 80,
                                   max_workers: int = 10) -> Dict:
    """
    Escanea los leak sites .onion de grupos de ransomware activos buscando
    menciones del dominio objetivo via Tor (concurrencia limitada).
    """
    log.info("   [*] Escaneando %d leak sites .onion de ransomware via Tor...", max_sites)
    sites    = get_ransomware_onion_sites()[:max_sites]
    variants = _domain_variants(domain)

    if not sites:
        return {"status": "error", "message": "No se pudo obtener leak sites",
                "hits": [], "scanned": 0}

    all_hits: List[Dict] = []

    def _scan(site):
        return search_ransomware_leaksite(site, domain, variants)

    for _, result in run_parallel(_scan, sites, max_workers=max_workers,
                                  label="leaksites"):
        if isinstance(result, list):
            all_hits.extend(result)

    log.info("   [=] Leak sites escaneados: %d | Hits: %d", len(sites), len(all_hits))
    return {
        "status":  "success",
        "scanned": len(sites),
        "total":   len(sites),
        "hits":    all_hits,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# B) MOTORES DE BÚSQUEDA TOR — búsqueda activa .onion
# ═══════════════════════════════════════════════════════════════════════════════

TOR_SEARCH_ENGINES = [
    ("Ahmia",      "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={q}"),
    ("OnionLand",  "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={q}"),
    ("Haystak",    "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={q}"),
    ("Torch",      "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/torch/search?query={q}&action=Search"),
    ("DarkSearch", "http://darksearcy3n4kxrkvdjfxxvj4ztafnlqrq2fv7cxwvdwvj2vcv4yd.onion/search?query={q}"),
]


def _search_one_tor_engine(args: tuple) -> List[Dict]:
    """Busca el dominio en un motor .onion via Tor. Ejecutable en paralelo."""
    name, url_template, domain = args
    hits = []
    variants = _domain_variants(domain)
    ts = _tor_session(timeout=15)   # 15s — suficiente; falla rápido si el motor está caído

    for variant in variants[:2]:
        url = url_template.format(q=variant)
        try:
            r = ts.get(url, timeout=15)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            result_links = soup.find_all("a", href=True)
            mentions = [a for a in result_links
                        if variant.lower() in (a.get_text() + a.get("href", "")).lower()
                        and ".onion" in a.get("href", "")
                        and f"?q={variant.lower()}" not in a.get("href", "").lower()
                        and f"search={variant.lower()}" not in a.get("href", "").lower()
                        and f"query={variant.lower()}" not in a.get("href", "").lower()]
            if mentions:
                for a in mentions[:3]:
                    hits.append({
                        "motor":    name,
                        "variante": variant,
                        "enlace":   a.get("href", "")[:150],
                        "texto":    re.sub(r"\s+", " ", a.get_text().strip())[:100],
                        "fuente":   f"tor_search:{name}",
                    })
            elif variant.lower() in r.text.lower():
                idx = r.text.lower().find(variant.lower())
                ctx = r.text[max(0, idx-100):idx+200]
                ctx_clean = re.sub(r"<[^>]+>", " ", ctx)
                ctx_clean = re.sub(r"\s+", " ", ctx_clean).strip()[:150]
                window = r.text[max(0, idx-80):idx+120].lower()
                engine_slug = name.lower().replace(" ", "")
                is_cross_search = any(pat in window for pat in [
                    f"?q={variant.lower()}", f"query={variant.lower()}",
                    "search?q=", "search for", "buscar en",
                    "i2p", "freenet", engine_slug, "<title>", "meta name",
                ])
                if ctx_clean and not is_cross_search:
                    hits.append({
                        "motor":    name,
                        "variante": variant,
                        "enlace":   url,
                        "texto":    ctx_clean,
                        "fuente":   f"tor_search:{name}",
                    })
            if hits:
                log.info("   [+] Tor search %s: encontró '%s'", name, variant)
                break
        except Exception as e:  # noqa: BLE001
            log.debug("Tor search %s: %s", name, str(e)[:60])
    return hits


def search_tor_engines(domain: str) -> List[Dict]:
    """
    Busca el dominio en múltiples motores de búsqueda .onion via Tor, en paralelo.
    Cada motor corre en su propio hilo con su propio circuito Tor.
    """
    tasks = [(name, url_template, domain) for name, url_template in TOR_SEARCH_ENGINES]
    all_hits: List[Dict] = []
    for _, result in run_parallel(_search_one_tor_engine, tasks,
                                   max_workers=len(TOR_SEARCH_ENGINES), label="tor_engines"):
        if isinstance(result, list):
            all_hits.extend(result)
    return all_hits


# ═══════════════════════════════════════════════════════════════════════════════
# C) FOROS DE CREDENCIALES / BRECHAS
# ═══════════════════════════════════════════════════════════════════════════════

def _search_forum_generic(name: str, url: str, domain: str,
                           use_tor: bool = False) -> List[Dict]:
    """
    Búsqueda genérica en foro/fuente con endpoint GET.
    Falla silenciosamente ante bloqueos (Cloudflare, 403, timeout).
    """
    variants = _domain_variants(domain)
    for variant in variants[:2]:
        search_url = url.format(q=variant)
        try:
            if use_tor:
                sess = _tor_session(timeout=25)
            else:
                sess = requests.Session()
                sess.headers.update({
                    "User-Agent": TOR_UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                })
            r = sess.get(search_url, timeout=20, allow_redirects=True)
            if r.status_code not in (200,):
                continue
            hits = _extract_hits(r.text, [variant], name, search_url, use_tor)
            if hits:
                return hits
        except Exception as e:  # noqa: BLE001
            log.debug("%s: %s", name, str(e)[:60])
    return []


def search_breachforums(domain: str) -> List[Dict]:
    """BreachForums: foro principal de brechas (.onion + clearnet fallback)."""
    hits = _search_forum_generic(
        "BreachForums (.onion)",
        "http://breachforumsrqjwoyf3qlhcbmrv6srgabxmyxrbhbzqkgwxhkscjkxad.onion/search?q={q}&action=results",
        domain, use_tor=True,
    )
    if not hits:
        hits = _search_forum_generic(
            "BreachForums",
            "https://breachforums.st/search?q={q}&action=results",
            domain, use_tor=False,
        )
    return hits


def search_clearnet_forums(domain: str) -> List[Dict]:
    """
    Busca en foros clearnet de credenciales/hacking: XSS.is, Nulled.to,
    Cracked.io, exploit.in. Muchos tienen Cloudflare; se manejan
    silenciosamente.
    """
    all_hits = []
    for name, url_template, use_tor in CLEARNET_FORUMS:
        hits = _search_forum_generic(name, url_template, domain, use_tor)
        if hits:
            log.info("   [+] %s: %d menciones de %s", name, len(hits), domain)
        all_hits.extend(hits)
    return all_hits


# ═══════════════════════════════════════════════════════════════════════════════
# D) APIS DE INTELIGENCIA DE CREDENCIALES (clearnet, gratuitas)
# ═══════════════════════════════════════════════════════════════════════════════

def check_hudson_rock(domain: str) -> Dict:
    """
    Hudson Rock Cavalier — infostealer intelligence gratuita.
    Busca credenciales de empleados/usuarios en bases de datos de infostealers
    (Redline, Vidar, Raccoon, LummaC2, etc.). API pública sin clave.
    """
    result = {"status": "error", "employees": 0, "users": 0, "data": {}}
    try:
        r = requests.get(
            f"{HUDSON_ROCK}/osint-tools/url/domain",
            params={"domain": domain},
            headers={"User-Agent": TOR_UA},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            result = {
                "status":    "success",
                "employees": data.get("total_corporate_credentials", 0),
                "users":     data.get("total_user_credentials", 0),
                "stealers":  data.get("stealers", [])[:5],
                "data":      data,
            }
        elif r.status_code == 404:
            result = {"status": "success", "employees": 0, "users": 0, "data": {}}
        else:
            result["status"] = f"http_{r.status_code}"
    except Exception as e:  # noqa: BLE001
        log.debug("Hudson Rock: %s", str(e)[:80])
        result["message"] = str(e)[:80]
    return result


def check_pulsedive(domain: str) -> Dict:
    """
    Pulsedive — threat intelligence gratuita.
    Busca indicadores de riesgo del dominio: feeds de malware, amenazas activas.
    Plan gratuito, sin clave.
    """
    result = {"status": "error", "risk": "unknown", "feeds": []}
    try:
        r = requests.get(
            PULSEDIVE_API,
            params={"indicator": domain, "pretty": 1},
            headers={"User-Agent": TOR_UA},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            result = {
                "status": "success",
                "risk":   data.get("risk", "unknown"),
                "feeds":  [f.get("name", "") for f in data.get("feeds", [])[:5]],
                "threats": data.get("threats", [])[:3],
                "ref":    data.get("indicator", ""),
            }
    except Exception as e:  # noqa: BLE001
        log.debug("Pulsedive: %s", str(e)[:80])
    return result


def check_intelx_domain(domain: str, api_key: str) -> List[Dict]:
    """
    IntelX: búsqueda en dark web, paste sites, foros, buckets S3, etc.
    Requiere plan de pago.
    """
    if not api_key:
        return []
    results = []
    try:
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            headers={"x-key": api_key, "Content-Type": "application/json"},
            json={"term": domain, "maxresults": 50, "media": 0,
                  "target": 0, "timeout": 20, "sort": 4,
                  "terminate": [], "sidfilter": [], "datefrom": "", "dateto": ""},
            timeout=25,
        )
        if r.status_code != 200:
            return []
        sid = r.json().get("id")
        if not sid:
            return []
        time.sleep(3)
        r2 = requests.get(
            "https://2.intelx.io/intelligent/search/result",
            headers={"x-key": api_key},
            params={"id": sid, "limit": 50, "offset": 0},
            timeout=20,
        )
        if r2.status_code != 200:
            return []
        media_map = {
            0: "foro/web", 1: "paste", 2: "dark web", 5: "Tor",
            7: "dark web", 14: "bucket S3", 15: "FTP",
        }
        for rec in r2.json().get("records", []):
            results.append({
                "fuente":  f"intelx:{media_map.get(rec.get('media', 0), 'otro')}",
                "nombre":  rec.get("name", "")[:80],
                "fecha":   rec.get("date", "")[:10],
                "id":      rec.get("keyid", ""),
                "size":    rec.get("size", 0),
            })
    except Exception as e:  # noqa: BLE001
        log.debug("IntelX domain: %s", e)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# E) PASTE SITES Y FUENTES DE FILTRACIÓN
# ═══════════════════════════════════════════════════════════════════════════════

def search_paste_sites(domain: str, use_tor: bool = False) -> List[Dict]:
    """Busca el dominio en paste sites (clearnet + .onion si use_tor=True)."""
    hits = []
    variants = _domain_variants(domain)

    def _check(entry):
        name, url_template = entry
        is_onion = ".onion" in url_template
        if is_onion and not use_tor:
            return []
        for variant in variants[:2]:
            url = url_template.format(q=variant)
            try:
                if is_onion:
                    sess = _tor_session(timeout=20)
                else:
                    sess = requests.Session()
                    sess.headers["User-Agent"] = TOR_UA
                r = sess.get(url, timeout=15, allow_redirects=True)
                if r.status_code == 200 and variant.lower() in r.text.lower():
                    return [{"fuente": name, "variante": variant,
                             "url": url, "via_tor": is_onion}]
            except Exception:  # noqa: BLE001
                pass
        return []

    sources = PASTE_SITES_CLEARNET + (PASTE_SITES_ONION if use_tor else [])
    for _, result in run_parallel(_check, sources, max_workers=5,
                                  label="paste_sites"):
        if isinstance(result, list):
            hits.extend(result)
    return hits


# ═══════════════════════════════════════════════════════════════════════════════
# F) CANALES TELEGRAM PÚBLICOS DE LEAKS/BRECHAS
# ═══════════════════════════════════════════════════════════════════════════════

def search_telegram_leak_channels(domain: str) -> List[Dict]:
    """
    Busca menciones del dominio en canales públicos de Telegram conocidos
    por publicar dumps de credenciales y filtraciones.
    Accede via t.me/s/{channel} (web pública, sin autenticación).
    """
    hits = []
    variants = _domain_variants(domain)

    def _check_channel(channel):
        channel_hits = []
        url = f"https://t.me/s/{channel}"
        try:
            sess = requests.Session()
            sess.headers.update({
                "User-Agent": TOR_UA,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            })
            r = sess.get(url, timeout=15, allow_redirects=True)
            if r.status_code != 200:
                return []
            text = r.text.lower()
            for variant in variants[:2]:
                if variant.lower() in text:
                    idx = text.find(variant.lower())
                    ctx = r.text[max(0, idx-100):idx+200]
                    ctx_clean = re.sub(r"<[^>]+>", " ", ctx)
                    ctx_clean = re.sub(r"\s+", " ", ctx_clean).strip()[:200]
                    channel_hits.append({
                        "fuente":   f"telegram/{channel}",
                        "variante": variant,
                        "url":      url,
                        "extracto": ctx_clean,
                        "via_tor":  False,
                    })
                    break
        except Exception as e:  # noqa: BLE001
            log.debug("Telegram %s: %s", channel, str(e)[:60])
        return channel_hits

    for _, result in run_parallel(_check_channel, TELEGRAM_LEAK_CHANNELS,
                                   max_workers=4, label="telegram"):
        if isinstance(result, list):
            hits.extend(result)

    if hits:
        log.info("   [+] Telegram: %d menciones encontradas en canales públicos", len(hits))
    return hits


# ═══════════════════════════════════════════════════════════════════════════════
# ORQUESTADOR PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_darkweb_scan(domain: str, intelx_key: str = "",
                           use_tor: bool = True,
                           scan_leaksites: bool = True) -> Dict:
    """
    Orquesta todas las fuentes de dark web disponibles y devuelve un
    resumen consolidado con nivel de riesgo.

    Fuentes cubiertas:
      · Leak sites directos de 80+ grupos de ransomware (via Tor)
      · RansomLook API backup (víctimas recientes)
      · BreachForums (.onion + clearnet)
      · Foros clearnet: XSS.is, Nulled.to, Cracked.io, exploit.in
      · Motores .onion: Ahmia, OnionLand, Haystak, Torch, DarkSearch
      · Hudson Rock (infostealer intelligence, gratis, sin clave)
      · Pulsedive (domain threat intel, gratis)
      · Paste sites: Ghostbin, Pastes.io, paste.ee, Justpaste.it + .onion
      · Canales Telegram públicos de leaks (7 canales)
      · IntelX (si hay clave con plan de pago)
    """
    summary: Dict = {
        "domain":             domain,
        "leaksites_hits":     [],
        "leaksites_scanned":  0,
        "ransomlook_hits":    [],
        "forum_hits":         [],
        "tor_search_hits":    [],
        "infostealer":        {},
        "pulsedive":          {},
        "paste_hits":         [],
        "telegram_hits":      [],
        "intelx_hits":        [],
        "nivel_riesgo":       "LOW",
        "total_hits":         0,
        "fuentes_activas":    [],
    }

    log.info("   [*] Lanzando todas las fuentes dark web en paralelo...")

    # Construir tareas paralelas (todas independientes)
    tasks: dict = {
        "ransomlook": lambda: check_ransomlook_victims(domain),
        "breachforums": lambda: search_breachforums(domain),
        "clearnet_forums": lambda: search_clearnet_forums(domain),
        "hudson_rock": lambda: check_hudson_rock(domain),
        "pulsedive": lambda: check_pulsedive(domain),
        "paste_sites": lambda: search_paste_sites(domain, use_tor=use_tor),
        "telegram": lambda: search_telegram_leak_channels(domain),
    }
    if use_tor and scan_leaksites:
        tasks["leaksites"] = lambda: scan_all_ransomware_leaksites(domain, max_sites=80)
    if use_tor:
        tasks["tor_engines"] = lambda: search_tor_engines(domain)
    if intelx_key:
        tasks["intelx"] = lambda: check_intelx_domain(domain, intelx_key)

    par = run_named_parallel(tasks, max_workers=len(tasks))

    # Leak sites de ransomware
    ls = par.get("leaksites") or {}
    if isinstance(ls, dict):
        summary["leaksites_hits"]    = ls.get("hits", [])
        summary["leaksites_scanned"] = ls.get("scanned", 0)
        if summary["leaksites_hits"]:
            summary["fuentes_activas"].append(
                f"ransomware_leaksites ({len(summary['leaksites_hits'])} hits)")

    # RansomLook
    rl_hits = par.get("ransomlook") or []
    summary["ransomlook_hits"] = rl_hits if isinstance(rl_hits, list) else []
    if summary["ransomlook_hits"]:
        summary["fuentes_activas"].append(f"ransomlook ({len(summary['ransomlook_hits'])} víctimas)")

    # Motores .onion
    tor_hits = par.get("tor_engines") or []
    summary["tor_search_hits"] = tor_hits if isinstance(tor_hits, list) else []
    if summary["tor_search_hits"]:
        summary["fuentes_activas"].append(f"tor_search ({len(summary['tor_search_hits'])} resultados)")

    # Foros
    bf_hits = par.get("breachforums") or []
    cl_hits = par.get("clearnet_forums") or []
    summary["forum_hits"] = (bf_hits if isinstance(bf_hits, list) else []) + \
                            (cl_hits if isinstance(cl_hits, list) else [])
    if summary["forum_hits"]:
        summary["fuentes_activas"].append(f"foros ({len(summary['forum_hits'])} hits)")

    # Hudson Rock
    hr = par.get("hudson_rock") or {}
    summary["infostealer"] = hr if isinstance(hr, dict) else {}
    if summary["infostealer"].get("employees", 0) > 0 or summary["infostealer"].get("users", 0) > 0:
        summary["fuentes_activas"].append(
            f"hudson_rock ({summary['infostealer'].get('employees',0)} emp, "
            f"{summary['infostealer'].get('users',0)} usr)")

    # Pulsedive
    pd = par.get("pulsedive") or {}
    summary["pulsedive"] = pd if isinstance(pd, dict) else {}
    if summary["pulsedive"].get("risk") not in ("none", "unknown", "error", ""):
        summary["fuentes_activas"].append(f"pulsedive (riesgo: {summary['pulsedive'].get('risk')})")

    # Paste sites
    paste_hits = par.get("paste_sites") or []
    summary["paste_hits"] = paste_hits if isinstance(paste_hits, list) else []
    if summary["paste_hits"]:
        summary["fuentes_activas"].append(f"paste_sites ({len(summary['paste_hits'])} hits)")

    # Telegram
    tg_hits = par.get("telegram") or []
    summary["telegram_hits"] = tg_hits if isinstance(tg_hits, list) else []
    if summary["telegram_hits"]:
        summary["fuentes_activas"].append(f"telegram ({len(summary['telegram_hits'])} menciones)")

    # IntelX
    if intelx_key:
        ix = par.get("intelx") or []
        summary["intelx_hits"] = ix if isinstance(ix, list) else []
        if summary["intelx_hits"]:
            summary["fuentes_activas"].append(f"intelx ({len(summary['intelx_hits'])} registros)")

    # Calcular nivel de riesgo
    total = (len(summary["leaksites_hits"])
             + len(summary["ransomlook_hits"])
             + len(summary["forum_hits"])
             + len(summary["tor_search_hits"])
             + len(summary["paste_hits"])
             + len(summary["telegram_hits"])
             + len(summary["intelx_hits"]))
    summary["total_hits"] = total

    employees = summary["infostealer"].get("employees", 0)
    if summary["leaksites_hits"] or summary["ransomlook_hits"] or employees > 0:
        summary["nivel_riesgo"] = "CRITICAL"
    elif summary["forum_hits"] or summary["tor_search_hits"]:
        summary["nivel_riesgo"] = "HIGH"
    elif total > 0 or summary["pulsedive"].get("risk") not in ("none", "unknown", "error"):
        summary["nivel_riesgo"] = "MEDIUM"

    return summary
