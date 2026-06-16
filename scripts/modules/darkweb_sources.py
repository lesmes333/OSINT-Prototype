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

import os
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

from .utils import get_logger, run_parallel, run_named_parallel
from .tor_utils import (
    tor_session as _tu_tor_session,
    clearnet_session as _tu_clearnet_session,
    request_with_retry,
    pick_user_agent,
)
from .ioc_extractor import extract_iocs

log = get_logger()

# ── Proxy Tor ─────────────────────────────────────────────────────────────────
TOR_PROXIES = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
TOR_UA = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

# ── Presupuestos de tiempo (segundos) ──────────────────────────────────────────
# Son límites GLOBALES para los barridos en paralelo: al agotarse, se devuelven
# las fuentes que ya respondieron y se abandonan las colgadas (p. ej. un .onion
# caído), de modo que NINGUNA fuente lenta pueda bloquear toda la fase.
# Ajustables sin tocar código mediante variables de entorno.
DARKWEB_BUDGET_S    = float(os.getenv("DARKWEB_BUDGET_S", "150"))    # barrido global de fuentes
TOR_ENGINES_BUDGET_S = float(os.getenv("TOR_ENGINES_BUDGET_S", "90"))  # solo motores .onion

# ── Keywords de fuga para búsquedas agresivas ─────────────────────────────────
# Se combinan con el dominio objetivo para encontrar hilos/dumps que de otro modo
# no aparecen al buscar el dominio "a secas" (así se indexan realmente las fugas).
LEAK_KEYWORDS = [
    "dump", "leak", "breach", "database", "combolist", "combo",
    "leaked", "stealer", "credentials", "accounts", "fullz",
]

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
    "DataLeakMonitoring",  # Monitorización de fugas
    "leak_databases",      # Bases de datos filtradas
    "combolist",           # Combolists
    "cloudleak",           # Cloud leaks
    "breached_db",         # DBs de brechas
    "darkfeed_news",       # DarkFeed (ransomware/leaks)
    "ransomwatch",         # Ransomware watch
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
    """
    Sesión Tor con circuito aislado y User-Agent rotativo (delega en tor_utils).
    Se conserva el nombre por compatibilidad con el resto del módulo.
    """
    return _tu_tor_session(timeout=timeout, isolate=True, tor_only_ua=True)


def _domain_variants(domain: str) -> List[str]:
    """Genera variantes de búsqueda para maximizar cobertura."""
    base = domain.split(".")[0]
    tld  = ".".join(domain.split(".")[1:])
    return list(dict.fromkeys([
        domain,           # example.com
        f"@{domain}",     # @example.com  (dumps de credenciales)
        base,             # example       (menciones sin TLD)
        f"@{base}",       # @example      (user handles)
    ]))


# ── Vocabulario de fuga multilingüe (EN / ES / RU) ────────────────────────────
# En la dark web los dumps se anuncian en varios idiomas. El ruso es habitual en
# foros de carding/credenciales (XSS, Exploit, etc.); el español aparece en
# canales de Telegram y foros hispanos. Incluir los tres multiplica la cobertura.
BREACH_VOCAB_EN = [
    "leak", "leaked", "dump", "database", "db", "combo", "combolist",
    "breach", "breached", "accounts", "credentials", "passwords",
    "fullz", "stealer", "logs", "cracked", "sql",
]
BREACH_VOCAB_ES = [
    "filtracion", "filtración", "fuga", "fugas", "contraseñas",
    "credenciales", "base de datos", "robados", "vendo", "hackeado",
]
# Ruso (cirílico + transliteración latina que también se usa en foros).
BREACH_VOCAB_RU = [
    "слив",        # sliv      → filtración/leak
    "база",        # baza      → base de datos
    "дамп",        # damp      → dump
    "утечка",      # utechka   → fuga
    "пароли",      # paroli    → contraseñas
    "взлом",       # vzlom     → hackeo
    "логи",        # logi      → logs (stealer)
    "продам",      # prodam    → "vendo"
    "sliv", "baza", "dump", "logi",  # transliteraciones frecuentes
]


def generate_breach_queries(domain: str, max_queries: int = 30) -> List[str]:
    """
    Genera un conjunto amplio de consultas para buscar fugas del dominio en la
    dark web, combinando variaciones del nombre con vocabulario de brecha en
    inglés, español y ruso.

    Estrategia (de mayor a menor precisión, así el recorte por `max_queries`
    conserva siempre lo más relevante):

      1. Variantes "ancla" del nombre:  example.com, www.example.com, @example.com,
         example, y patrones de archivo de dump (example.txt, example.sql, example.zip).
      2. dominio.com + keyword EN:       "example.com" leak / dump / database ...
      3. nombre base + keyword EN:       example leak / dump / combo ...
      4. nombre base + keyword ES:       example filtracion / contraseñas ...
      5. nombre base + keyword RU:       example слив / база / dump ...
      6. Variantes con año:              example 2024 / 2025 / 2026
      7. Variante con guion (si aplica):  zun-der  (typosquat / separadores)

    :param domain: dominio objetivo (p.ej. 'example.com').
    :param max_queries: tope de consultas devueltas (evita escaneos eternos).
    :return: lista de strings de búsqueda, deduplicada y ordenada por precisión.
    """
    domain = domain.lower().strip()
    base = domain.split(".")[0]                      # 'example'
    tld  = ".".join(domain.split(".")[1:]) or "com"  # 'com'

    queries: List[str] = []

    # 1) Anclas del nombre + patrones típicos de fichero de dump.
    queries += [
        domain,
        f"www.{domain}",
        f"@{domain}",
        base,
        f"{base}.txt", f"{base}.sql", f"{base}.zip", f"{base}.csv",
        f"{domain}.txt", f"{domain}.sql",
    ]

    # 2) dominio completo + vocabulario inglés (entre comillas = frase exacta).
    for kw in BREACH_VOCAB_EN:
        queries.append(f'"{domain}" {kw}')

    # 3) nombre base + vocabulario inglés.
    for kw in BREACH_VOCAB_EN:
        queries.append(f"{base} {kw}")

    # 4) nombre base + vocabulario español.
    for kw in BREACH_VOCAB_ES:
        queries.append(f"{base} {kw}")

    # 5) nombre base + vocabulario ruso (cirílico y transliterado).
    for kw in BREACH_VOCAB_RU:
        queries.append(f"{base} {kw}")

    # 6) Variantes con año (los dumps suelen etiquetarse por año).
    for year in ("2024", "2025", "2026"):
        queries.append(f"{base} {year}")
        queries.append(f'"{domain}" {year}')

    # 7) Variante con guion como separador (algunos índices lo trocean así).
    if len(base) > 4 and "-" not in base:
        mid = len(base) // 2
        queries.append(f"{base[:mid]}-{base[mid:]}")

    # Deduplicar preservando el orden (precisión) y recortar al tope.
    return list(dict.fromkeys(queries))[:max_queries]


def _aggressive_queries(domain: str, max_queries: int = 8) -> List[str]:
    """
    Subconjunto de ALTA SEÑAL para los motores .onion (que no deben recibir las
    ~30 consultas completas). Prioriza el dominio y el dominio+keyword inglesa,
    que es lo que mejor indexan Ahmia/Torch/Haystak, en vez de las anclas de
    nombre de fichero (.txt/.zip) que son ruido para un buscador.
    """
    base = domain.split(".")[0]
    queries = [domain, f"@{domain}", base]
    for kw in ("leak", "dump", "database", "combolist", "breach"):
        queries.append(f'"{domain}" {kw}')
    return list(dict.fromkeys(queries))[:max_queries]


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
    """
    Busca el dominio en un motor .onion via Tor con queries agresivas y
    reintentos resilientes (circuito nuevo entre fallos). Ejecutable en paralelo.

    Cada query combina el dominio con keywords de fuga (dump/leak/breach…) para
    sacar a la luz dumps y combolists que no aparecen buscando el dominio solo.
    La detección de coincidencias se hace sobre las variantes del dominio, no
    sobre la query completa (que incluye la keyword).
    """
    name, url_template, domain = args
    hits = []
    variants = _domain_variants(domain)
    queries  = _aggressive_queries(domain, max_queries=5)
    ts = _tor_session(timeout=15)   # circuito aislado + UA rotativa

    for query in queries:
        url = url_template.format(q=quote_plus(query))
        r = request_with_retry(ts, url, timeout=15, retries=2,
                               accept_status=(200,))
        if r is None:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        text_lower = r.text.lower()

        for variant in variants[:2]:
            vl = variant.lower()
            if vl not in text_lower:
                continue
            # 1) Enlaces .onion en resultados que mencionan la variante.
            mentions = [a for a in soup.find_all("a", href=True)
                        if vl in (a.get_text() + a.get("href", "")).lower()
                        and ".onion" in a.get("href", "")
                        and f"?q={vl}" not in a.get("href", "").lower()
                        and f"search={vl}" not in a.get("href", "").lower()
                        and f"query={vl}" not in a.get("href", "").lower()]
            if mentions:
                for a in mentions[:3]:
                    hits.append({
                        "motor":    name,
                        "variante": variant,
                        "query":    query,
                        "enlace":   a.get("href", "")[:150],
                        "texto":    re.sub(r"\s+", " ", a.get_text().strip())[:100],
                        "fuente":   f"tor_search:{name}",
                    })
            else:
                # 2) Coincidencia en texto, filtrando ecos de la propia búsqueda.
                idx = text_lower.find(vl)
                ctx = r.text[max(0, idx-100):idx+200]
                ctx_clean = re.sub(r"<[^>]+>", " ", ctx)
                ctx_clean = re.sub(r"\s+", " ", ctx_clean).strip()[:150]
                window = r.text[max(0, idx-80):idx+120].lower()
                engine_slug = name.lower().replace(" ", "")
                is_cross_search = any(pat in window for pat in [
                    f"?q={vl}", f"query={vl}",
                    "search?q=", "search for", "buscar en",
                    "i2p", "freenet", engine_slug, "<title>", "meta name",
                ])
                if ctx_clean and not is_cross_search:
                    hits.append({
                        "motor":    name,
                        "variante": variant,
                        "query":    query,
                        "enlace":   url,
                        "texto":    ctx_clean,
                        "fuente":   f"tor_search:{name}",
                    })
        if hits:
            log.info("   [+] Tor search %s: hits con query '%s'", name, query)
            break  # con un hit confirmado basta; no machacar el motor
    return hits


def search_tor_engines(domain: str) -> List[Dict]:
    """
    Busca el dominio en múltiples motores de búsqueda .onion via Tor, en paralelo.
    Cada motor corre en su propio hilo con su propio circuito Tor.
    """
    tasks = [(name, url_template, domain) for name, url_template in TOR_SEARCH_ENGINES]
    all_hits: List[Dict] = []
    for _, result in run_parallel(_search_one_tor_engine, tasks,
                                   max_workers=len(TOR_SEARCH_ENGINES), label="tor_engines",
                                   timeout=TOR_ENGINES_BUDGET_S):
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
        search_url = url.format(q=quote_plus(variant))
        sess = _tor_session(timeout=25) if use_tor else _tu_clearnet_session()
        r = request_with_retry(sess, search_url, timeout=20, retries=2,
                               rotate_circuit_on_fail=use_tor,
                               accept_status=(200,))
        if r is None:
            continue
        hits = _extract_hits(r.text, [variant], name, search_url, use_tor)
        if hits:
            return hits
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


def _search_forum_registry(domain: str) -> Dict:
    """
    Busca en el registro data-driven de foros (darkweb_forums.py): DarkForums,
    Dread, XSS, Exploit, BHF, DamageLib, mercados de credenciales, etc.

    Las direcciones .onion se toman de darkweb_onions.json (gitignored). Devuelve
    {hits, buscados, sin_endpoint}. Si el módulo falla, no rompe el escaneo.
    """
    try:
        from .darkweb_forums import search_all_forums
        return search_all_forums(domain)
    except Exception as e:  # noqa: BLE001
        log.debug("forum_registry: %s", e)
        return {"hits": [], "buscados": 0, "sin_endpoint": []}


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
            url = url_template.format(q=quote_plus(variant))
            sess = _tor_session(timeout=20) if is_onion else _tu_clearnet_session()
            r = request_with_retry(sess, url, timeout=15, retries=1,
                                   rotate_circuit_on_fail=is_onion,
                                   accept_status=(200,))
            if r is not None and variant.lower() in r.text.lower():
                return [{"fuente": name, "variante": variant,
                         "url": url, "via_tor": is_onion}]
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

def _telegram_channels() -> List[str]:
    """
    Lista de canales a vigilar: los conocidos + los definidos por el operador en
    la variable de entorno TELEGRAM_CHANNELS (separados por comas/espacios).
    Acepta '@canal', 'canal' o 't.me/canal'.
    """
    extra_raw = os.getenv("TELEGRAM_CHANNELS", "")
    extra = []
    for tok in re.split(r"[,;\s]+", extra_raw):
        tok = tok.strip()
        tok = re.sub(r"^(https?://)?t\.me/(s/)?", "", tok)  # t.me/s/x, https://t.me/x → x
        tok = tok.lstrip("@").strip("/")
        if tok:
            extra.append(tok)
    return list(dict.fromkeys(TELEGRAM_LEAK_CHANNELS + extra))


def _parse_telegram_messages(html: str, channel: str) -> List[Dict]:
    """
    Extrae los mensajes individuales de la vista web de un canal (t.me/s/{channel}).

    Cada mensaje en esa vista es un <div class="tgme_widget_message"> con su texto
    en <div class="tgme_widget_message_text">, su permalink en el enlace de fecha
    y la fecha en <time datetime=...>. Devuelve [{text, link, fecha}].
    """
    soup = BeautifulSoup(html, "html.parser")
    mensajes: List[Dict] = []
    for wrap in soup.select("div.tgme_widget_message"):
        text_el = wrap.select_one("div.tgme_widget_message_text")
        if not text_el:
            continue
        text = text_el.get_text(" ", strip=True)
        if not text:
            continue
        date_el = wrap.select_one("a.tgme_widget_message_date")
        link = date_el.get("href", "") if date_el else f"https://t.me/s/{channel}"
        time_el = wrap.select_one("time[datetime]")
        fecha = (time_el.get("datetime", "")[:10] if time_el else "")
        mensajes.append({"text": text, "link": link, "fecha": fecha})
    return mensajes


def search_telegram_leak_channels(domain: str, max_msgs_per_channel: int = 6,
                                  use_browser: bool = False) -> List[Dict]:
    """
    Busca menciones del dominio en canales públicos de Telegram de leaks/brechas
    y extrae los IOCs de CADA mensaje coincidente.

    Para cada canal usa el buscador nativo de la vista web (t.me/s/{channel}?q=)
    con varios términos (dominio y dominio+keyword), parsea los mensajes que
    realmente mencionan el dominio, los deduplica por permalink y les aplica el
    extractor de IOCs. Acceso 100% público, sin autenticación.

    Los canales se toman de TELEGRAM_LEAK_CHANNELS + la variable de entorno
    TELEGRAM_CHANNELS (ver _telegram_channels).
    """
    hits = []
    variants = _domain_variants(domain)
    channels = _telegram_channels()

    def _check_channel(channel):
        channel_hits: List[Dict] = []
        seen_links: set = set()
        sess = _tu_clearnet_session()
        # Histórico del canal con el buscador nativo (?q=), no solo lo reciente.
        search_terms = [domain, f"{domain} leak", f"{domain} dump"]
        for term in search_terms:
            if len(channel_hits) >= max_msgs_per_channel:
                break
            url = f"https://t.me/s/{channel}?q={quote_plus(term)}"
            r = request_with_retry(sess, url, timeout=15, retries=1,
                                   rotate_circuit_on_fail=False,
                                   accept_status=(200,))
            html_text = r.text if r is not None else None
            parsed = _parse_telegram_messages(html_text, channel) if html_text else []
            # Respaldo con Firefox: si requests falló o la vista web no devolvió
            # mensajes (a veces Telegram los carga por JS), renderizamos con el
            # navegador. Solo si --browser está activo (clearnet, sin Tor).
            if use_browser and not parsed:
                from .browser_fetch import get_fetcher
                rendered = get_fetcher(use_tor=False).fetch(url)
                if rendered:
                    parsed = _parse_telegram_messages(rendered, channel)
            for msg in parsed:
                low = msg["text"].lower()
                matched = next((v for v in variants[:3] if v.lower() in low), None)
                if not matched:
                    continue
                if msg["link"] in seen_links:
                    continue
                seen_links.add(msg["link"])
                extracto = re.sub(r"\s+", " ", msg["text"]).strip()[:400]
                iocs = {k: sorted(v) for k, v in
                        extract_iocs(msg["text"], domain).items() if v}
                channel_hits.append({
                    "fuente":   f"telegram/{channel}",
                    "canal":    channel,
                    "variante": matched,
                    "query":    term,
                    "url":      msg["link"],
                    "fecha":    msg["fecha"],
                    "extracto": extracto,
                    "iocs":     iocs,
                    "via_tor":  False,
                })
                if len(channel_hits) >= max_msgs_per_channel:
                    break
        return channel_hits

    for _, result in run_parallel(_check_channel, channels,
                                   max_workers=6, label="telegram"):
        if isinstance(result, list):
            hits.extend(result)

    if hits:
        log.info("   [+] Telegram: %d mensajes con menciones en %d canales",
                 len(hits), len(channels))
    return hits


# ═══════════════════════════════════════════════════════════════════════════════
# ORQUESTADOR PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_darkweb_scan(domain: str, intelx_key: str = "",
                           use_tor: bool = True,
                           scan_leaksites: bool = True,
                           use_browser: bool = False) -> Dict:
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
        "forum_registry": lambda: _search_forum_registry(domain),
        "hudson_rock": lambda: check_hudson_rock(domain),
        "pulsedive": lambda: check_pulsedive(domain),
        "paste_sites": lambda: search_paste_sites(domain, use_tor=use_tor),
        "telegram": lambda: search_telegram_leak_channels(domain, use_browser=use_browser),
    }
    if use_tor and scan_leaksites:
        tasks["leaksites"] = lambda: scan_all_ransomware_leaksites(domain, max_sites=80)
    if use_tor:
        tasks["tor_engines"] = lambda: search_tor_engines(domain)
    if intelx_key:
        tasks["intelx"] = lambda: check_intelx_domain(domain, intelx_key)

    par = run_named_parallel(tasks, max_workers=len(tasks), timeout=DARKWEB_BUDGET_S)

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

    # Foros (BreachForums + foros clearnet legacy + registro data-driven)
    bf_hits = par.get("breachforums") or []
    cl_hits = par.get("clearnet_forums") or []
    fr = par.get("forum_registry") or {}
    fr_hits = fr.get("hits", []) if isinstance(fr, dict) else []
    summary["forum_hits"] = (bf_hits if isinstance(bf_hits, list) else []) + \
                            (cl_hits if isinstance(cl_hits, list) else []) + \
                            fr_hits
    # Foros del registro que necesitan una .onion en darkweb_onions.json para activarse.
    summary["forums_sin_endpoint"] = fr.get("sin_endpoint", []) if isinstance(fr, dict) else []
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
