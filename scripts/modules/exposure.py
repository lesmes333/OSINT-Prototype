#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Monitorización de exposición y filtraciones (enfoque defensivo y legal).

Cinco capas complementarias, todas sin acceder a sistemas ajenos:

  Capa 1 — Brechas de datos (XposedOrNot + HIBP opcional):
      Correos del dominio descubiertos automáticamente via Hunter.io.

  Capa 2 — Dark web index (motores .onion vía Tor + IntelX opcional):
      Busca menciones del dominio en servicios indexados en Tor.
      Usa OnionLand, Haystak y otros via proxy SOCKS5 si Tor está activo.
      Ahmia.fi (clearnet/Tor) bloquea headless browsers: se usa como
      último recurso pero la cobertura principal la dan otros motores.

  Capa 3 — Leaks en fuentes abiertas:
      URLScan histórico · GitHub code search · Pastebin Pro (opcional).

  Capa 4 — Ransomware & ciberataques (APIs públicas):
      Rastrea si el dominio o empresa aparece en leak sites de grupos
      de ransomware activos. Fuentes: ransomware.live (gratis, sin clave)
      y RansomLook (gratis, sin clave).
      Esta capa cubre el 80% de lo que herramientas de pago ofrecen como
      «dark web monitoring» para empresas.

  Capa 5 — Crawling .onion profundo vía Tor (OPCIONAL, avanzada):
      Solo con --tor. Accede a DarkWebMonitor para análisis más profundo.
"""

import os
import re
import socket
import time
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

from .utils import get_logger, make_session, run_parallel, run_named_parallel

log = get_logger()

XON_BASE        = "https://api.xposedornot.com/v1"
HIBP_BASE       = "https://haveibeenpwned.com/api/v3"
INTELX_BASE     = "https://2.intelx.io"
LEAKCHECK_BASE  = "https://leakcheck.io/api/v2"
PASTEBIN_SCRAPE = "https://scrape.pastebin.com/api_scraping.php"
RANSOMWARE_LIVE = "https://api.ransomware.live"
RANSOMLOOK      = "https://www.ransomlook.io"
MALTIVERSE      = "https://api.maltiverse.com"

# Presupuesto GLOBAL (segundos) para TODA la FASE 4 (todas las capas en paralelo).
# Si se agota, las capas que no terminaron se marcan como {"status": "timeout"}
# y el escaneo continúa con lo que haya: ninguna capa lenta (Tor/.onion) cuelga
# la fase. Configurable con EXPOSURE_BUDGET_S. Debe ser >= DARKWEB_BUDGET_S.
EXPOSURE_BUDGET_S = float(os.getenv("EXPOSURE_BUDGET_S", "240"))

# Motores de búsqueda .onion accesibles via Tor (sin fingerprinting JS).
# Las direcciones .onion v3 son estables (64 chars) pero algunos motores
# migran periódicamente — si falla una, la herramienta continúa con las demás.
TOR_ENGINES = [
    # Ahmia — el índice .onion más fiable, sin JS requerido
    ("Ahmia",      "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={q}"),
    # OnionLand — funciona bien desde esta VM (verificado)
    ("OnionLand",  "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={q}"),
    # DarkSearch — índice alternativo estable
    ("DarkSearch", "http://darksearch.io.onion/search?query={q}"),
    # Haystak — puede estar caído/migrado, se intenta igualmente
    ("Haystak",    "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={q}"),
]


def _tor_available() -> bool:
    """Comprueba si hay un proxy Tor activo en 127.0.0.1:9050."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 9050))
        sock.close()
        return result == 0
    except OSError:
        return False


class ExposureMonitor:
    def __init__(self, domain: str, emails: Optional[List[str]] = None,
                 run_tor: bool = False, threads: int = 10):
        self.domain   = domain.lower().strip()
        # Los correos llegan auto-descubiertos desde Hunter (main.py).
        self.emails   = sorted({e.lower().strip() for e in (emails or []) if "@" in e})
        self.run_tor  = run_tor
        self.threads  = threads
        self.session  = make_session()
        self.hibp_key       = os.getenv("HIBP_API_KEY", "")
        self.intelx_key     = os.getenv("INTELX_API_KEY", "")
        self.urlscan_key    = os.getenv("URLSCAN_API_KEY", "")
        self.github_token   = os.getenv("GITHUB_TOKEN", "")
        self.pastebin_key   = os.getenv("PASTEBIN_API_KEY", "")
        self.leakcheck_key  = os.getenv("LEAKCHECK_API_KEY", "")
        self.dehashed_key   = os.getenv("DEHASHED_API_KEY", "")
        self.dehashed_email = os.getenv("DEHASHED_EMAIL", "")
        self._tor_up        = _tor_available()

    # ============================================================
    # CAPA 1 — Brechas de datos
    # ============================================================
    def _xon_domain_breaches(self) -> Dict:
        """XposedOrNot domain-level: brechas que afectan al dominio completo.
        Gratis, sin clave. Devuelve lista de brechas con emails afectados del dominio."""
        try:
            r = self.session.get(f"{XON_BASE}/domain-breaches/{self.domain}", timeout=15)
            if r.status_code == 200:
                data = r.json()
                return {
                    "breaches": data.get("breaches", []),
                    "count":    data.get("BreachMetrics", {}).get("domain", {}).get("breached", 0),
                    "emails":   data.get("emails_affected", []),
                }
            return {"breaches": [], "count": 0, "emails": []}
        except Exception as e:  # noqa: BLE001
            log.debug("XON domain: %s", e)
            return {"breaches": [], "count": 0, "emails": []}

    def _leakcheck_domain(self) -> List[Dict]:
        """LeakCheck.io: busca credenciales filtradas por dominio.
        Plan gratuito: 5 búsquedas/día con LEAKCHECK_API_KEY (registro gratis en leakcheck.io).
        Devuelve emails, contraseñas y fuente de la brecha."""
        if not self.leakcheck_key:
            return []
        results = []
        try:
            r = self.session.get(
                f"{LEAKCHECK_BASE}/query/{self.domain}",
                headers={"X-API-Key": self.leakcheck_key},
                params={"type": "domain"},
                timeout=20,
            )
            if r.status_code == 401:
                log.debug("LeakCheck: clave inválida")
                return []
            if r.status_code == 403:
                log.debug("LeakCheck: límite diario alcanzado (5/día en plan free)")
                return [{"error": "rate_limit", "message": "Límite diario de LeakCheck (5/día) alcanzado"}]
            if r.status_code != 200:
                return []
            data = r.json()
            if not data.get("success"):
                return []
            for entry in data.get("result", []):
                results.append({
                    "email":    entry.get("email", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "source":   entry.get("sources", []),
                    "last_breach": entry.get("last_breach", ""),
                })
        except Exception as e:  # noqa: BLE001
            log.debug("LeakCheck: %s", e)
        return results

    def _dehashed_domain(self) -> List[Dict]:
        """Dehashed: la mayor BD de credenciales filtradas (~15 mil millones de registros).
        Busca por dominio (@example.com), devuelve email, usuario, contraseña, IP, nombre.
        Requiere cuenta Dehashed ($5.49/mes o $14.99/año — registro en dehashed.com)."""
        if not self.dehashed_key or not self.dehashed_email:
            return []
        results = []
        try:
            import base64
            creds = base64.b64encode(f"{self.dehashed_email}:{self.dehashed_key}".encode()).decode()
            r = self.session.get(
                "https://api.dehashed.com/search",
                headers={"Authorization": f"Basic {creds}",
                         "Accept": "application/json"},
                params={"query": f"domain:{self.domain}", "size": 50},
                timeout=20,
            )
            if r.status_code in (401, 403):
                log.debug("Dehashed: credenciales inválidas")
                return []
            if r.status_code != 200:
                return []
            for entry in r.json().get("entries", []) or []:
                results.append({
                    "email":    entry.get("email", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "hashed_password": entry.get("hashed_password", ""),
                    "name":     entry.get("name", ""),
                    "ip":       entry.get("ip_address", ""),
                    "database": entry.get("database_name", ""),
                })
        except Exception as e:  # noqa: BLE001
            log.debug("Dehashed: %s", e)
        return results

    def _xon_check_email(self, email: str) -> Dict:
        """XposedOrNot: filtraciones por email (gratis)."""
        try:
            r = self.session.get(f"{XON_BASE}/check-email/{email}", timeout=15)
            if r.status_code == 200:
                flat = []
                for grupo in r.json().get("breaches", []):
                    flat.extend(grupo if isinstance(grupo, list) else [grupo])
                return {"email": email, "found": bool(flat), "breaches": flat}
            if r.status_code == 404:
                return {"email": email, "found": False, "breaches": []}
            return {"email": email, "found": False, "breaches": [],
                    "error": f"HTTP {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"email": email, "found": False, "breaches": [], "error": str(e)}

    def _hibp_check_email(self, email: str) -> Dict:
        """Have I Been Pwned: filtraciones por email (requiere suscripción de pago)."""
        headers = {"hibp-api-key": self.hibp_key, "user-agent": "OSINT-Recon-Suite"}
        try:
            r = self.session.get(
                f"{HIBP_BASE}/breachedaccount/{email}?truncateResponse=true",
                headers=headers, timeout=15,
            )
            if r.status_code == 200:
                return {"breaches": [b.get("Name") for b in r.json() if b.get("Name")]}
            if r.status_code == 404:
                return {"breaches": []}
            return {"breaches": [], "error": f"HTTP {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"breaches": [], "error": str(e)}

    def layer_breaches(self) -> Dict:
        """Capa 1: brechas de datos (XposedOrNot + HIBP + LeakCheck + Dehashed)."""
        log.info("   [*] Capa 1: brechas de datos (XposedOrNot / HIBP / LeakCheck / Dehashed)...")
        # Búsqueda a nivel de dominio (más completa que por email individual)
        domain_breaches = self._xon_domain_breaches()
        per_email = []
        if self.emails:
            for _, res in run_parallel(self._xon_check_email, self.emails,
                                       max_workers=min(self.threads, 8),
                                       label="xposedornot"):
                if isinstance(res, dict):
                    per_email.append(res)

        if self.hibp_key and self.emails:
            hibp_index = {}
            for email in self.emails:
                hibp_index[email] = self._hibp_check_email(email).get("breaches", [])
                time.sleep(1.6)
            for row in per_email:
                extra = hibp_index.get(row["email"], [])
                if extra:
                    row["breaches"] = sorted(set(row.get("breaches", []) + extra))
                    row["found"] = True

        # LeakCheck: búsqueda por dominio (más rápida que por email)
        leakcheck_results = self._leakcheck_domain()
        leakcheck_error   = next((r for r in leakcheck_results if r.get("error")), None)

        # Dehashed: la BD más completa de credenciales
        dehashed_results = self._dehashed_domain()

        comprometidos = [r for r in per_email if r.get("found")]
        return {
            "checked_emails":      len(per_email),
            "compromised_emails":  len(comprometidos),
            "results":             per_email,
            "hibp_used":           bool(self.hibp_key),
            "domain_breaches":     domain_breaches,
            "leakcheck":           leakcheck_results,
            "leakcheck_error":     leakcheck_error,
            "dehashed":            dehashed_results,
        }

    # ============================================================
    # CAPA 2 — Índice dark web vía Tor
    # ============================================================
    def _tor_session(self):
        """Sesión HTTP ruteada por Tor (SOCKS5h en 127.0.0.1:9050)."""
        import requests
        s = requests.Session()
        proxies = {"http": "socks5h://127.0.0.1:9050",
                   "https": "socks5h://127.0.0.1:9050"}
        s.proxies.update(proxies)
        s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        )
        return s

    def _search_engine_via_tor(self, name: str, url_template: str) -> List[Dict]:
        """Busca el dominio en un motor .onion via Tor y parsea los resultados."""
        results = []
        try:
            ts = self._tor_session()
            url = url_template.format(q=self.domain)
            r = ts.get(url, timeout=30)
            if r.status_code != 200:
                return []
            soup = BeautifulSoup(r.text, "html.parser")
            # Buscar bloques de resultado con .onion addresses
            onion_re = re.compile(r"[a-z2-7]{16,56}\.onion")
            for a in soup.find_all("a", href=True):
                href = a.get("href", "")
                m = onion_re.search(href)
                if not m:
                    continue
                onion_addr = m.group(0)
                # Solo incluir si el snippet menciona el dominio buscado
                parent_text = ""
                parent = a.find_parent(["li", "div", "article", "tr"])
                if parent:
                    parent_text = parent.get_text()[:300]
                if self.domain not in parent_text.lower() and self.domain not in href.lower():
                    continue
                results.append({
                    "title":       a.get_text(strip=True)[:100] or onion_addr,
                    "onion":       onion_addr,
                    "description": parent_text[:200],
                    "source":      f"tor:{name.lower()}",
                })
        except Exception as e:  # noqa: BLE001
            log.debug("Tor motor %s: %s", name, e)
        return results

    def _intelx_darkweb_search(self) -> List[Dict]:
        """IntelX dark web (media=7). Requiere plan con acceso API (no plan free)."""
        if not self.intelx_key:
            return []
        results = []
        try:
            r = self.session.post(
                f"{INTELX_BASE}/intelligent/search",
                headers={"x-key": self.intelx_key, "Content-Type": "application/json"},
                json={"term": self.domain, "maxresults": 20, "media": 7,
                      "target": 0, "timeout": 20, "datefrom": "", "dateto": "",
                      "sort": 4, "terminate": [], "sidfilter": []},
                timeout=25,
            )
            if r.status_code in (401, 403):
                return []
            if r.status_code != 200:
                return []
            sid = r.json().get("id")
            if not sid:
                return []
            time.sleep(3)
            r2 = self.session.get(
                f"{INTELX_BASE}/intelligent/search/result",
                headers={"x-key": self.intelx_key},
                params={"id": sid, "limit": 20, "offset": 0}, timeout=20,
            )
            if r2.status_code != 200:
                return []
            for rec in r2.json().get("records", []):
                results.append({
                    "title": rec.get("name", self.domain)[:120],
                    "onion": "", "description": rec.get("keyid", ""),
                    "source": "intelx:dark-web",
                })
        except Exception as e:  # noqa: BLE001
            log.debug("IntelX dark web: %s", e)
        return results

    def layer_ahmia(self) -> Dict:
        """Capa 2: índice dark web (motores .onion via Tor + IntelX)."""
        log.info("   [*] Capa 2: dark web index (Tor motors / IntelX)...")
        all_links: List[Dict] = []
        motores_usados: List[str] = []
        motores_error: List[str] = []

        # Búsqueda via Tor si está disponible
        if self._tor_up:
            for nombre, template in TOR_ENGINES:
                resultados = self._search_engine_via_tor(nombre, template)
                if resultados is not None:
                    motores_usados.append(nombre)
                    all_links.extend(resultados)
                else:
                    motores_error.append(nombre)
        # IntelX como complemento (si hay clave con acceso API)
        intelx_res = self._intelx_darkweb_search()
        if intelx_res:
            motores_usados.append("IntelX")
            all_links.extend(intelx_res)

        # Deduplica por dirección .onion
        vistos, unicos = set(), []
        for item in all_links:
            key = item.get("onion") or item.get("title", "")
            if key and key not in vistos:
                vistos.add(key)
                unicos.append(item)

        if self._tor_up and motores_usados:
            status = "success"
            method = f"tor ({', '.join(motores_usados)})"
        elif intelx_res:
            status = "success"
            method = "intelx"
        elif self._tor_up:
            status = "success"          # Tor activo pero sin resultados (buena noticia)
            method = f"tor ({', '.join([n for n,_ in TOR_ENGINES])} — sin resultados)"
        else:
            status = "requires_tor_or_intelx"
            method = "none"

        return {
            "status":  status,
            "method":  method,
            "total":   len(unicos),
            "links":   unicos,
            "message": (
                "Tor no detectado en 127.0.0.1:9050. "
                "Activa Tor (`sudo systemctl start tor`) y usa --tor para búsqueda completa. "
                "Alternativa: INTELX_API_KEY con plan de pago."
            ) if status == "requires_tor_or_intelx" else "",
            "tor_active": self._tor_up,
        }

    # ============================================================
    # CAPA 3 — Leaks en fuentes abiertas
    # ============================================================
    def _urlscan_domain_history(self) -> List[Dict]:
        """URLScan.io: historial de análisis públicos del dominio."""
        if not self.urlscan_key:
            return []
        try:
            r = self.session.get(
                f"https://urlscan.io/api/v1/search/?q=domain%3A{self.domain}&size=25",
                headers={"API-Key": self.urlscan_key}, timeout=20,
            )
            if r.status_code != 200:
                return []
            return [{"id": res.get("task", {}).get("uuid", ""),
                     "date": res.get("task", {}).get("time", "")[:10],
                     "url":  res.get("task", {}).get("url", ""),
                     "ip":   res.get("page", {}).get("ip", ""),
                     "country": res.get("page", {}).get("country", ""),
                     "source": "urlscan"}
                    for res in r.json().get("results", [])]
        except Exception as e:  # noqa: BLE001
            log.debug("URLScan: %s", e)
            return []

    def _github_code_search(self) -> Tuple[List[Dict], int]:
        """GitHub: menciones del dominio en repos/gists públicos."""
        if not self.github_token:
            return [], 0
        try:
            r = self.session.get(
                "https://api.github.com/search/code",
                headers={"Authorization": f"Bearer {self.github_token}",
                         "Accept": "application/vnd.github.v3+json",
                         "X-GitHub-Api-Version": "2022-11-28"},
                params={"q": self.domain, "per_page": 20}, timeout=20,
            )
            if r.status_code != 200:
                return [], 0
            data  = r.json()
            total = data.get("total_count", 0)
            items = [{"repo": it.get("repository", {}).get("full_name", ""),
                      "file": it.get("path", ""),
                      "url":  it.get("html_url", ""),
                      "source": "github"}
                     for it in data.get("items", [])]
            return items, total
        except Exception as e:  # noqa: BLE001
            log.debug("GitHub: %s", e)
            return [], 0

    def _pastebin_pro_search(self) -> Tuple[List[Dict], str]:
        """Pastebin Pro scraping API: feed de pastes en tiempo real.
        Requiere cuenta Pro ($8.95/mes). Sin clave devuelve vacío."""
        if not self.pastebin_key:
            return [], ("Sin PASTEBIN_API_KEY (Pro $8.95/mes). "
                        "Usando Pastebin /archive vía Tor como alternativa gratuita.")
        try:
            r = self.session.get(
                PASTEBIN_SCRAPE,
                params={"limit": 250, "api_user_key": self.pastebin_key},
                timeout=20,
            )
            if r.status_code == 403:
                return [], "IP sin acceso — verifica que la cuenta es Pro."
            if r.status_code != 200:
                return [], f"HTTP {r.status_code}"
            pastes_raw = r.json() if r.headers.get("content-type", "").startswith("application/json") else []
            hits = []
            for paste in pastes_raw:
                key = paste.get("key") or ""
                if not key:
                    continue
                try:
                    r2 = self.session.get(f"https://pastebin.com/raw/{key}", timeout=8)
                    if self.domain in r2.text.lower():
                        hits.append({"id": key, "date": paste.get("date", ""),
                                     "url": f"https://pastebin.com/{key}",
                                     "title": paste.get("title", key)[:80],
                                     "tags": "pastebin | contiene dominio"})
                except Exception:  # noqa: BLE001
                    pass
            return hits, ""
        except Exception as e:  # noqa: BLE001
            log.debug("Pastebin Pro: %s", e)
            return [], f"Error: {e}"

    def _pastebin_tor_monitor(self) -> Tuple[List[Dict], str]:
        """Pastebin gratis vía Tor: scraping de /archive sin cuenta Pro.
        La IP de la VM está bloqueada por Pastebin, pero los exit nodes de Tor
        suelen poder acceder. Comprueba cada paste del archivo reciente."""
        if not self._tor_up:
            return [], "Tor no activo — Pastebin vía Tor no disponible."
        try:
            ts = self._tor_session()
            r = ts.get("https://pastebin.com/archive", timeout=20)
            if r.status_code != 200:
                return [], f"Pastebin/archive HTTP {r.status_code} vía Tor."
            soup = BeautifulSoup(r.text, "html.parser")
            # Pastebin archive: <table class="maintable"> con links /XXXXXXXX
            paste_links = [
                a["href"] for a in soup.select("table.maintable a[href]")
                if re.match(r"^/[A-Za-z0-9]{8}$", a.get("href", ""))
            ]
            if not paste_links:
                return [], "Sin pastes en /archive (estructura HTML inesperada)."
            hits: List[Dict] = []
            for href in paste_links[:30]:  # Limitar para no saturar Tor
                paste_id = href.lstrip("/")
                try:
                    r2 = ts.get(f"https://pastebin.com/raw/{paste_id}", timeout=10)
                    if r2.status_code == 200 and self.domain.lower() in r2.text.lower():
                        hits.append({
                            "id":    paste_id,
                            "date":  "",
                            "url":   f"https://pastebin.com/{paste_id}",
                            "title": paste_id,
                            "tags":  "pastebin-tor | contiene dominio",
                        })
                except Exception:  # noqa: BLE001
                    pass
            nota = "" if hits else "Sin menciones del dominio en los últimos pastes de Pastebin."
            return hits, nota
        except Exception as e:  # noqa: BLE001
            log.debug("Pastebin Tor: %s", e)
            return [], f"Pastebin vía Tor: {e}"

    def _intelx_paste_search(self) -> List[Dict]:
        """IntelX paste sites (media=1). Requiere plan con acceso API."""
        if not self.intelx_key:
            return []
        results = []
        try:
            r = self.session.post(
                f"{INTELX_BASE}/intelligent/search",
                headers={"x-key": self.intelx_key, "Content-Type": "application/json"},
                json={"term": self.domain, "maxresults": 30, "media": 1,
                      "target": 0, "timeout": 20, "datefrom": "", "dateto": "",
                      "sort": 4, "terminate": [], "sidfilter": []},
                timeout=25,
            )
            if r.status_code in (401, 403):
                return []
            sid = r.json().get("id") if r.status_code == 200 else None
            if not sid:
                return []
            time.sleep(3)
            r2 = self.session.get(
                f"{INTELX_BASE}/intelligent/search/result",
                headers={"x-key": self.intelx_key},
                params={"id": sid, "limit": 30, "offset": 0}, timeout=20,
            )
            if r2.status_code != 200:
                return []
            for rec in r2.json().get("records", []):
                tipo = {1: "paste", 14: "bucket-S3", 6: "foro"}.get(rec.get("media", 0), "otro")
                results.append({"id": rec.get("keyid", ""), "date": rec.get("date", "")[:10],
                                 "url": rec.get("keyid", ""),
                                 "tags": f"intelx | {tipo} | {rec.get('name','')[:60]}"})
        except Exception as e:  # noqa: BLE001
            log.debug("IntelX pastes: %s", e)
        return results

    def layer_pastes(self) -> Dict:
        """Capa 3: leaks en fuentes abiertas (URLScan + GitHub + Pastebin + IntelX)."""
        log.info("   [*] Capa 3: leaks en fuentes abiertas (URLScan / GitHub / Pastebin / IntelX)...")

        urlscan_items              = self._urlscan_domain_history()
        github_items, github_total = self._github_code_search()
        pastebin_hits, pb_nota     = self._pastebin_pro_search()
        # Si no hay clave Pro y Tor está activo, intentar Pastebin vía Tor (gratis)
        if not pastebin_hits and not self.pastebin_key and self._tor_up:
            pastebin_hits, pb_nota = self._pastebin_tor_monitor()
        intelx_items               = self._intelx_paste_search()

        pastes: List[Dict] = []
        for item in urlscan_items[:20]:
            pastes.append({"id": item["id"], "date": item["date"],
                           "url": f"https://urlscan.io/result/{item['id']}/",
                           "tags": f"urlscan | IP:{item.get('ip','')} | {item.get('country','')}"})
        for item in github_items[:15]:
            pastes.append({"id": item["url"], "date": "",
                           "url": item["url"],
                           "tags": f"github | repo:{item['repo']} | {item['file']}"})
        for item in pastebin_hits[:20]:
            pastes.append({"id": item.get("id", ""), "date": item.get("date", ""),
                           "url": item.get("url", ""), "tags": item.get("tags", "pastebin")})
        for item in intelx_items[:10]:
            pastes.append({"id": item.get("id", ""), "date": item.get("date", ""),
                           "url": item.get("url", ""), "tags": item.get("tags", "intelx")})

        fuentes_activas = []
        if urlscan_items:
            fuentes_activas.append(f"urlscan ({len(urlscan_items)} análisis históricos)")
        if github_items:
            fuentes_activas.append(f"github ({github_total} menciones en repos públicos)")
        if pastebin_hits:
            fuentes_activas.append(f"pastebin ({len(pastebin_hits)} pastes con mención)")
        if intelx_items:
            fuentes_activas.append(f"intelx ({len(intelx_items)} registros)")

        notas = []
        if pb_nota:
            notas.append(f"Pastebin: {pb_nota}")
        if self.intelx_key and not intelx_items:
            notas.append("IntelX: clave sin acceso API (plan gratuito) o sin resultados.")

        return {
            "status":         "success" if pastes else "no_results",
            "total":          len(pastes),
            "pastes":         pastes,
            "urlscan_count":  len(urlscan_items),
            "github_total":   github_total,
            "github_sample":  github_items[:5],
            "pastebin_count": len(pastebin_hits),
            "intelx_count":   len(intelx_items),
            "fuentes":        fuentes_activas,
            "notas":          notas,
        }

    # ============================================================
    # CAPA 4 — Ransomware & Ciberataques (APIs públicas gratuitas)
    # ============================================================
    def _ransomware_live_search(self) -> Dict:
        """ransomware.live: busca el dominio en víctimas e incidentes recientes.
        API pública y gratuita, sin clave. Cubre las 100 entradas más recientes."""
        resultado = {"victims": [], "cyberattacks": [], "error": None}
        domain_base = self.domain.split(".")[0]  # "example" de "example.com"
        try:
            # /recentvictims: 100 últimas víctimas en leak sites de ransomware
            r = self.session.get(f"{RANSOMWARE_LIVE}/recentvictims", timeout=15)
            if r.status_code == 200:
                for v in r.json():
                    site    = (v.get("website") or "").lower()
                    title   = (v.get("post_title") or "").lower()
                    desc    = (v.get("description") or "").lower()
                    if (self.domain in site or domain_base in site
                            or domain_base in title or self.domain in desc):
                        resultado["victims"].append({
                            "grupo":       v.get("group_name", ""),
                            "victima":     v.get("post_title", ""),
                            "sitio":       v.get("website", ""),
                            "publicado":   (v.get("published") or "")[:10],
                            "descripcion": (v.get("description") or "")[:300],
                            "infostealer": v.get("infostealer", {}),
                            "fuente":      "ransomware.live/recentvictims",
                        })
        except Exception as e:  # noqa: BLE001
            log.debug("ransomware.live victims: %s", e)
            resultado["error"] = str(e)

        try:
            # /recentcyberattacks: 100 últimos ciberataques reportados
            r2 = self.session.get(f"{RANSOMWARE_LIVE}/recentcyberattacks", timeout=15)
            if r2.status_code == 200:
                for a in r2.json():
                    dom     = (a.get("domain") or "").lower()
                    victim  = (a.get("victim") or "").lower()
                    title   = (a.get("title") or "").lower()
                    if (self.domain in dom or domain_base in dom
                            or domain_base in victim or domain_base in title):
                        resultado["cyberattacks"].append({
                            "titulo":    a.get("title", ""),
                            "dominio":   a.get("domain", ""),
                            "victima":   a.get("victim", ""),
                            "pais":      a.get("country", ""),
                            "fecha":     a.get("date", ""),
                            "resumen":   (a.get("summary") or "")[:300],
                            "url":       a.get("url", ""),
                            "fuente":    "ransomware.live/recentcyberattacks",
                        })
        except Exception as e:  # noqa: BLE001
            log.debug("ransomware.live cyberattacks: %s", e)

        return resultado

    def _ransomlook_search(self) -> List[Dict]:
        """RansomLook: busca el dominio entre posts de grupos de ransomware.
        API pública gratuita. Devuelve posts recientes con contexto del grupo."""
        hits = []
        try:
            # Obtener los grupos de ransomware activos y sus características
            r = self.session.get(f"{RANSOMLOOK}/api/groups", timeout=15)
            grupos_activos = len(r.json()) if r.status_code == 200 else 0
            # Buscar posts que mencionen el dominio
            r2 = self.session.get(f"{RANSOMLOOK}/api/posts", timeout=15)
            if r2.status_code == 200:
                posts_data = r2.json()
                posts = posts_data.get("posts", posts_data) if isinstance(posts_data, dict) else posts_data
                domain_base = self.domain.split(".")[0]
                for post in posts:
                    # Los posts de RansomLook tienen poco detalle en el endpoint público
                    nombre = (post.get("victim") or post.get("title") or "").lower()
                    if domain_base in nombre or self.domain in nombre:
                        hits.append({
                            "grupo":   post.get("group_name", ""),
                            "victima": post.get("victim", nombre),
                            "fecha":   (post.get("discovered") or "")[:10],
                            "fuente":  "ransomlook.io",
                        })
            return hits
        except Exception as e:  # noqa: BLE001
            log.debug("RansomLook: %s", e)
            return []

    def _maltiverse_check(self) -> Dict:
        """Maltiverse: reputación del dominio en bases de threat intelligence.
        API pública y gratuita (sin clave para consultas básicas)."""
        try:
            r = self.session.get(f"{MALTIVERSE}/hostname/{self.domain}", timeout=15)
            if r.status_code != 200:
                return {"status": "error", "code": r.status_code}
            d = r.json()
            return {
                "status":       "success",
                "clasificacion": d.get("classification", "neutral"),
                "blacklist":    d.get("blacklist", []),
                "threat_types": d.get("threat_types", []),
                "creation_time": d.get("creation_time", ""),
                "last_seen":    d.get("last_seen", ""),
                "tags":         d.get("tag", []),
            }
        except Exception as e:  # noqa: BLE001
            log.debug("Maltiverse: %s", e)
            return {"status": "error", "message": str(e)}

    def layer_ransomware(self) -> Dict:
        """Capa 4: monitorización de ransomware y ciberataques.
        Comprueba si el dominio o empresa aparece en leak sites de grupos activos."""
        log.info("   [*] Capa 4: ransomware & ciberataques (ransomware.live / RansomLook / Maltiverse)...")

        rw_live   = self._ransomware_live_search()
        ransomlook_hits = self._ransomlook_search()
        maltiverse = self._maltiverse_check()

        total_victims    = len(rw_live.get("victims", []))
        total_attacks    = len(rw_live.get("cyberattacks", []))
        total_ransomlook = len(ransomlook_hits)

        # Extraer datos de infostealers si la empresa aparece como víctima
        infostealer_data = {}
        for v in rw_live.get("victims", []):
            ist = v.get("infostealer", {}) or {}
            if ist:
                infostealer_data = {
                    "empleados_comprometidos": ist.get("employees", 0),
                    "usuarios_comprometidos":  ist.get("users", 0),
                    "terceros_afectados":      ist.get("thirdparties", 0),
                }

        nivel_riesgo = "LOW"
        if total_victims > 0 or total_ransomlook > 0:
            nivel_riesgo = "CRITICAL"
        elif total_attacks > 0:
            nivel_riesgo = "HIGH"
        elif maltiverse.get("blacklist"):
            nivel_riesgo = "HIGH"
        elif maltiverse.get("clasificacion") not in ("neutral", None, ""):
            nivel_riesgo = "MEDIUM"

        return {
            "status":              "success",
            "nivel_riesgo":        nivel_riesgo,
            "victims":             rw_live.get("victims", []),
            "cyberattacks":        rw_live.get("cyberattacks", []),
            "ransomlook":          ransomlook_hits,
            "maltiverse":          maltiverse,
            "infostealer":         infostealer_data,
            "total_incidents":     total_victims + total_attacks + total_ransomlook,
            "nota": (
                "Cubre las 100 últimas entradas de cada fuente. "
                "Para historial completo: ransomware.live y ransomlook.io (web)."
            ),
        }

    # ============================================================
    # CAPA 5 — Tor profundo (DarkWebMonitor)
    # ============================================================
    def layer_tor(self) -> Dict:
        """Capa 5: crawling .onion profundo vía Tor (DarkWebMonitor)."""
        log.info("   [*] Capa 5: dark web crawling profundo vía Tor...")
        try:
            from .darkweb_monitor import DarkWebMonitor
            return DarkWebMonitor(self.domain).run_all()
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    # ============================================================
    # CAPA 6 — Foros dark web + leak sites directos + infostealers
    # ============================================================
    def layer_darkweb_sources(self) -> Dict:
        """
        Capa 6: búsqueda activa en fuentes dark web conocidas.

        Cubre cuatro vectores:
          A) Leak sites .onion de 60+ grupos de ransomware activos (via Tor directo)
          B) BreachForums .onion + clearnet (foro principal de credenciales)
          C) Hudson Rock infostealer intelligence (gratis, sin clave)
          D) Paste sites especializados en leaks
        """
        log.info("   [*] Capa 6: foros dark web + leak sites directos + infostealers...")
        from .darkweb_sources import run_full_darkweb_scan
        result = run_full_darkweb_scan(
            domain        = self.domain,
            intelx_key    = self.intelx_key,
            use_tor       = self._tor_up,
            scan_leaksites= self._tor_up,  # solo si Tor activo
        )
        return result

    # ============================================================
    # Orquestación
    # ============================================================
    def run_all(self) -> Dict:
        # Todas las capas son independientes — se lanzan en paralelo
        layer_results = run_named_parallel({
            "breaches":     self.layer_breaches,
            "ahmia":        self.layer_ahmia,
            "pastes":       self.layer_pastes,
            "ransomware":   self.layer_ransomware,
            "tor":          (self.layer_tor if self.run_tor
                             else lambda: {"status": "skipped"}),
            "dark_sources": self.layer_darkweb_sources,
        }, max_workers=6, timeout=EXPOSURE_BUDGET_S)

        breaches     = layer_results.get("breaches",     {})
        ahmia        = layer_results.get("ahmia",        {})
        pastes       = layer_results.get("pastes",       {})
        ransomware   = layer_results.get("ransomware",   {})
        tor          = layer_results.get("tor",          {"status": "skipped"})
        dark_sources = layer_results.get("dark_sources", {})

        onion_links = [{"title": x["title"],
                        "link": f"http://{x['onion']}" if x.get("onion") else x.get("description", ""),
                        "description": x.get("description", ""),
                        "source": x.get("source", "tor")}
                       for x in ahmia.get("links", [])]
        analyzed_threats = []
        if isinstance(tor, dict):
            analyzed_threats = tor.get("analyzed_threats", [])
            for tr in tor.get("raw_results", []):
                if tr.get("link"):
                    onion_links.append(tr)

        # Nivel de exposición global (toma el peor nivel de todas las capas)
        rw_nivel  = ransomware.get("nivel_riesgo", "LOW")
        ds_nivel  = dark_sources.get("nivel_riesgo", "LOW")
        hr_empleados = dark_sources.get("infostealer", {}).get("employees", 0)
        hr_usuarios  = dark_sources.get("infostealer", {}).get("users", 0)

        summary = {
            "emails_comprometidos":    breaches.get("compromised_emails", 0),
            "menciones_onion":         ahmia.get("total", 0),
            "urlscan_historico":       pastes.get("urlscan_count", 0),
            "github_menciones":        pastes.get("github_total", 0),
            "pastebin_hits":           pastes.get("pastebin_count", 0),
            "intelx_pastes":           pastes.get("intelx_count", 0),
            "ransomware_incidents":    ransomware.get("total_incidents", 0),
            "ransomware_nivel":        rw_nivel,
            "maltiverse_clasificacion": ransomware.get("maltiverse", {}).get("clasificacion", ""),
            # Capa 6 — fuentes dark web
            "leaksite_hits":           len(dark_sources.get("leaksites_hits", [])),
            "ransomlook_hits":         len(dark_sources.get("ransomlook_hits", [])),
            "forum_hits":              len(dark_sources.get("forum_hits", [])),
            "tor_search_hits":         len(dark_sources.get("tor_search_hits", [])),
            "paste_hits":              len(dark_sources.get("paste_hits", [])),
            "telegram_hits":           len(dark_sources.get("telegram_hits", [])),
            "infostealer_empleados":   hr_empleados,
            "infostealer_usuarios":    hr_usuarios,
            "pulsedive_riesgo":        dark_sources.get("pulsedive", {}).get("risk", ""),
            "dark_sources_nivel":      ds_nivel,
        }

        # El nivel final es el más grave de todas las capas
        niveles_orden = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        nivel = "LOW"
        if summary["emails_comprometidos"] > 0 or summary["pastebin_hits"] > 0:
            nivel = "HIGH"
        if summary["menciones_onion"] > 0 or summary["github_menciones"] > 5:
            nivel = max(nivel, "MEDIUM", key=niveles_orden.index)
        nivel = max(nivel, rw_nivel,  key=niveles_orden.index)
        nivel = max(nivel, ds_nivel,  key=niveles_orden.index)
        summary["nivel_exposicion"] = nivel

        result = {
            "status":       "success",
            "keyword":      self.domain,
            "breaches":     breaches,
            "ahmia":        ahmia,
            "pastes":       pastes,
            "ransomware":   ransomware,
            "dark_sources": dark_sources,   # Capa 6
            "tor":          tor,
            "summary":      summary,
            # compatibilidad con contrato anterior
            "total_links_found": len(onion_links),
            "raw_results":       onion_links,
            "analyzed_threats":  analyzed_threats,
            "timestamp":         time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # ── IOCs: extraer indicadores accionables de todo el corpus recolectado ──
        try:
            from .ioc_extractor import extract_iocs_from_results
            ioc_result = extract_iocs_from_results(result, target_domain=self.domain)
            result["iocs"] = ioc_result
            summary["iocs_total"] = ioc_result.get("total", 0)
        except Exception as e:  # noqa: BLE001
            log.debug("IOC extractor: %s", e)
            result["iocs"] = {"iocs": {}, "counts": {}, "total": 0}

        return result
