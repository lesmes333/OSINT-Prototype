#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de monitorización en Dark Web vía Tor.

Busca menciones del dominio en múltiples motores .onion gratuitos y analiza
los enlaces encontrados para detectar amenazas. Requiere Tor en 127.0.0.1:9050.

Motores incluidos (todos gratuitos, sin registro):
  · Ahmia .onion  — índice de servicios Tor, más fiable que la versión clearnet
  · Haystak       — uno de los índices más grandes (~1.5 mil millones de páginas)
  · Torch         — el motor .onion más antiguo, amplio índice histórico
  · osint-darkweb-pkg (opcional) — 15+ motores adicionales si está instalado
"""

import re
import socket
import time
import platform
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup

# ── biblioteca multi-motor opcional ──────────────────────────────────────────
try:
    from osint_darkweb_pkg import get_search_results
    MULTI_ENGINE_AVAILABLE = True
except ImportError:
    MULTI_ENGINE_AVAILABLE = False

# Dirección .onion de Ahmia (más fiable que clearnet para scraping sin JS).
AHMIA_ONION  = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
HAYSTAK_ONION = "haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion"
TORCH_ONION   = "xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion"


class DarkWebMonitor:
    """
    Monitorización en la dark web vía Tor.

    Busca el dominio objetivo en múltiples motores .onion y realiza crawling
    de los resultados para evaluar el nivel de amenaza.
    """

    def __init__(self, keyword: str):
        self.keyword  = keyword
        self.proxies  = {
            "http":  "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }
        self.timeout  = 50
        self.os_name  = platform.system().lower()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _tor_session(self) -> requests.Session:
        """Sesión HTTP preconfigurada para usar Tor (SOCKS5h)."""
        s = requests.Session()
        s.proxies.update(self.proxies)
        # Tor Browser UA para no destacar en servidores .onion.
        s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        )
        return s

    def _tor_instructions(self) -> str:
        if self.os_name == "windows":
            return "Inicia Tor Browser o el servicio Tor (puerto 9050)."
        elif self.os_name == "linux":
            return "Ejecuta: sudo systemctl start tor"
        return "Ejecuta: brew services start tor"

    def _parse_onion_links(self, html: str, source: str) -> List[Dict]:
        """Extrae enlaces .onion de HTML genérico de motores de búsqueda."""
        soup = BeautifulSoup(html, "html.parser")
        seen: set = set()
        results: List[Dict] = []

        onion_re = re.compile(r"https?://[a-z2-7]{16,56}\.onion[^\s\"'<>]*|[a-z2-7]{16,56}\.onion")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            m = onion_re.search(href)
            if not m:
                continue
            raw = m.group(0)
            link = raw if raw.startswith("http") else f"http://{raw}"
            if link in seen:
                continue
            seen.add(link)
            title = a.get_text(strip=True)[:100]
            if not title:
                parent = a.find_parent(["li", "div", "dt", "article"])
                h = parent.find(["h2", "h3", "h4", "b"]) if parent else None
                title = h.get_text(strip=True)[:100] if h else raw[:60]
            parent = a.find_parent(["li", "div", "dt", "article"])
            desc_el = parent.find("p") if parent else None
            desc = desc_el.get_text(strip=True)[:200] if desc_el else ""
            results.append({
                "title":       title,
                "link":        link,
                "description": desc,
                "source":      source,
            })
        return results

    # ── verificación Tor ──────────────────────────────────────────────────────

    def check_tor(self) -> bool:
        """Verifica que Tor esté activo en :9050 y enrute tráfico."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex(("127.0.0.1", 9050)) != 0:
                return False
            sock.close()
        except Exception:
            return False
        try:
            r = requests.get(
                "https://check.torproject.org/",
                proxies=self.proxies, timeout=15,
            )
            return "Congratulations" in r.text or r.status_code == 200
        except Exception:
            return False

    # ── motores de búsqueda .onion ────────────────────────────────────────────

    def search_ahmia_onion(self) -> List[Dict]:
        """Ahmia .onion vía Tor. Devuelve HTML completo sin JS requerido."""
        print("[*] Ahmia .onion (Tor)...")
        url = f"http://{AHMIA_ONION}/search/?q={self.keyword}"
        try:
            r = self._tor_session().get(url, timeout=self.timeout)
            if r.status_code != 200:
                print(f"[!] Ahmia .onion: HTTP {r.status_code}")
                return []
            soup = BeautifulSoup(r.text, "html.parser")
            results: List[Dict] = []
            seen: set = set()
            # Estructura Ahmia: <li class="result"> con <h4><a> y <p>
            for li in soup.select("li.result, div.result"):
                a = li.select_one("h4 a, h3 a, a[href*='.onion']")
                if not a:
                    continue
                href = a.get("href", "")
                m = re.search(r"[a-z2-7]{16,56}\.onion", href)
                if not m:
                    continue
                link = href if href.startswith("http") else f"http://{m.group(0)}"
                if link in seen:
                    continue
                seen.add(link)
                desc_el = li.select_one("p.result-description, p")
                results.append({
                    "title":       a.get_text(strip=True)[:100] or m.group(0),
                    "link":        link,
                    "description": desc_el.get_text(strip=True)[:200] if desc_el else "",
                    "source":      "ahmia_onion",
                })
            print(f"[✓] Ahmia .onion: {len(results)} resultado(s)")
            return results
        except Exception as e:
            print(f"[!] Ahmia .onion error: {e}")
            return []

    def search_haystak(self) -> List[Dict]:
        """Haystak .onion vía Tor (~1.5 mil millones de páginas indexadas)."""
        print("[*] Haystak (Tor)...")
        url = f"http://{HAYSTAK_ONION}/?q={self.keyword}"
        try:
            r = self._tor_session().get(url, timeout=self.timeout)
            if r.status_code != 200:
                print(f"[!] Haystak: HTTP {r.status_code}")
                return []
            results = self._parse_onion_links(r.text, "haystak")
            print(f"[✓] Haystak: {len(results)} resultado(s)")
            return results
        except Exception as e:
            print(f"[!] Haystak error: {e}")
            return []

    def search_torch(self) -> List[Dict]:
        """Torch .onion vía Tor (el motor dark web más antiguo)."""
        print("[*] Torch (Tor)...")
        url = f"http://{TORCH_ONION}/search?query={self.keyword}&cmd=wordquery"
        try:
            r = self._tor_session().get(url, timeout=self.timeout)
            if r.status_code != 200:
                print(f"[!] Torch: HTTP {r.status_code}")
                return []
            results = self._parse_onion_links(r.text, "torch")
            print(f"[✓] Torch: {len(results)} resultado(s)")
            return results
        except Exception as e:
            print(f"[!] Torch error: {e}")
            return []

    # ── multi-motor (osint-darkweb-pkg, opcional) ─────────────────────────────

    def search_multi_engine(self) -> List[Dict]:
        """osint-darkweb-pkg (15+ motores) si está disponible."""
        if not MULTI_ENGINE_AVAILABLE:
            return []
        print("[*] Buscando en 15+ motores (osint-darkweb-pkg)...")
        try:
            raw = get_search_results(self.keyword)
            exclude = {
                "/search?", "/directory", "/advertising", "/last-added",
                "/contact", "/webmaster", "add link", "about", "ascending",
                "descending", "sort", "order", "filter", "submit", "register",
            }
            kw = self.keyword.lower()
            results = []
            for item in raw:
                link  = item.get("link", "")
                title = item.get("title", "").lower()
                if ".onion" not in link:
                    continue
                if any(p in link.lower() or p in title for p in exclude):
                    continue
                if kw in title or kw in link:
                    results.append({
                        "title":       item.get("title", "N/A")[:100],
                        "link":        link,
                        "description": "",
                        "source":      "multi_engine",
                    })
            print(f"[✓] Multi-motor: {len(results)} relevante(s) de {len(raw)} totales")
            return results
        except Exception as e:
            print(f"[!] Multi-motor error: {e}")
            return []

    # ── crawling y análisis ───────────────────────────────────────────────────

    def _threat_keywords(self) -> List[str]:
        base = [
            "leak", "breach", "credential", "password", "database", "dump",
            "hack", "exploit", "filtración", "credenciales", "ransomware", "stealer",
        ]
        kw = self.keyword.lower()
        derived = {kw, kw.split(".")[0]}
        return base + [d for d in derived if d]

    def _crawl_single(self, link: str, threat_keywords: List[str]) -> Dict:
        """Descarga y analiza un único enlace .onion."""
        result = {
            "url": link, "title": "N/A", "emails": [],
            "keywords_found": [], "threat_level": "LOW", "error": None,
        }
        try:
            r = self._tor_session().get(link, timeout=30)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                if soup.title and soup.title.string:
                    result["title"] = soup.title.string.strip()[:100]
                emails = re.findall(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", r.text
                )
                result["emails"] = list(set(emails))[:5]
                text_lower = r.text.lower()
                found = [kw for kw in threat_keywords if kw in text_lower]
                result["keywords_found"] = found
                if self.keyword.lower() in text_lower and len(found) >= 1:
                    result["threat_level"] = "HIGH"
                elif len(found) >= 2:
                    result["threat_level"] = "HIGH"
                elif len(found) == 1:
                    result["threat_level"] = "MEDIUM"
            else:
                result["error"] = f"HTTP {r.status_code}"
        except Exception as e:  # noqa: BLE001
            result["error"] = str(e)
        return result

    def crawl_onion_links(self, links: List[str], max_links: int = 10) -> List[Dict]:
        """Analiza en paralelo enlaces .onion encontrados."""
        from .utils import run_parallel
        threat_keywords = self._threat_keywords()
        targets = links[:max_links]
        print(f"[*] Analizando {len(targets)} enlace(s) .onion...")
        return [
            res for _, res in run_parallel(
                lambda l: self._crawl_single(l, threat_keywords),
                targets, max_workers=5, label="onion_crawl",
            )
            if isinstance(res, dict)
        ]

    # ── orquestación principal ────────────────────────────────────────────────

    def run_all(self) -> Dict:
        """
        Flujo completo:
          1. Verifica Tor.
          2. Busca en Ahmia .onion, Haystak, Torch y multi-motor (si instalado).
          3. Deduplica por URL.
          4. Crawlea los primeros enlaces para análisis de amenazas.
        """
        print("[*] Verificando conexión Tor...")
        if not self.check_tor():
            return {
                "status":  "error",
                "message": f"Tor no está activo. {self._tor_instructions()}",
                "results": [],
            }
        print("[✓] Tor conectado.")

        todos: List[Dict] = []
        todos.extend(self.search_ahmia_onion())
        todos.extend(self.search_haystak())
        todos.extend(self.search_torch())
        todos.extend(self.search_multi_engine())

        # Deduplicar por link
        unicos: Dict[str, Dict] = {}
        for r in todos:
            link = r.get("link")
            if link and link not in unicos:
                unicos[link] = r
        limpios = list(unicos.values())
        print(f"[✓] Total único(s): {len(limpios)} enlace(s) .onion")

        analyzed: List[Dict] = []
        onion_urls = [r["link"] for r in limpios if ".onion" in r.get("link", "")]
        if onion_urls:
            analyzed = self.crawl_onion_links(onion_urls, max_links=5)

        return {
            "status":            "success",
            "keyword":           self.keyword,
            "total_links_found": len(limpios),
            "raw_results":       limpios,
            "analyzed_threats":  analyzed,
            "timestamp":         time.strftime("%Y-%m-%d %H:%M:%S"),
        }
