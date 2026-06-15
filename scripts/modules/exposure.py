#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Monitorización de exposición y filtraciones (enfoque defensivo y legal).

Reúne, por capas, la información sobre exposición de un dominio en fuentes
públicas, deep web y dark web **legalmente accesibles**, sin acceder a sistemas
ajenos ni a contenido ilegal:

  Capa 1 — Brechas de datos:
      ¿Aparece el dominio o sus correos en filtraciones conocidas?
      · XposedOrNot (gratis, sin clave)
      · Have I Been Pwned (si hay HIBP_API_KEY)

  Capa 2 — Índice de dark web (Ahmia, por clearnet, SIN Tor):
      Menciones del dominio en servicios .onion indexados públicamente.

  Capa 3 — Paste sites (PSBDMP):
      Menciones del dominio en volcados de Pastebin indexados.

  Capa 4 — Crawling .onion vía Tor (OPCIONAL, avanzada):
      Solo si se solicita explícitamente y Tor está disponible. Reutiliza
      DarkWebMonitor. Desactivada por defecto por su coste y sus implicaciones.

Todo es consulta a índices/APIs públicas. No se interactúa con los sistemas
objetivo ni se descarga contenido ilegal.
"""

import os
import re
import time
from typing import Dict, List, Optional

from bs4 import BeautifulSoup

from .utils import get_logger, make_session, run_parallel

log = get_logger()

XON_BASE = "https://api.xposedornot.com/v1"
HIBP_BASE = "https://haveibeenpwned.com/api/v3"
AHMIA_URL = "https://ahmia.fi/search/?q={q}"
PSBDMP_URL = "https://psbdmp.ws/api/v3/search/{q}"


class ExposureMonitor:
    def __init__(self, domain: str, emails: Optional[List[str]] = None,
                 run_tor: bool = False, threads: int = 10):
        self.domain = domain.lower().strip()
        # Deduplica y normaliza los correos a vigilar.
        self.emails = sorted({e.lower().strip() for e in (emails or []) if "@" in e})
        self.run_tor = run_tor
        self.threads = threads
        self.session = make_session()
        self.hibp_key = os.getenv("HIBP_API_KEY", "")

    # ============================================================
    # CAPA 1 — Brechas de datos
    # ============================================================
    def _xon_check_email(self, email: str) -> Dict:
        """Consulta XposedOrNot para un email concreto (gratis, sin clave)."""
        try:
            r = self.session.get(f"{XON_BASE}/check-email/{email}", timeout=15)
            if r.status_code == 200:
                breaches = r.json().get("breaches", [])
                # La API devuelve [[ "BreachA", "BreachB" ]]; lo aplanamos.
                flat = []
                for grupo in breaches:
                    flat.extend(grupo if isinstance(grupo, list) else [grupo])
                return {"email": email, "found": bool(flat), "breaches": flat}
            if r.status_code == 404:
                return {"email": email, "found": False, "breaches": []}
            return {"email": email, "found": False, "breaches": [], "error": f"HTTP {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"email": email, "found": False, "breaches": [], "error": str(e)}

    def _hibp_check_email(self, email: str) -> Dict:
        """Consulta Have I Been Pwned para un email (requiere HIBP_API_KEY)."""
        headers = {"hibp-api-key": self.hibp_key, "user-agent": "OSINT-Recon-Suite"}
        try:
            r = self.session.get(
                f"{HIBP_BASE}/breachedaccount/{email}?truncateResponse=true",
                headers=headers, timeout=15,
            )
            if r.status_code == 200:
                names = [b.get("Name") for b in r.json()]
                return {"breaches": [n for n in names if n]}
            if r.status_code == 404:
                return {"breaches": []}
            return {"breaches": [], "error": f"HTTP {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"breaches": [], "error": str(e)}

    def layer_breaches(self) -> Dict:
        """Capa 1: comprueba el dominio y cada correo en bases de filtraciones."""
        log.info("   [*] Capa 1: brechas de datos (XposedOrNot/HIBP)...")
        per_email = []
        # XposedOrNot por cada email (en paralelo).
        if self.emails:
            for _, res in run_parallel(self._xon_check_email, self.emails,
                                       max_workers=min(self.threads, 8), label="xposedornot"):
                if isinstance(res, dict):
                    per_email.append(res)

        # HIBP enriquece si hay clave (secuencial: HIBP limita la tasa).
        if self.hibp_key and self.emails:
            hibp_index = {}
            for email in self.emails:
                hibp_index[email] = self._hibp_check_email(email).get("breaches", [])
                time.sleep(1.6)  # respeta el rate limit de HIBP
            for row in per_email:
                extra = hibp_index.get(row["email"], [])
                if extra:
                    row["breaches"] = sorted(set(row.get("breaches", []) + extra))
                    row["found"] = True

        comprometidos = [r for r in per_email if r.get("found")]
        return {
            "checked_emails": len(per_email),
            "compromised_emails": len(comprometidos),
            "results": per_email,
            "hibp_used": bool(self.hibp_key),
        }

    # ============================================================
    # CAPA 2 — Índice de dark web (Ahmia, clearnet, sin Tor)
    # ============================================================
    def layer_ahmia(self) -> Dict:
        """Capa 2: busca menciones del dominio en .onion indexados por Ahmia."""
        log.info("   [*] Capa 2: índice dark web Ahmia (sin Tor)...")
        results = []
        try:
            r = self.session.get(AHMIA_URL.format(q=self.domain), timeout=25)
            if r.status_code != 200:
                return {"status": "error", "message": f"HTTP {r.status_code}", "links": []}
            soup = BeautifulSoup(r.text, "html.parser")
            for res in soup.select("li.result, div.result"):
                a = res.select_one("a")
                if not a:
                    continue
                # Ahmia muestra el .onion en el atributo cite/href o en el texto.
                href = a.get("href", "")
                m = re.search(r"[a-z2-7]{16,56}\.onion", href + " " + res.get_text())
                onion = m.group(0) if m else None
                if not onion:
                    continue
                title = a.get_text(strip=True)[:100]
                desc_el = res.select_one("p")
                results.append({
                    "title": title or onion,
                    "onion": onion,
                    "description": (desc_el.get_text(strip=True)[:200] if desc_el else ""),
                    "source": "ahmia",
                })
            # Deduplica por .onion
            vistos, unicos = set(), []
            for r0 in results:
                if r0["onion"] in vistos:
                    continue
                vistos.add(r0["onion"])
                unicos.append(r0)
            return {"status": "success", "total": len(unicos), "links": unicos}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e), "links": []}

    # ============================================================
    # CAPA 3 — Paste sites (PSBDMP)
    # ============================================================
    def layer_pastes(self) -> Dict:
        """Capa 3: busca el dominio en volcados de Pastebin indexados (PSBDMP)."""
        log.info("   [*] Capa 3: paste sites (PSBDMP)...")
        try:
            r = self.session.get(PSBDMP_URL.format(q=self.domain), timeout=20)
            if r.status_code != 200:
                return {"status": "error", "message": f"HTTP {r.status_code}", "pastes": []}
            data = r.json()
            items = data.get("data", []) if isinstance(data, dict) else []
            pastes = [{
                "id": it.get("id"),
                "date": it.get("date", ""),
                "url": f"https://psbdmp.ws/{it.get('id')}",
                "tags": it.get("tags", ""),
            } for it in items if it.get("id")]
            return {"status": "success", "total": len(pastes), "pastes": pastes[:50]}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e), "pastes": []}

    # ============================================================
    # CAPA 4 — Tor (opcional, avanzada)
    # ============================================================
    def layer_tor(self) -> Dict:
        """Capa 4: crawling .onion vía Tor. Solo si se solicita y Tor está activo."""
        log.info("   [*] Capa 4: crawling .onion vía Tor (opcional)...")
        try:
            from .darkweb_monitor import DarkWebMonitor
            return DarkWebMonitor(self.domain).run_all()
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    # ============================================================
    # Orquestación
    # ============================================================
    def run_all(self) -> Dict:
        breaches = self.layer_breaches()
        ahmia = self.layer_ahmia()
        pastes = self.layer_pastes()
        tor = self.layer_tor() if self.run_tor else {"status": "skipped"}

        # Agregado compatible con el contrato 'darkweb' previo (informe/UI).
        onion_links = [{"title": x["title"], "link": f"http://{x['onion']}",
                        "description": x.get("description", ""), "source": "ahmia"}
                       for x in ahmia.get("links", [])]
        analyzed_threats = tor.get("analyzed_threats", []) if isinstance(tor, dict) else []
        if isinstance(tor, dict):
            for tr in tor.get("raw_results", []):
                if tr.get("link"):
                    onion_links.append(tr)

        # Resumen de riesgo de exposición.
        summary = {
            "emails_comprometidos": breaches.get("compromised_emails", 0),
            "menciones_onion": ahmia.get("total", 0),
            "pastes": pastes.get("total", 0),
        }
        nivel = "LOW"
        if summary["emails_comprometidos"] > 0 or summary["pastes"] > 0:
            nivel = "HIGH"
        elif summary["menciones_onion"] > 0:
            nivel = "MEDIUM"
        summary["nivel_exposicion"] = nivel

        return {
            "status": "success",
            "keyword": self.domain,
            # --- nuevas capas legales ---
            "breaches": breaches,
            "ahmia": ahmia,
            "pastes": pastes,
            "tor": tor,
            "summary": summary,
            # --- compatibilidad con el contrato 'darkweb' anterior ---
            "total_links_found": len(onion_links),
            "raw_results": onion_links,
            "analyzed_threats": analyzed_threats,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
