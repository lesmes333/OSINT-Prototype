#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integración con INCIBE-CERT (Instituto Nacional de Ciberseguridad de España).

Proporciona, para cada vulnerabilidad detectada:
  1. Una URL de referencia en español en INCIBE-CERT (válida para cualquier CVE
     catalogado): .../alerta-temprana/vulnerabilidades/cve-xxxx-yyyyy
  2. Enriquecimiento con el feed de "Alerta Temprana" de INCIBE-CERT, que publica
     las vulnerabilidades más recientes con su título en español, gravedad, CVSS
     (3.1 y 4.0), tipo (CWE) y fechas.

El feed se descarga una sola vez y se cachea en memoria. Las comprobaciones de
existencia de cada página CVE se hacen en paralelo.
"""

import re
from html import unescape
from typing import Dict, List, Optional

from .utils import get_logger, make_session, run_parallel

log = get_logger()

FEED_URL = "https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/feed"
BASE_CVE_URL = "https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/"
# URL de búsqueda general (la que facilita el usuario) como referencia de fallback
SEARCH_URL = (
    "https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades?"
    "field_vulnerability_severity_txt=All"
)


def cve_reference_url(cve_id: str) -> str:
    """Devuelve la URL de la ficha INCIBE-CERT para un CVE concreto."""
    return BASE_CVE_URL + cve_id.strip().lower()


class IncibeCert:
    """Cliente ligero para el feed de Alerta Temprana de INCIBE-CERT."""

    def __init__(self):
        self.session = make_session()
        self._feed_index: Optional[Dict[str, Dict]] = None

    # ------------------------------------------------------------
    # Descarga y parseo del feed RSS (artículos HTML embebidos)
    # ------------------------------------------------------------
    @staticmethod
    def _field(block: str, field_name: str) -> str:
        """Extrae el valor de un campo field--name-<field_name> dentro de un <article>."""
        pat = (
            r'field--name-' + re.escape(field_name) + r'\b.*?field__item[^>]*>\s*'
            r'(?:<p>)?\s*(?:<time[^>]*>)?([^<]+)'
        )
        m = re.search(pat, block, re.S)
        return unescape(m.group(1).strip()) if m else ""

    def fetch_feed(self) -> Dict[str, Dict]:
        """
        Descarga el feed y construye un índice {CVE: datos}. Cachea el resultado.
        """
        if self._feed_index is not None:
            return self._feed_index

        index: Dict[str, Dict] = {}
        try:
            r = self.session.get(FEED_URL, timeout=20)
            if r.status_code != 200:
                log.debug(f"    [!] INCIBE feed HTTP {r.status_code}")
                self._feed_index = index
                return index

            for block in re.findall(r"<article.*?</article>", r.text, re.S):
                title = self._field(block, "field-vulnerability-title-es") or ""
                m = re.search(r"CVE-\d{4}-\d{4,7}", block, re.I)
                cve_id = m.group(0).upper() if m else None
                if not cve_id:
                    continue
                index[cve_id] = {
                    "cve": cve_id,
                    "titulo_es": title or cve_id,
                    "tipo": self._field(block, "field-vulnerability-type"),
                    "gravedad_31": self._field(block, "field-vul-severity-txt-31"),
                    "gravedad_40": self._field(block, "field-vul-severity-txt-40"),
                    "cvss_31": self._field(block, "field-vul-severity-31"),
                    "cvss_40": self._field(block, "field-vul-severity-40"),
                    "vector_31": self._field(block, "field-vul-vector-31"),
                    "fecha_publicacion": self._field(block, "field-vul-publication-date"),
                    "descripcion": self._field(block, "field-vulnerability-descrip-en"),
                    "url": cve_reference_url(cve_id),
                }
            log.debug(f"    [+] INCIBE feed: {len(index)} vulnerabilidades en alerta temprana")
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error leyendo feed INCIBE: {e}")

        self._feed_index = index
        return index

    # ------------------------------------------------------------
    # Comprobación de existencia de una ficha CVE (en paralelo)
    # ------------------------------------------------------------
    def _page_exists(self, cve_id: str) -> bool:
        try:
            r = self.session.get(cve_reference_url(cve_id), timeout=15, allow_redirects=True)
            if r.status_code != 200:
                return False
            # Las páginas reales muestran el identificador CVE en el contenido
            return cve_id.lower() in r.url.lower() or cve_id.upper() in r.text
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------
    # Enriquecer una lista de CVEs con datos/links de INCIBE-CERT
    # ------------------------------------------------------------
    def enrich_cves(self, cve_ids: List[str], verify: bool = True) -> Dict[str, Dict]:
        """
        Para cada CVE devuelve:
          - url: ficha INCIBE-CERT
          - disponible: True/False (si verify=True; None si no se comprueba)
          - en_alerta_temprana: True si aparece en el feed reciente
          - datos del feed (titulo_es, gravedad, cvss...) cuando estén disponibles
        """
        cve_ids = sorted({c.upper() for c in cve_ids if c})
        if not cve_ids:
            return {}

        feed = self.fetch_feed()
        result: Dict[str, Dict] = {}

        # Verificación de existencia en paralelo (opcional)
        existence: Dict[str, Optional[bool]] = {c: None for c in cve_ids}
        if verify:
            for cve, ok in run_parallel(self._page_exists, cve_ids, max_workers=10, label="incibe"):
                existence[cve] = ok if isinstance(ok, bool) else False

        for cve in cve_ids:
            entry = {
                "url": cve_reference_url(cve),
                "disponible": existence[cve],
                "en_alerta_temprana": cve in feed,
            }
            if cve in feed:
                entry.update(
                    {
                        "titulo_es": feed[cve]["titulo_es"],
                        "tipo": feed[cve]["tipo"],
                        "gravedad": feed[cve].get("gravedad_31") or feed[cve].get("gravedad_40"),
                        "cvss": feed[cve].get("cvss_31") or feed[cve].get("cvss_40"),
                        "fecha_publicacion": feed[cve]["fecha_publicacion"],
                    }
                )
            result[cve] = entry
        disponibles = sum(1 for v in result.values() if v.get("disponible"))
        en_alerta = sum(1 for v in result.values() if v.get("en_alerta_temprana"))
        log.info(
            f"   [=] INCIBE-CERT: {disponibles}/{len(cve_ids)} con ficha; "
            f"{en_alerta} en alerta temprana reciente"
        )
        return result

    # ------------------------------------------------------------
    # Cruce de tecnologías detectadas con el feed reciente
    # ------------------------------------------------------------
    def match_technologies(self, technologies: List[str]) -> List[Dict]:
        """
        Busca en el feed reciente de INCIBE-CERT vulnerabilidades cuyo título o
        descripción mencione alguna de las tecnologías detectadas. Útil para
        avisos de "alerta temprana" relevantes para el objetivo.
        """
        feed = self.fetch_feed()
        if not feed or not technologies:
            return []
        terms = {t.lower() for t in technologies if t and len(t) > 2}
        matches = []
        for data in feed.values():
            haystack = (data.get("titulo_es", "") + " " + data.get("descripcion", "")).lower()
            hit = next((t for t in terms if t in haystack), None)
            if hit:
                matches.append({**data, "tecnologia": hit})
        return matches
