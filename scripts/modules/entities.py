#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modelo de ENTIDADES + grafo de relaciones (columna vertebral de la correlación).

Por qué: OSINT no son tablas sueltas, son RELACIONES. Hasta ahora cada fase
devolvía su propio dict (subdominios, DNS, brechas, hits de foros, IOCs…). Este
módulo NORMALIZA todo eso a un único grafo de entidades:

    entidad := (tipo, valor)          p.ej. ("email", "ceo@acme.com")
    relación := (origen) --rel--> (destino)

Cada entidad acumula sus FUENTES (con su fiabilidad) y de ahí sale un
CONFIDENCE GRADE (A/B/C/D), que es lo que distingue un dato confirmado por
tres fuentes fiables de una simple inferencia por subcadena.

Es la base sobre la que luego montaremos timeline, visualización de grafo y
correlación de actores. No hace red: solo consume los resultados ya recolectados.
"""

from typing import Dict, List, Tuple

from .utils import get_logger

log = get_logger()


# ─────────────────────────────────────────────────────────────────────────────
# FIABILIDAD DE FUENTES (source reliability scoring)
# ─────────────────────────────────────────────────────────────────────────────
# Peso por nivel de fiabilidad. Una entidad confirmada por fuentes fiables sube
# de grado mucho más rápido que una vista solo en un buscador .onion.
RELIABILITY_WEIGHT = {
    "trusted":   1.0,   # registros factuales / CTI curada
    "mixed":     0.5,   # foros/markets/pastes: contenido real pero ruidoso
    "unknown":   0.25,  # buscadores .onion / pivoting (match por subcadena)
    "malicious": 0.1,   # fuente hostil/no fiable
}

# Clasificación de fuentes por su identificador (prefijo o nombre). Se compara
# en minúsculas por subcadena, así que "tor_search:Ahmia" cae en unknown, etc.
_TIER_TRUSTED = (
    "input", "discovery", "dns", "whois", "crt.sh", "crtsh", "hackertarget",
    "rapiddns", "alienvault", "otx", "threatcrowd", "certspotter", "anubis",
    "wayback", "urlscan", "ransomware.live", "ransomware_live", "ransomlook",
    "hudson", "pulsedive", "maltiverse", "hibp", "xposedornot", "xposed",
    "hunter", "github", "leakcheck", "intelx", "breaches",
)
_TIER_MIXED = (
    "forum", "foro", "breachforums", "xss", "exploit", "nulled", "cracked",
    "bhf", "damagelib", "darkforums", "dread", "dkforest", "germania",
    "telegram", "paste", "leaksite", "leak_site", "ransomware_leaksite",
    "russianmarket", "briansclub", "styx", "abacus",
)
_TIER_UNKNOWN = (
    "tor_search", "pivot", "seed", "onion_seed", "ahmia", "torch", "haystak",
    "onionland", "darksearch", "tor66", "aggregate",
)


def source_tier(source: str) -> str:
    """Devuelve el nivel de fiabilidad ('trusted'/'mixed'/'unknown') de una fuente."""
    s = (source or "").lower()
    if any(k in s for k in _TIER_TRUSTED):
        return "trusted"
    if any(k in s for k in _TIER_MIXED):
        return "mixed"
    if any(k in s for k in _TIER_UNKNOWN):
        return "unknown"
    return "unknown"


def confidence_grade(sources: List[Tuple[str, str]]) -> str:
    """
    Calcula el grado de confianza de una entidad a partir de sus (fuente, tier):

      A → confirmado    (≥3 fuentes distintas, o ≥2 con al menos una fiable)
      B → verificado    (1 fuente fiable, o ≥2 fuentes cualesquiera)
      C → una fuente media (un foro/paste)
      D → inferencia    (una sola fuente débil: buscador .onion / pivoting)
    """
    if not sources:
        return "D"
    distintas = len({s for s, _ in sources})
    pesos = [RELIABILITY_WEIGHT.get(t, 0.25) for _, t in sources]
    w_max = max(pesos)
    if distintas >= 3 or (distintas >= 2 and w_max >= 1.0):
        return "A"
    if w_max >= 1.0 or distintas >= 2:
        return "B"
    if w_max >= 0.5:
        return "C"
    return "D"


GRADE_LABEL = {
    "A": "confirmado",
    "B": "verificado",
    "C": "una fuente",
    "D": "inferencia",
}


# ─────────────────────────────────────────────────────────────────────────────
# GRAFO DE ENTIDADES
# ─────────────────────────────────────────────────────────────────────────────
# IOC type (de ioc_extractor) → tipo de entidad del grafo.
_IOC_TO_ENTITY = {
    "emails":               "email",
    "emails_dominio":       "email",
    "credenciales":         "credencial",
    "dominios":             "dominio",
    "subdominios_objetivo": "subdominio",
    "ips":                  "ip",
    "ipv6":                 "ip",
    "md5":                  "hash",
    "sha1":                 "hash",
    "sha256":               "hash",
    "sha512":               "hash",
    "btc":                  "wallet",
    "eth":                  "wallet",
    "xmr":                  "wallet",
    "cve":                  "cve",
    "onion":                "onion",
}

# Tipos cuyo valor se normaliza a minúsculas (los hashes/wallets son
# sensibles a mayúsculas según el esquema, así que se dejan tal cual).
_LOWER_TYPES = {"email", "dominio", "subdominio", "onion", "ip"}


class EntityGraph:
    """Acumula entidades (deduplicadas) y relaciones con su procedencia."""

    def __init__(self):
        # clave (tipo, valor_norm) → {type, value, sources:[(src,tier)], attrs}
        self._ent: Dict[Tuple[str, str], dict] = {}
        self._rel: List[dict] = []
        self._rel_seen: set = set()

    @staticmethod
    def _norm(etype: str, value: str) -> str:
        v = (value or "").strip()
        return v.lower() if etype in _LOWER_TYPES else v

    def add(self, etype: str, value: str, source: str, tier: str = "",
            attrs: dict = None) -> Tuple[str, str]:
        """Añade/fusiona una entidad y registra la fuente. Devuelve su clave."""
        v = self._norm(etype, value)
        if not v:
            return ("", "")
        key = (etype, v)
        tier = tier or source_tier(source)
        ent = self._ent.get(key)
        if ent is None:
            ent = {"type": etype, "value": v, "sources": [], "attrs": {}}
            self._ent[key] = ent
        if (source, tier) not in ent["sources"]:
            ent["sources"].append((source, tier))
        if attrs:
            ent["attrs"].update(attrs)
        return key

    def relate(self, src_key: Tuple[str, str], rel: str,
               dst_key: Tuple[str, str], source: str = "") -> None:
        if not src_key[1] or not dst_key[1] or src_key == dst_key:
            return
        sig = (src_key, rel, dst_key)
        if sig in self._rel_seen:
            return
        self._rel_seen.add(sig)
        self._rel.append({
            "from": {"type": src_key[0], "value": src_key[1]},
            "rel":  rel,
            "to":   {"type": dst_key[0], "value": dst_key[1]},
            "source": source,
        })

    def add_iocs(self, iocs: Dict[str, list], source: str,
                 link_to: Tuple[str, str] = None, rel: str = "menciona") -> None:
        """Vuelca un dict de IOCs (de ioc_extractor) como entidades con su fuente."""
        tier = source_tier(source)
        for ioc_type, valores in (iocs or {}).items():
            etype = _IOC_TO_ENTITY.get(ioc_type)
            if not etype:
                continue
            for val in valores or []:
                key = self.add(etype, val, source, tier)
                if link_to and key[1]:
                    self.relate(link_to, rel, key, source)

    def export(self) -> dict:
        """Serializa el grafo con el confidence grade calculado por entidad."""
        entidades = []
        by_type: Dict[str, int] = {}
        by_grade: Dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0}
        for ent in self._ent.values():
            grade = confidence_grade(ent["sources"])
            fuentes = sorted({s for s, _ in ent["sources"]})
            entidades.append({
                "type":      ent["type"],
                "value":     ent["value"],
                "grade":     grade,
                "n_sources": len(fuentes),
                "sources":   fuentes,
                "attrs":     ent["attrs"],
            })
            by_type[ent["type"]] = by_type.get(ent["type"], 0) + 1
            by_grade[grade] = by_grade.get(grade, 0) + 1
        # Orden: primero por grado (A→D), luego por nº de fuentes desc.
        _go = {"A": 0, "B": 1, "C": 2, "D": 3}
        entidades.sort(key=lambda e: (_go.get(e["grade"], 9), -e["n_sources"], e["type"]))
        return {
            "entities":  entidades,
            "relations": self._rel,
            "stats": {
                "total":    len(entidades),
                "by_type":  by_type,
                "by_grade": by_grade,
                "relations": len(self._rel),
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUCCIÓN DEL GRAFO A PARTIR DE LOS RESULTADOS DEL ESCANEO
# ─────────────────────────────────────────────────────────────────────────────
def build_entity_graph(domain: str, discovery: dict, threat_intel: dict) -> dict:
    """
    Normaliza los resultados de discovery + threat_intel (incluida dark web) a un
    grafo de entidades con confidence scoring. Tolerante a claves ausentes.
    """
    g = EntityGraph()
    discovery = discovery or {}
    threat_intel = threat_intel or {}

    root = g.add("dominio", domain, "input", "trusted")

    # ── Discovery: subdominios (con procedencia real) ──────────────────────────
    for sub in discovery.get("subdomains", []) or []:
        k = g.add("subdominio", sub, "discovery", "trusted")
        g.relate(root, "tiene_subdominio", k, "discovery")
    for src, subs in (discovery.get("subdomain_sources", {}) or {}).items():
        for sub in subs or []:
            g.add("subdominio", sub, src)  # tier inferido del nombre de la fuente

    # ── Discovery: DNS → IPs y registros ───────────────────────────────────────
    dns = discovery.get("dns_records", {}) or {}
    for rtype, valores in dns.items():
        if not isinstance(valores, (list, tuple)):
            valores = [valores]
        for v in valores:
            v = str(v).strip()
            if rtype.upper() in ("A", "AAAA") and v:
                k = g.add("ip", v, f"dns:{rtype}", "trusted")
                g.relate(root, "resuelve_a", k, "dns")

    # ── Brechas (HIBP / XposedOrNot…) → emails comprometidos ───────────────────
    dw = threat_intel.get("darkweb", {}) or {}
    breaches = dw.get("breaches", {}) if isinstance(dw, dict) else {}
    if isinstance(breaches, dict):
        for em in breaches.get("emails_comprometidos", []) or []:
            val = em.get("email") if isinstance(em, dict) else em
            if val:
                k = g.add("email", val, "breaches", "trusted")
                g.relate(k, "asociado_a", root, "breaches")

    # ── Dark web por fuente: cada hit trae sus propios IOCs con procedencia ────
    ds = dw.get("dark_sources", {}) if isinstance(dw, dict) else {}
    if isinstance(ds, dict):
        _ingest_hit_list(g, ds.get("forum_hits", []), "foro", root)
        _ingest_hit_list(g, ds.get("tor_search_hits", []), "tor_search", root)
        _ingest_hit_list(g, ds.get("telegram_hits", []), "telegram", root)
        _ingest_hit_list(g, ds.get("paste_hits", []), "paste", root)
        _ingest_hit_list(g, ds.get("leaksites_hits", []), "leaksite", root)

        # Semillas .onion descubiertas → entidades onion (descubrimiento puro).
        for s in ds.get("onion_seeds", []) or []:
            if isinstance(s, dict) and s.get("onion"):
                g.add("onion", s["onion"], s.get("fuente", "onion_seed"), "unknown",
                      attrs={"titulo": s.get("titulo", "")})

        # Salud de .onion → atributo de estado en la entidad onion.
        for h in ds.get("onion_health", []) or []:
            if isinstance(h, dict) and h.get("onion"):
                g.add("onion", h["onion"], "onion_health",
                      attrs={"estado": h.get("estado", ""),
                             "servicio": h.get("servicio", "")})

    # ── Pivoting: hits relanzados con los IOCs (fiabilidad baja, subcadena) ─────
    pivot = dw.get("pivoting", {}) if isinstance(dw, dict) else {}
    if isinstance(pivot, dict):
        _ingest_hit_list(g, pivot.get("hits", []), "pivot", root)

    # ── IOCs agregados (respaldo): los que no llegaron con procedencia por hit ──
    agg = dw.get("iocs", {}) if isinstance(dw, dict) else {}
    if isinstance(agg, dict):
        g.add_iocs(agg.get("iocs", {}), "darkweb_aggregate", link_to=root)

    graph = g.export()
    st = graph["stats"]
    log.info("   [*] Grafo de entidades: %d entidades (%dA/%dB/%dC/%dD), %d relaciones",
             st["total"], st["by_grade"]["A"], st["by_grade"]["B"],
             st["by_grade"]["C"], st["by_grade"]["D"], st["relations"])
    return graph


def _ingest_hit_list(g: EntityGraph, hits, fuente_base: str,
                     root: Tuple[str, str]) -> None:
    """Vuelca los IOCs de cada hit de una fuente dark web al grafo."""
    if not isinstance(hits, list):
        return
    for h in hits:
        if not isinstance(h, dict):
            continue
        # Etiqueta de fuente: prioriza el nombre concreto (foro/motor) si existe.
        etiqueta = str(h.get("fuente") or h.get("foro") or h.get("motor") or fuente_base)
        # Evita duplicar el prefijo (p.ej. fuente="pivot_tor:Torch" ya lleva el contexto).
        if etiqueta == fuente_base or fuente_base in etiqueta.lower():
            fuente = etiqueta
        else:
            fuente = f"{fuente_base}:{etiqueta}"
        g.add_iocs(h.get("iocs", {}), fuente, link_to=root)
