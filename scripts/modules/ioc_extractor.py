#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extracción y exportación de IOCs (Indicators of Compromise) detectados en la
dark web y demás fuentes de exposición.

Convierte los extractos de texto crudo recolectados por las capas de dark web
(menciones en foros, leak sites, paste sites, canales Telegram, motores .onion)
en indicadores estructurados y accionables:

  · Emails (resaltando los del dominio objetivo)
  · Credenciales filtradas (email:contraseña / usuario:contraseña)
  · Dominios y subdominios del objetivo
  · Direcciones IPv4 e IPv6 públicas
  · Hashes (MD5 / SHA1 / SHA256 / SHA512) — contraseñas hasheadas o muestras malware
  · Direcciones de criptomoneda (BTC / ETH / XMR) — rescates, pagos de carding
  · Identificadores CVE
  · Servicios .onion mencionados

Exporta a JSON (estructurado) y CSV (una fila por IOC) listos para ingerir en
un SIEM/TIP o compartir con el equipo de respuesta.

Todo es análisis pasivo de texto ya recolectado: no genera tráfico de red.
"""

import csv
import ipaddress
import json
import os
import re
import time
from typing import Dict, List, Set

from .utils import get_logger

log = get_logger()

# ─────────────────────────────────────────────────────────────────────────────
# Patrones de detección
# ─────────────────────────────────────────────────────────────────────────────
# Email estándar (RFC-ish, suficiente para OSINT).
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}\b"
)

# Credenciales: email:contraseña o usuario:contraseña (formato típico de combolists).
# La contraseña se captura sin espacios y de longitud razonable (4-64).
_RE_CRED_EMAIL = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}):([^\s:,;\"'<>]{4,64})"
)
_RE_CRED_USER = re.compile(
    r"\b([a-zA-Z0-9._\-]{3,32}):([^\s:,;\"'<>]{4,64})\b"
)

# IPv4 (se valida después con ipaddress para descartar privadas/reservadas).
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# IPv6 — en vez de un regex por alternancia (que trocea las formas comprimidas
# con '::'), capturamos un "candidato" formado solo por hex y ':' y dejamos que
# ipaddress decida si es una IPv6 real. Exigir >=2 ':' descarta horas (12:34) y
# fragmentos sueltos. Es el enfoque más fiable para IPv6.
_RE_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:]{4,45}")

# Hashes — longitudes exactas con límites de palabra para evitar falsos positivos.
# Orden de extracción: SHA512 → SHA256 → SHA1 → MD5 (el más largo primero, para
# no trocear un hash largo en varios cortos).
_RE_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Criptomonedas.
_RE_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_RE_XMR = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# CVE.
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Servicios .onion (v2 16 chars / v3 56 chars).
_RE_ONION = re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b")

# Dominios / subdominios genéricos (uno o más labels + TLD alfabético).
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Extensiones de archivo que el regex de dominio confundiría con un TLD
# (example.txt, base.sql, dump.rar…). Se descartan como dominios.
_FILE_EXTENSIONS = {
    "txt", "sql", "csv", "json", "xml", "log", "zip", "rar", "gz", "tar",
    "7z", "png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx",
    "exe", "dll", "bin", "bat", "sh", "py", "php", "js", "css", "html",
    "htm", "md", "yml", "yaml", "ini", "conf", "bak", "db", "sqlite",
}

# Campos de los dicts de resultados dark web que contienen texto libre útil.
_TEXT_FIELDS = (
    "extracto", "contexto", "texto", "description", "desc", "title",
    "nombre", "victima", "post_title",
)

# Palabras que, si aparecen como "contraseña" en cred:user, suelen ser ruido
# (rutas, claves de config, etc.). Filtro conservador.
_CRED_NOISE = {"http", "https", "www", "com", "org", "net", "html", "php"}


def _is_public_ipv4(ip: str) -> bool:
    """True si la IP es válida y enrutable públicamente (descarta privadas/reservadas)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_multicast or addr.is_link_local or addr.is_unspecified)


def _is_public_ipv6(ip: str) -> bool:
    """True si `ip` es una IPv6 válida y enrutable públicamente (descarta privadas/locales)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 6 and not (
        addr.is_private or addr.is_loopback or addr.is_reserved
        or addr.is_multicast or addr.is_link_local or addr.is_unspecified
    )


def extract_iocs(text: str, target_domain: str = "") -> Dict[str, Set[str]]:
    """
    Extrae todos los tipos de IOC de un bloque de texto plano.

    Tipos detectados:
      · emails / emails_dominio (los del dominio objetivo)
      · credenciales (email:pass y user:pass, formato combolist)
      · dominios / subdominios_objetivo
      · ips (IPv4 pública) / ipv6
      · md5 / sha1 / sha256 / sha512
      · btc / eth / xmr
      · cve / onion

    Devuelve un dict {tipo: set(valores)}. El llamador une los sets de varios
    textos (ver extract_iocs_from_results). Esta es la función canónica que pide
    la integración; `extract_iocs_from_text` se mantiene como alias.
    """
    found: Dict[str, Set[str]] = {
        "emails": set(),
        "emails_dominio": set(),
        "credenciales": set(),
        "dominios": set(),
        "subdominios_objetivo": set(),
        "ips": set(),
        "ipv6": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
        "sha512": set(),
        "btc": set(),
        "eth": set(),
        "xmr": set(),
        "cve": set(),
        "onion": set(),
    }
    if not text or not isinstance(text, str):
        return found

    base = target_domain.lower().strip()

    # IPv6 primero: validamos candidatos y guardamos sus posiciones (spans) para
    # no confundir luego fragmentos como '2001:4860' con credenciales user:pass.
    ipv6_spans = []
    for m in _RE_IPV6_CANDIDATE.finditer(text):
        cand = m.group(0).strip(":")
        if cand.count(":") >= 2 and _is_public_ipv6(cand):
            found["ipv6"].add(ipaddress.ip_address(cand).compressed)
            ipv6_spans.append((m.start(), m.end()))

    def _in_ipv6(pos: int) -> bool:
        return any(s <= pos < e for s, e in ipv6_spans)

    # Credenciales email:pass primero (consumen el par antes de contar el email suelto).
    for m in _RE_CRED_EMAIL.finditer(text):
        user, pwd = m.group(1), m.group(2)
        found["credenciales"].add(f"{user}:{pwd}")

    # Emails.
    for email in _RE_EMAIL.findall(text):
        email_l = email.lower()
        found["emails"].add(email_l)
        if base and email_l.endswith("@" + base):
            found["emails_dominio"].add(email_l)

    # Credenciales usuario:pass (solo si no son ya un email:pass, IPv6 ni ruido).
    for m in _RE_CRED_USER.finditer(text):
        user, pwd = m.group(1), m.group(2)
        if _in_ipv6(m.start()):                       # fragmento de una IPv6
            continue
        if user.lower() in _CRED_NOISE or pwd.lower() in _CRED_NOISE:
            continue
        if user.isdigit() and len(user) <= 4:         # típico de IP/puerto, no usuario
            continue
        # Si el carácter previo es '@' o '.', es un fragmento de un email/host
        # ya capturado por _RE_CRED_EMAIL (p.ej. el 'example.com' de a@example.com:pw).
        prev = text[m.start() - 1] if m.start() > 0 else " "
        if prev in "@.:":
            continue
        if f"{user}@" in text.lower():  # probablemente parte de un email
            continue
        found["credenciales"].add(f"{user}:{pwd}")

    # Dominios / subdominios — se descartan los que terminan en extensión de archivo.
    for dom in _RE_DOMAIN.findall(text):
        dom_l = dom.lower().strip(".")
        if dom_l.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        if dom_l.endswith(".onion"):
            continue  # se gestiona aparte
        found["dominios"].add(dom_l)
        if base and (dom_l == base or dom_l.endswith("." + base)):
            found["subdominios_objetivo"].add(dom_l)

    # IPv4 públicas (IPv6 ya procesadas arriba, antes que las credenciales).
    for ip in _RE_IPV4.findall(text):
        if _is_public_ipv4(ip):
            found["ips"].add(ip)

    # Hashes — orden de mayor a menor para no recortar un hash largo en varios cortos.
    remaining = text
    for tipo, regex in (("sha512", _RE_SHA512), ("sha256", _RE_SHA256),
                        ("sha1", _RE_SHA1), ("md5", _RE_MD5)):
        matches = set(regex.findall(remaining))
        found[tipo].update(h.lower() for h in matches)
        for h in matches:  # evita que un hash ya contado reaparezca como uno más corto
            remaining = remaining.replace(h, " ")

    # Cripto.
    found["btc"].update(_RE_BTC.findall(text))
    found["eth"].update(m.lower() for m in _RE_ETH.findall(text))
    found["xmr"].update(_RE_XMR.findall(text))

    # CVE y onion.
    found["cve"].update(c.upper() for c in _RE_CVE.findall(text))
    found["onion"].update(o.lower() for o in _RE_ONION.findall(text))

    return found


# Alias de compatibilidad con la integración previa.
extract_iocs_from_text = extract_iocs


def _iter_text_fields(obj) -> List[str]:
    """Recorre recursivamente un dict/list y devuelve los valores de texto relevantes."""
    texts: List[str] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, str) and key in _TEXT_FIELDS:
                texts.append(val)
            elif isinstance(val, (dict, list)):
                texts.extend(_iter_text_fields(val))
    elif isinstance(obj, list):
        for item in obj:
            texts.extend(_iter_text_fields(item))
    return texts


def extract_iocs_from_results(darkweb_summary: Dict,
                              target_domain: str = "") -> Dict:
    """
    Recorre el resumen completo de un escaneo dark web (run_full_darkweb_scan /
    ExposureMonitor.run_all) y consolida todos los IOCs detectados.

    Devuelve un dict con:
      · iocs:   {tipo: [valores ordenados]}
      · counts: {tipo: nº}
      · total:  nº total de IOCs únicos
    """
    texts = _iter_text_fields(darkweb_summary)
    log.info("   [*] IOC extractor: analizando %d extractos de texto...", len(texts))

    merged: Dict[str, Set[str]] = {}
    for text in texts:
        partial = extract_iocs_from_text(text, target_domain)
        for tipo, values in partial.items():
            merged.setdefault(tipo, set()).update(values)

    iocs = {tipo: sorted(vals) for tipo, vals in merged.items() if vals}
    counts = {tipo: len(vals) for tipo, vals in iocs.items()}
    total = sum(counts.values())

    if total:
        resumen = ", ".join(f"{n} {t}" for t, n in counts.items())
        log.info("   [=] IOCs extraídos: %d (%s)", total, resumen)
    else:
        log.info("   [=] IOCs extraídos: 0")

    return {"iocs": iocs, "counts": counts, "total": total}


def export_iocs(ioc_result: Dict, output_dir: str, domain: str,
                timestamp: str = "") -> Dict[str, str]:
    """
    Exporta los IOCs a JSON y CSV en `output_dir`.

    :return: dict {formato: ruta} de los archivos generados.
    """
    if not ioc_result.get("total"):
        log.debug("export_iocs: sin IOCs que exportar")
        return {}

    ts = timestamp or time.strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")
    os.makedirs(output_dir, exist_ok=True)
    paths: Dict[str, str] = {}

    # ── JSON ──────────────────────────────────────────────────────────────────
    json_path = os.path.join(output_dir, f"iocs_{safe_domain}_{ts}.json")
    payload = {
        "domain": domain,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_iocs": ioc_result["total"],
        "counts": ioc_result["counts"],
        "iocs": ioc_result["iocs"],
    }
    try:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        paths["json"] = json_path
    except OSError as e:
        log.debug("export_iocs JSON: %s", e)

    # ── CSV (una fila por IOC) ──────────────────────────────────────────────────
    csv_path = os.path.join(output_dir, f"iocs_{safe_domain}_{ts}.csv")
    try:
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["tipo", "valor"])
            for tipo, values in ioc_result["iocs"].items():
                for val in values:
                    writer.writerow([tipo, val])
        paths["csv"] = csv_path
    except OSError as e:
        log.debug("export_iocs CSV: %s", e)

    if paths:
        log.info("   [+] IOCs exportados: %s", " | ".join(paths.values()))
    return paths
