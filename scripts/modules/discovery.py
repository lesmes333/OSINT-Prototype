#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de descubrimiento pasivo de activos para un dominio.

Fuentes SIN clave API (todas en paralelo):
  crt.sh, certspotter, HackerTarget, RapidDNS, Anubis (jldc.me),
  AlienVault OTX passive DNS, Wayback Machine (web.archive.org),
  DNSdumpster, Subfinder (CLI) y consultas DNS + WHOIS.

El uso de múltiples fuentes gratuitas maximiza la cobertura de subdominios
sin depender de claves de pago, y la ejecución concurrente reduce
drásticamente el tiempo total.
"""

import json
import re
import subprocess
from typing import Dict, Set
from urllib.parse import urlparse

import dns.resolver

from .active_check import ActiveChecker
from .utils import clean_subdomain, get_logger, make_session, run_named_parallel, run_parallel

log = get_logger()


class PassiveDiscovery:
    """
    Descubrimiento pasivo de activos (subdominios, DNS, WHOIS) con verificación
    opcional de actividad (ICMP/TCP). Las fuentes se consultan en paralelo.
    """

    def __init__(self, domain: str, threads: int = 20, timeout: int = 20):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.subdomains: Set[str] = set()
        # Mapa subdominio -> conjunto de fuentes que lo reportaron (para el informe)
        self.sources: Dict[str, Set[str]] = {}
        self.dns_records: Dict = {}
        self.session = make_session()

    # ------------------------------------------------------------
    # Helper interno: registrar subdominios encontrados por una fuente
    # ------------------------------------------------------------
    def _add(self, raw: str, source: str) -> None:
        sub = clean_subdomain(raw, self.domain)
        if not sub or sub == self.domain:
            return
        self.subdomains.add(sub)
        self.sources.setdefault(sub, set()).add(source)

    # ------------------------------------------------------------
    # 1. crt.sh - Certificate Transparency
    # ------------------------------------------------------------
    def query_crtsh(self) -> int:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                log.debug(f"    [!] crt.sh HTTP {r.status_code}")
                return 0
            data = r.json()
            count = 0
            for entry in data:
                names = []
                for field in ("name_value", "common_name"):
                    val = entry.get(field, "")
                    if val:
                        names.extend(val.split("\n"))
                for name in names:
                    before = len(self.subdomains)
                    self._add(name, "crt.sh")
                    count += len(self.subdomains) - before
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en crt.sh: {e}")
            return 0

    # ------------------------------------------------------------
    # 2. certspotter (sslmate) - Certificate Transparency
    # ------------------------------------------------------------
    def query_certspotter(self) -> int:
        url = (
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
            "&include_subdomains=true&expand=dns_names"
        )
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return 0
            count = 0
            for cert in r.json():
                for name in cert.get("dns_names", []):
                    self._add(name, "certspotter")
                    count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en certspotter: {e}")
            return 0

    # ------------------------------------------------------------
    # 3. HackerTarget - hostsearch
    # ------------------------------------------------------------
    def query_hackertarget(self) -> int:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200 or "API count exceeded" in r.text or "error" in r.text.lower():
                return 0
            count = 0
            for line in r.text.splitlines():
                host = line.split(",")[0]
                self._add(host, "hackertarget")
                count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en hackertarget: {e}")
            return 0

    # ------------------------------------------------------------
    # 4. RapidDNS
    # ------------------------------------------------------------
    def query_rapiddns(self) -> int:
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return 0
            count = 0
            for sub in re.findall(r"[A-Za-z0-9_.-]+\." + re.escape(self.domain), r.text):
                self._add(sub, "rapiddns")
                count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en rapiddns: {e}")
            return 0

    # ------------------------------------------------------------
    # 5. Anubis (jldc.me)
    # ------------------------------------------------------------
    def query_anubis(self) -> int:
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return 0
            count = 0
            for sub in r.json():
                self._add(sub, "anubis")
                count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en anubis: {e}")
            return 0

    # ------------------------------------------------------------
    # 6. AlienVault OTX - passive DNS (sin clave)
    # ------------------------------------------------------------
    def query_otx(self) -> int:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return 0
            count = 0
            for record in r.json().get("passive_dns", []):
                self._add(record.get("hostname", ""), "otx")
                count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en otx: {e}")
            return 0

    # ------------------------------------------------------------
    # 7. Wayback Machine (web.archive.org)
    # ------------------------------------------------------------
    def query_wayback(self) -> int:
        url = (
            "https://web.archive.org/cdx/search/cdx?"
            f"url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"
        )
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return 0
            rows = r.json()
            count = 0
            for row in rows[1:]:  # primera fila = cabecera
                if not row:
                    continue
                host = urlparse(row[0]).netloc
                self._add(host, "wayback")
                count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en wayback: {e}")
            return 0

    # ------------------------------------------------------------
    # 8. DNSdumpster (endpoint clásico; tolerante a fallos)
    # ------------------------------------------------------------
    def query_dnsdumpster(self) -> int:
        url = "https://dnsdumpster.com/"
        try:
            r = self.session.get(url, timeout=self.timeout)
            csrf = self.session.cookies.get("csrftoken")
            if not csrf:
                m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
                csrf = m.group(1) if m else None
            if not csrf:
                return 0
            data = {"csrfmiddlewaretoken": csrf, "targetip": self.domain, "user": "free"}
            resp = self.session.post(url, data=data, headers={"Referer": url}, timeout=self.timeout)
            count = 0
            for sub in re.findall(r"[A-Za-z0-9_.-]+\." + re.escape(self.domain), resp.text):
                self._add(sub, "dnsdumpster")
                count += 1
            return count
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en dnsdumpster: {e}")
            return 0

    # ------------------------------------------------------------
    # 9. Subfinder (CLI, pasivo)
    # ------------------------------------------------------------
    def query_subfinder(self) -> int:
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent", "-all", "-timeout", "20"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            count = 0
            for line in result.stdout.splitlines():
                if line.strip():
                    self._add(line, "subfinder")
                    count += 1
            return count
        except FileNotFoundError:
            log.debug("    [!] Subfinder no instalado (opcional).")
            return 0
        except subprocess.TimeoutExpired:
            log.debug("    [!] Subfinder timeout.")
            return 0
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en subfinder: {e}")
            return 0

    # ------------------------------------------------------------
    # Ejecutar todas las fuentes de subdominios en paralelo
    # ------------------------------------------------------------
    def discover_subdomains(self) -> None:
        sources = {
            "crt.sh": self.query_crtsh,
            "certspotter": self.query_certspotter,
            "hackertarget": self.query_hackertarget,
            "rapiddns": self.query_rapiddns,
            "anubis": self.query_anubis,
            "otx": self.query_otx,
            "wayback": self.query_wayback,
            "dnsdumpster": self.query_dnsdumpster,
            "subfinder": self.query_subfinder,
        }
        log.info(f"[*] Consultando {len(sources)} fuentes de subdominios en paralelo...")
        counts = run_named_parallel(
            {name: fn for name, fn in sources.items()}, max_workers=len(sources)
        )
        for name, count in counts.items():
            if isinstance(count, dict):  # error capturado
                log.info(f"    [!] {name}: error")
            else:
                log.info(f"    [+] {name}: {count} hallazgos")
        log.info(f"    [=] Subdominios únicos tras combinar fuentes: {len(self.subdomains)}")

    # ------------------------------------------------------------
    # Consulta de registros DNS (tipos en paralelo)
    # ------------------------------------------------------------
    def query_dns_records(self) -> Dict:
        log.info(f"[*] Consultando registros DNS de {self.domain}")
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]

        def _resolve(rtype):
            # Resolver propio por hilo (dnspython no garantiza thread-safety al compartir)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            try:
                answers = resolver.resolve(self.domain, rtype)
                return [str(r) for r in answers]
            except Exception:  # noqa: BLE001
                return []

        for rtype, values in run_parallel(_resolve, record_types, max_workers=7):
            self.dns_records[rtype] = values
            if values:
                log.info(f"    [+] {rtype}: {len(values)} registros")
        return self.dns_records

    # ------------------------------------------------------------
    # WHOIS
    # ------------------------------------------------------------
    def query_whois(self) -> Dict:
        log.info(f"[*] Consultando WHOIS de {self.domain}")
        try:
            import whois  # import local: librería opcional

            w = whois.whois(self.domain)
            return {
                "registrar": str(w.registrar) if w.registrar else "No disponible",
                "creation_date": str(w.creation_date) if w.creation_date else "No disponible",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "No disponible",
                "name_servers": sorted(set(w.name_servers)) if w.name_servers else [],
                "emails": w.emails if getattr(w, "emails", None) else [],
            }
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error en WHOIS: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------
    # Añadir subdominios desde fuentes externas (ej. threat_intel)
    # ------------------------------------------------------------
    def add_subdomains_from_list(self, new_subdomains: list, source: str = "external") -> None:
        if not new_subdomains:
            return
        for sub in new_subdomains:
            self._add(sub, source)

    # ------------------------------------------------------------
    # Flujo completo de descubrimiento
    # ------------------------------------------------------------
    def run_all(self, verificar_actividad: bool = True, active_ports=(80, 443)) -> Dict:
        # Subdominios (paralelo) y, a la vez, DNS + WHOIS
        meta = run_named_parallel(
            {
                "subdomains": self.discover_subdomains,
                "dns": self.query_dns_records,
                "whois": self.query_whois,
            },
            max_workers=3,
        )
        whois_data = meta.get("whois", {})
        if isinstance(whois_data, dict) and whois_data.get("status") == "error":
            whois_data = {"error": whois_data.get("message", "desconocido")}

        # Verificación de actividad (ICMP + TCP) concurrente
        activos_info = {}
        if verificar_actividad and self.subdomains:
            checker = ActiveChecker(threads=self.threads)
            hosts = sorted(self.subdomains) + [self.domain]
            resultados = checker.check_multiple_hosts(hosts, ports=active_ports)
            resumen = checker.generar_resumen(resultados)

            log.info(
                f"    [=] Activos: {resumen['activos']}/{resumen['total_hosts']} "
                f"(ICMP: {resumen['detectados_por_icmp']}, TCP: {resumen['detectados_por_tcp']})"
            )
            activos_info = {"resumen": resumen, "resultados_detallados": resultados}

        return {
            "domain": self.domain,
            "subdomains": sorted(self.subdomains),
            "total_subdomains": len(self.subdomains),
            "subdomain_sources": {k: sorted(v) for k, v in self.sources.items()},
            "dns_records": self.dns_records,
            "whois": whois_data,
            "activos": activos_info,
        }
