#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de integración con la plataforma SOCRadar (platform.socradar.com).

Aporta inteligencia de SOCRadar a la herramienta, priorizando lo que la cuenta
FREEMIUM puede usar SIN gastar créditos (verificado en vivo contra la API):

  ENDPOINTS GRATIS (estándar, ligados a tu company_id — 0 créditos):
    · License Overview      → plan, caducidad y SALDO de créditos.
    · ASM Digital Footprint → activos descubiertos de la empresa (dominios,
                              webs, IPs, registros DNS, tecnologías). ← lo más
                              valioso para "búsqueda de activos del dominio".
    · ASM Vulnerabilities   → vulnerabilidades de los activos.
    · Dark Web Monitoring   → hallazgos de dark web ligados a la company.
    · Incidents             → incidentes/alarmas abiertos.

  ENDPOINTS DE PAGO (consumen créditos — solo si spend_credits=True):
    · Identity Intelligence → credenciales/identidades filtradas (1 créd./req).
    · IoC Enrichment        → enriquecimiento de IOCs (1 créd./req).

NOTAS IMPORTANTES sobre la cuenta freemium:
  - La cuenta está ATADA a una empresa (company_id). ASM/Dark Web devuelven los
    activos de ESA empresa (p. ej. Zunder), no de un dominio arbitrario. Si se
    escanea otro dominio, estos datos siguen siendo los de la company licenciada.
  - Los créditos de "dark_web" en freemium suelen ser 0 → la API global
    'CTI Dark Web News' (/darkweb/news) NO está disponible; se usa en su lugar el
    Dark Web Monitoring ligado a la company, que SÍ es gratis.

Autenticación: header `api-key` (la mayoría) o `X-API-Key` (Source Code Leakage).
Rate limit: 1 request/segundo → se respeta con un throttle interno.
"""

import json
import os
import time
from typing import Dict, List, Optional

from .utils import get_logger, make_session

log = get_logger()

API_BASE = "https://platform.socradar.com/api"

# Tipos de activo ASM que nos interesa resaltar como "superficie de ataque".
_ASSET_INTEREST = ("Domain", "Subdomain", "Website", "IP", "DNS Record", "Cloud Bucket")


class SocRadar:
    """
    Cliente de la API de SOCRadar para una empresa (company_id) concreta.

    Cada método devuelve un dict con la clave `status`:
      ok | no_api_key | no_credits | invalid_key | error | skipped
    de forma que el resto de la herramienta (diagnóstico, informe) lo trate igual
    que cualquier otra API.
    """

    def __init__(self, domain: str, company_id: str = "", api_key: str = "",
                 cache_dir: Optional[str] = None):
        self.domain = domain
        self.company_id = (company_id or os.getenv("SOCRADAR_COMPANY_ID", "")).strip()
        self.api_key = (api_key or os.getenv("SOCRADAR_API_KEY", "")).strip()
        # Las APIs AVANZADAS (de pago, por créditos) requieren una API Key ADICIONAL
        # distinta de la estándar (Settings → API Options en la plataforma). Si no se
        # configura, se reintenta con la estándar (que normalmente devolverá 402).
        self.advanced_api_key = (os.getenv("SOCRADAR_ADVANCED_API_KEY", "") or self.api_key).strip()
        self.session = make_session()
        self.cache_dir = cache_dir
        # Throttle: garantiza ≥1s entre peticiones (rate limit de SOCRadar).
        self._last_call = 0.0
        # Contador de créditos gastados en esta ejecución (estimado).
        self.credits_spent = 0

    # ── helpers ──────────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self.api_key and self.company_id)

    def _headers(self, key_header: str = "api-key") -> Dict[str, str]:
        return {key_header: self.api_key, "Accept": "application/json"}

    def _throttle(self) -> None:
        """Respeta el límite de 1 req/s de SOCRadar."""
        delta = time.time() - self._last_call
        if delta < 1.05:
            time.sleep(1.05 - delta)
        self._last_call = time.time()

    def _get(self, path: str, params: Optional[Dict] = None,
             key_header: str = "api-key", timeout: int = 30) -> Dict:
        """
        GET genérico que normaliza errores a un dict {status, ...}.
        Devuelve {"status": "ok", "json": <payload>} si todo va bien.
        """
        self._throttle()
        url = f"{API_BASE}{path}"
        try:
            r = self.session.get(url, headers=self._headers(key_header),
                                 params=params or {}, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

        if r.status_code == 200:
            try:
                return {"status": "ok", "json": r.json()}
            except ValueError:
                return {"status": "error", "message": "respuesta no-JSON de SOCRadar"}
        if r.status_code in (401, 403):
            # 403 también aparece cuando el plan/módulo no cubre el endpoint o no
            # quedan créditos: lo señalamos como tal para el diagnóstico.
            body = (r.text or "").lower()
            if "credit" in body or r.status_code == 402:
                return {"status": "no_credits", "message": "Sin créditos o módulo no cubierto."}
            return {"status": "invalid_key",
                    "message": f"HTTP {r.status_code}: clave inválida o sin permiso para este endpoint."}
        if r.status_code == 402:
            # Las APIs avanzadas exigen una API Key adicional (de pago/créditos).
            return {"status": "advanced_key_required",
                    "message": "HTTP 402: requiere la Advanced API Key de SOCRadar "
                               "(genérala en Settings → API Options y ponla en "
                               "SOCRADAR_ADVANCED_API_KEY)."}
        if r.status_code == 429:
            return {"status": "error", "error_type": "quota_exceeded",
                    "message": "Rate limit de SOCRadar superado (espera y reintenta)."}
        return {"status": "error", "message": f"HTTP {r.status_code}", "code": r.status_code}

    # ── cache simple en disco (solo para llamadas que cuestan créditos) ────────

    def _cache_path(self, name: str) -> Optional[str]:
        if not self.cache_dir:
            return None
        os.makedirs(self.cache_dir, exist_ok=True)
        safe = name.replace("/", "_").replace(":", "_")
        return os.path.join(self.cache_dir, f"socradar_{self.company_id}_{safe}.json")

    def _cache_get(self, name: str, ttl_hours: int = 24) -> Optional[Dict]:
        path = self._cache_path(name)
        if not path or not os.path.exists(path):
            return None
        try:
            age = time.time() - os.path.getmtime(path)
            if age > ttl_hours * 3600:
                return None
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            data["_cached"] = True
            return data
        except Exception:  # noqa: BLE001
            return None

    def _cache_put(self, name: str, data: Dict) -> None:
        path = self._cache_path(name)
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except Exception:  # noqa: BLE001
            pass

    # ── 0) License overview (GRATIS) ───────────────────────────────────────────

    def get_license_overview(self) -> Dict:
        """Plan, caducidad y saldo de créditos. Cuesta 0 créditos."""
        if not self.is_configured():
            return {"status": "no_api_key",
                    "message": "Configura SOCRADAR_API_KEY y SOCRADAR_COMPANY_ID en .env"}
        print("[*] SOCRadar: License Overview (créditos y plan)...")
        res = self._get(f"/company/{self.company_id}/license/overview")
        if res["status"] != "ok":
            return res
        d = res["json"].get("data", {})
        sub = d.get("subscription", {})
        ti = d.get("credits", {}).get("threat_intelligence_credits", {})
        return {
            "status": "ok",
            "company_name": d.get("company_info", {}).get("name", ""),
            "plan": sub.get("plan", ""),
            "subscription_status": sub.get("status", ""),
            "expire_date": sub.get("expire_date", ""),
            "days_remaining": sub.get("days_remaining", 0),
            "credits": ti,
            "features": d.get("features_and_permissions", {}),
        }

    # ── 1) ASM Digital Footprint (GRATIS) — activos de la empresa ──────────────

    def get_asm_assets(self, max_pages: int = 0) -> Dict:
        """
        Activos descubiertos por SOCRadar (dominios, webs, IPs, DNS, tecnologías).
        Pagina la API; max_pages=0 → todas las páginas. Cuesta 0 créditos.
        """
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        print("[*] SOCRadar: ASM Digital Footprint (activos)...")
        records: List[Dict] = []
        page = 1
        total_count = 0
        total_pages = 1
        while True:
            res = self._get(f"/company/{self.company_id}/asm/v2", params={"page": page})
            if res["status"] != "ok":
                # Si ya tenemos algo de páginas previas, devolvemos lo logrado.
                if records:
                    break
                return res
            data = res["json"].get("data", {}) or {}
            pag = data.get("pagination", {})
            total_count = pag.get("total_count", total_count)
            total_pages = pag.get("total_pages", total_pages)
            for rec in data.get("records", []):
                asset = rec.get("asset", rec)
                records.append({
                    "name": asset.get("assetName", ""),
                    "type": asset.get("assetType", ""),
                    "source": asset.get("source", ""),
                    "channel": asset.get("channel", ""),
                    "discovered": asset.get("discoveryDate", ""),
                    "monitored": asset.get("isMonitor", False),
                    "false_positive": asset.get("isFalsePositive", False),
                    "tags": asset.get("tags", []),
                })
            if page >= total_pages or (max_pages and page >= max_pages):
                break
            page += 1

        # Agregaciones útiles para el informe.
        by_type: Dict[str, int] = {}
        for r in records:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1

        def _of(types):
            return sorted({r["name"] for r in records
                           if r["type"] in types and r["name"] and not r["false_positive"]})

        return {
            "status": "ok",
            "total": total_count or len(records),
            "fetched": len(records),
            "pages_fetched": page,
            "total_pages": total_pages,
            "by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
            "domains": _of(("Domain", "Subdomain")),
            "ips": _of(("IP",)),
            "websites": _of(("Website",)),
            "technologies": _of(("Technology",)),
            "records": records,
        }

    # ── 2) ASM Vulnerabilities (GRATIS) ────────────────────────────────────────

    def get_asm_vulnerabilities(self) -> Dict:
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        print("[*] SOCRadar: ASM Vulnerabilities...")
        res = self._get(f"/company/{self.company_id}/vulnerabilities/v2/latest")
        if res["status"] != "ok":
            return res
        data = res["json"].get("data", {}) or {}
        records = data.get("records", [])
        return {
            "status": "ok",
            "total": data.get("pagination", {}).get("total_count", len(records)),
            "records": records[:50],
        }

    # ── 3) Dark Web Monitoring (GRATIS, ligado a la company) ───────────────────

    def get_dark_web_monitoring(self) -> Dict:
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        print("[*] SOCRadar: Dark Web Monitoring (company)...")
        res = self._get(f"/company/{self.company_id}/dark-web-monitoring/v2")
        if res["status"] != "ok":
            return res
        data = res["json"].get("data")
        findings: List[Dict] = []
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("records") or data.get("results") or []
        return {"status": "ok", "total": len(findings), "findings": findings[:50]}

    # ── 3b) Surface Web Monitoring (GRATIS) ────────────────────────────────────

    def get_surface_web_monitoring(self) -> Dict:
        """Menciones de la marca en la web de superficie (pastes, foros clear…)."""
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        print("[*] SOCRadar: Surface Web Monitoring...")
        res = self._get(f"/company/{self.company_id}/surface_web_monitoring/v2")
        if res["status"] != "ok":
            return res
        data = res["json"].get("data", {}) or {}
        items = data.get("data", []) if isinstance(data, dict) else (data or [])
        total = data.get("total_data_count", len(items)) if isinstance(data, dict) else len(items)
        return {"status": "ok", "total": total, "findings": items[:50]}

    # ── 3c) VIP Protection (GRATIS) ────────────────────────────────────────────

    def get_vip_protection(self) -> Dict:
        """Exposición de VIPs/ejecutivos de la empresa."""
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        print("[*] SOCRadar: VIP Protection...")
        res = self._get(f"/company/{self.company_id}/vip-protection/v2")
        if res["status"] != "ok":
            return res
        data = res["json"].get("data", {}) or {}
        items = data.get("data", []) if isinstance(data, dict) else (data or [])
        total = data.get("total_data_count", len(items)) if isinstance(data, dict) else len(items)
        return {"status": "ok", "total": total, "findings": items[:50]}

    # ── 4) Incidents (GRATIS) ──────────────────────────────────────────────────

    def get_incidents(self) -> Dict:
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        print("[*] SOCRadar: Incidents v4...")
        res = self._get(f"/company/{self.company_id}/incidents/v4")
        if res["status"] != "ok":
            return res
        data = res["json"].get("data")
        incidents = data if isinstance(data, list) else (data or {}).get("records", [])
        return {"status": "ok", "total": len(incidents), "incidents": incidents[:50]}

    # ── 5) Identity Intelligence (DE PAGO: 1 crédito/req) ──────────────────────

    def query_identity_intelligence(self, target: str) -> Dict:
        """Credenciales/identidades filtradas. CONSUME 1 crédito. Cacheado 24h."""
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        cached = self._cache_get(f"identity_{target}")
        if cached:
            print(f"[*] SOCRadar: Identity Intelligence ({target}) [caché, 0 créditos]")
            return cached
        print(f"[*] SOCRadar: Identity Intelligence ({target}) [consume 1 crédito]...")
        self._throttle()
        try:
            r = self.session.get(f"{API_BASE}/identity/intelligence/query",
                                 headers={"api-key": self.advanced_api_key, "Accept": "application/json"},
                                 params={"value": target}, timeout=30)
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}
        if r.status_code == 402:
            return {"status": "advanced_key_required",
                    "message": "Requiere la Advanced API Key (SOCRADAR_ADVANCED_API_KEY)."}
        if r.status_code != 200:
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        res = {"status": "ok", "json": r.json()}
        self.credits_spent += 1
        data = res["json"].get("data", {})
        out = {"status": "ok", "target": target, "data": data}
        self._cache_put(f"identity_{target}", out)
        return out

    # ── 6) IoC Enrichment (DE PAGO: 1 crédito/req) ─────────────────────────────

    def enrich_ioc(self, indicator: str) -> Dict:
        """Enriquece un IOC. CONSUME 1 crédito. Cacheado 24h."""
        if not self.is_configured():
            return {"status": "no_api_key", "message": "Configura SOCRadar en .env"}
        cached = self._cache_get(f"ioc_{indicator}")
        if cached:
            return cached
        print(f"[*] SOCRadar: IoC Enrichment ({indicator}) [consume 1 crédito]...")
        self._throttle()
        url = f"{API_BASE}/ioc_enrichment/get/indicator_details"
        try:
            r = self.session.post(url, headers={"api-key": self.advanced_api_key,
                                                "Accept": "application/json"},
                                  json={"indicator": indicator}, timeout=30)
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}
        if r.status_code != 200:
            if r.status_code == 402:
                return {"status": "advanced_key_required",
                        "message": "Requiere la Advanced API Key (SOCRADAR_ADVANCED_API_KEY)."}
            if r.status_code == 403:
                return {"status": "no_credits", "message": f"HTTP {r.status_code}"}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        self.credits_spent += 1
        try:
            data = r.json().get("data", {})
        except ValueError:
            data = {}
        out = {"status": "ok", "indicator": indicator, "data": data}
        self._cache_put(f"ioc_{indicator}", out)
        return out

    # ── orquestación ───────────────────────────────────────────────────────────

    def run_all(self, spend_credits: bool = False, asm_max_pages: int = 0,
                identity_targets: Optional[List[str]] = None,
                max_credits: int = 10) -> Dict:
        """
        Ejecuta la inteligencia de SOCRadar.

        Por defecto SOLO usa endpoints gratis (0 créditos). Si spend_credits=True,
        consulta además Identity Intelligence para los `identity_targets` indicados
        (dominio + emails), respetando un tope de `max_credits` créditos.
        """
        if not self.is_configured():
            return {"status": "no_api_key",
                    "message": "Configura SOCRADAR_API_KEY y SOCRADAR_COMPANY_ID en .env"}

        out: Dict = {"status": "success", "company_id": self.company_id}

        overview = self.get_license_overview()
        out["overview"] = overview
        if overview.get("status") == "invalid_key":
            return {"status": "error", "message": overview.get("message"),
                    "overview": overview}

        # Endpoints gratis (secuencial: el throttle ya garantiza 1 req/s).
        out["asm"] = self.get_asm_assets(max_pages=asm_max_pages)
        out["vulnerabilities"] = self.get_asm_vulnerabilities()
        out["dark_web"] = self.get_dark_web_monitoring()
        out["surface_web"] = self.get_surface_web_monitoring()
        out["vip_protection"] = self.get_vip_protection()
        out["incidents"] = self.get_incidents()

        # Endpoints de pago (opt-in explícito, con tope de créditos).
        if spend_credits and identity_targets:
            avail = overview.get("credits", {}).get("identity_intelligence", 0)
            budget = min(max_credits, avail or 0)
            id_results = []
            for tgt in identity_targets:
                if self.credits_spent >= budget:
                    log.info(f"   [i] SOCRadar: alcanzado tope de {budget} crédito(s); "
                             f"se omiten {len(identity_targets) - len(id_results)} consulta(s).")
                    break
                r = self.query_identity_intelligence(tgt)
                id_results.append(r)
                # Si falta la Advanced API Key, no tiene sentido seguir intentando.
                if r.get("status") == "advanced_key_required":
                    log.info("   [i] SOCRadar: Identity Intelligence requiere la Advanced "
                             "API Key (SOCRADAR_ADVANCED_API_KEY). Se omite el resto.")
                    break
            out["identity_intelligence"] = {"status": "ok", "results": id_results}

        out["credits_spent"] = self.credits_spent
        out["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return out
