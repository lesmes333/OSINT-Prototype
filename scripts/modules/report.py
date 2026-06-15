#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de generación de informes - JSON, CSV y Markdown.
Convierte los resultados del descubrimiento y threat intelligence en tres formatos:
- JSON: datos completos y estructurados (para reutilización programática)
- CSV: solo lista de subdominios (fácil de importar a Excel)
- Markdown: informe legible para humanos, con tablas y secciones.
"""

import json
import csv
from datetime import datetime
from typing import Dict, List

# Plantilla HTML autocontenida (CSS embebido, tema oscuro, sin dependencias externas)
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe OSINT - {domain}</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--border:#2d3543;--txt:#e6edf3;--muted:#8b949e;--accent:#58a6ff;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
header{{background:linear-gradient(135deg,#1f6feb22,#a371f722);border:1px solid var(--border);border-radius:14px;padding:24px;margin-bottom:24px}}
header h1{{margin:0 0 4px;font-size:26px}}
header .sub{{color:var(--muted);font-size:14px}}
header .meta{{margin-top:10px;font-size:13px;color:var(--muted)}}
header .meta b{{color:var(--txt)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;text-align:center}}
.card .num{{font-size:28px;font-weight:700}}
.card .lbl{{color:var(--muted);font-size:12px;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
.card.blue .num{{color:#58a6ff}}.card.green .num{{color:#3fb950}}.card.cyan .num{{color:#39c5cf}}
.card.violet .num{{color:#a371f7}}.card.red .num{{color:#f85149}}.card.orange .num{{color:#db8e3c}}
.card.yellow .num{{color:#d4a72c}}.card.gray .num{{color:#8b949e}}
section{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:20px}}
section h2{{margin:0 0 14px;font-size:19px;border-bottom:1px solid var(--border);padding-bottom:8px}}
section h3{{font-size:15px;color:var(--muted);margin:18px 0 8px}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
th{{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
tbody tr:hover{{background:var(--panel2)}}
code{{background:#0b0f14;padding:1px 6px;border-radius:5px;font-size:12.5px;color:#79c0ff}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.muted{{color:var(--muted)}}
.badge{{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}}
.badge.crit{{background:#f8514922;color:#ff7b72;border:1px solid #f8514955}}
.badge.high{{background:#db6d2822;color:#e3914b;border:1px solid #db6d2855}}
.badge.med{{background:#d4a72c22;color:#e3c14b;border:1px solid #d4a72c55}}
.badge.low{{background:#3fb95022;color:#56d364;border:1px solid #3fb95055}}
.badge.unk{{background:#8b949e22;color:#b1bac4;border:1px solid #8b949e55}}
.alert{{background:#f8514915;border:1px solid #f85149;border-radius:12px;padding:16px 20px;margin-bottom:20px}}
.alert h3{{margin:0 0 8px;color:#ff7b72}}
.alert ul{{margin:0;padding-left:20px}}
.alert-inline{{color:#e3914b}}
footer{{text-align:center;color:var(--muted);font-size:12.5px;padding:20px 0}}
footer b{{color:var(--accent)}}
</style></head>
<body><div class="wrap">
<header>
  <h1>🔍 Informe OSINT — {domain}</h1>
  <div class="sub">OSINT Recon Suite · Reconocimiento pasivo de activos, tecnologías, vulnerabilidades y dark web</div>
  <div class="meta">🎯 <b>{domain}</b> &nbsp;·&nbsp; 📡 IP: <b>{ip}</b> &nbsp;·&nbsp; 🕐 {ts}</div>
</header>
<div class="cards">{cards}</div>
{alert}
{diag}
<section><h2>🌐 Subdominios ({sub_total})</h2>
<table><thead><tr><th>#</th><th>Subdominio</th><th>Estado</th><th>Fuentes</th></tr></thead><tbody>{sub_rows}</tbody></table></section>
<section><h2>🔍 Registros DNS</h2><table><tbody>{dns_rows}</tbody></table></section>
<section><h2>🏢 WHOIS</h2><table><tbody>{whois_rows}</tbody></table></section>
<section><h2>🧬 Tecnologías detectadas</h2><table><thead><tr><th>URL</th><th>Tecnologías</th></tr></thead><tbody>{tech_rows}</tbody></table></section>
{cve_section}
{ew_section}
{dw_section}
<footer>Generado por <b>OSINT Recon Suite</b> · Created by Cristian &amp; Luisber</footer>
</div></body></html>"""

class ReportGenerator:
    """
    Genera informes en tres formatos: JSON, CSV y Markdown.
    Los archivos se guardan en una carpeta (por defecto 'outputs').
    """

    def __init__(self, output_dir: str = "outputs", dominio: str = None):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dominio_slug = dominio.replace('.', '_') if dominio else "unknown"
        import os
        os.makedirs(output_dir, exist_ok=True)

    def to_json(self, data: Dict, filename: str = None) -> str:
        if filename is None:
            filename = f"{self.output_dir}/activos_{self.dominio_slug}_{self.timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"[✓] JSON guardado en: {filename}")
        return filename

    def to_csv(self, subdomains: List[str], filename: str = None, sources: Dict = None) -> str:
        if filename is None:
            filename = f"{self.output_dir}/subdominios_{self.dominio_slug}_{self.timestamp}.csv"
        sources = sources or {}
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['subdominio', 'fecha_deteccion', 'fuentes'])
            for sub in subdomains:
                fuentes = ",".join(sources.get(sub, [])) or "desconocida"
                writer.writerow([sub, self.timestamp, fuentes])
        print(f"[✓] CSV guardado en: {filename}")
        return filename

    def to_markdown(self, discovery_data: Dict, threat_data: Dict, diagnostics: Dict = None, filename: str = None) -> str:
        activos_info = discovery_data.get('activos', {})
        if filename is None:
            filename = f"{self.output_dir}/informe_{self.dominio_slug}_{self.timestamp}.md"

        # Contar APIs exitosas/fallidas
        apis_ok = 0
        apis_error = 0
        for key, value in threat_data.items():
            if isinstance(value, dict) and value.get('status') == 'ok':
                apis_ok += 1
            elif isinstance(value, dict) and value.get('status') in ['error', 'no_api_key']:
                apis_error += 1

        md_content = f"""# Informe OSINT - {discovery_data.get('domain', 'N/D')}

**Fecha de generación:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Dominio analizado:** {discovery_data.get('domain', 'N/D')}
**IP resuelta:** {threat_data.get('ip_address', 'N/D')}

---

## Resumen Ejecutivo

| Indicador | Valor |
|-----------|-------|
| Subdominios únicos detectados | {discovery_data.get('total_subdomains', 0)} |
| Tipos de registros DNS consultados | {len(discovery_data.get('dns_records', {}))} |
| APIs consultadas (exitosas/fallidas) | {apis_ok}/{apis_ok + apis_error} |

---
"""
        # ========== SECCIÓN: DIAGNÓSTICO (claves/herramientas) ==========
        if diagnostics:
            keys_to_fix = diagnostics.get('keys_to_fix', [])
            md_content += "\n## 🩺 Diagnóstico del escaneo\n\n"
            if keys_to_fix:
                md_content += "> 🔑 **Acción requerida — claves a renovar/actualizar en `.env`:**\n>\n"
                for a in keys_to_fix:
                    md_content += f"> - **{a['name']}** ({a['label']}): {a['action']}\n"
                md_content += "\n"
            md_content += "**APIs de Threat Intelligence**\n\n"
            md_content += "| API | Estado | Acción recomendada |\n|-----|--------|--------------------|\n"
            status_icon = {"ok": "✅ OK", "no_api_key": "⚪ Sin clave",
                           "invalid_key": "❌ Inválida/caducada", "quota_exceeded": "⏳ Cuota agotada",
                           "error": "⚠️ Error"}
            for a in diagnostics.get('apis', []):
                md_content += f"| {a['name']} | {status_icon.get(a['status'], a['status'])} | {a['action'] or '—'} |\n"
            md_content += "\n**Herramientas externas**\n\n"
            md_content += "| Herramienta | Estado | Aporta | Cómo solucionarlo |\n|-------------|--------|--------|-------------------|\n"
            for t in diagnostics.get('tools', []):
                est = "✅ Disponible" if t['ok'] else "⚠️ No disponible"
                fix = "" if t['ok'] else t['fix']
                md_content += f"| {t['tool']} | {est} | {t['impact']} | {fix} |\n"
            md_content += "\n---\n"

        md_content += f"""
## 📋 Inventario de Subdominios ({discovery_data.get('total_subdomains', 0)})

| # | Subdominio | Estado | Fuentes |
|---|------------|--------|---------|
"""
        _src_map = discovery_data.get('subdomain_sources', {})
        _estado_map = {r.get('host'): r for r in activos_info.get('resultados_detallados', [])}
        for i, sub in enumerate(discovery_data.get('subdomains', [])[:60], 1):
            est = _estado_map.get(sub, {})
            estado_txt = "🟢 activo" if est.get('estado') == 'ACTIVA' else ("🔴 inactivo" if est.get('estado') else "—")
            fuentes = ", ".join(_src_map.get(sub, [])) or "—"
            md_content += f"| {i} | `{sub}` | {estado_txt} | {fuentes} |\n"

        # ========== SECCIÓN: VERIFICACIÓN DE ACTIVIDAD ==========
        md_content += f"""
---

## 🟢 Verificación de Actividad de Máquinas

**Metodología:**
1. ICMP (ping) - Envío de Echo Request, espera Echo Reply (ICMP-0)
2. TCP/80 - Si ICMP falla, intento de conexión SYN/SYN+ACK

### Resumen de actividad

| Indicador | Valor |
|-----------|-------|
| Total hosts analizados | {activos_info.get('resumen', {}).get('total_hosts', 0)} |
| Hosts **ACTIVOS** | {activos_info.get('resumen', {}).get('activos', 0)} |
| Hosts NO ACTIVOS | {activos_info.get('resumen', {}).get('no_activos', 0)} |
| Detectados por ICMP | {activos_info.get('resumen', {}).get('detectados_por_icmp', 0)} |
| Detectados por TCP | {activos_info.get('resumen', {}).get('detectados_por_tcp', 0)} |

### Resultados detallados

| Host | Estado | Método de detección |
|------|--------|---------------------|
"""
        for item in activos_info.get('resultados_detallados', []):
            host = item.get('host', 'N/A')
            estado = item.get('estado', 'N/A')
            metodo = item.get('metodo_deteccion', 'N/A')
            if estado == "ACTIVA":
                md_content += f"| `{host}` | ✅ ACTIVA | {metodo} |\n"
            else:
                md_content += f"| `{host}` | ❌ {estado} | {metodo} |\n"

        # ========== SECCIÓN: REGISTROS DNS ==========
        md_content += f"""
---

## 🔍 Registros DNS Detectados

| Tipo | Valores |
|------|---------|
"""
        for record_type, values in discovery_data.get('dns_records', {}).items():
            if values:
                md_content += f"| {record_type} | `{', '.join(values[:5])}` |\n"
            else:
                md_content += f"| {record_type} | *No encontrados* |\n"

        # ========== SECCIÓN: WHOIS ==========
        md_content += f"""
---

## 🏢 Información WHOIS

| Campo | Valor |
|-------|-------|
| Registrador | {discovery_data.get('whois', {}).get('registrar', 'N/D')} |
| Fecha de creación | {discovery_data.get('whois', {}).get('creation_date', 'N/D')} |
| Fecha de expiración | {discovery_data.get('whois', {}).get('expiration_date', 'N/D')} |
| Servidores DNS | {', '.join(discovery_data.get('whois', {}).get('name_servers', []))} |

---

## 📊 Estado de las APIs consultadas

| API | Estado | Motivo |
|-----|--------|--------|
"""
        # Lista de APIs a mostrar (clave en threat_data, nombre legible)
        api_list = [
            ('virustotal', 'VirusTotal'),
            ('shodan', 'Shodan'),
            ('censys', 'Censys'),
            ('alienvault', 'AlienVault OTX'),
            ('ipinfo', 'IPinfo'),
            ('ipdata', 'IPdata'),
            ('hunter', 'Hunter.io'),
            ('urlscan', 'urlscan.io'),
            ('abuseipdb', 'AbuseIPDB'),
            ('github', 'GitHub'),
            ('gitlab', 'GitLab')
        ]
        for key, name in api_list:
            api_data = threat_data.get(key, {})
            status = api_data.get('status', 'unknown')
            if status == 'ok':
                md_content += f"| {name} | ✅ Éxito | - |\n"
            elif status == 'no_api_key':
                md_content += f"| {name} | ⚠️ Sin clave | Configurar en .env |\n"
            elif status == 'error':
                error_type = api_data.get('error_type', 'unknown')
                message = api_data.get('message', 'Error desconocido')
                if error_type == 'invalid_key':
                    md_content += f"| {name} | ❌ Clave inválida | {message} |\n"
                elif error_type == 'quota_exceeded':
                    md_content += f"| {name} | ❌ Cuota agotada | {message} |\n"
                else:
                    md_content += f"| {name} | ❌ Error | {message[:80]} |\n"
            else:
                md_content += f"| {name} | ❓ Desconocido | - |\n"

        # ========== SECCIÓN: THREAT INTELLIGENCE (detalle por API) ==========
        md_content += f"""

## 🛡️ Threat Intelligence - Detalle por API

### VirusTotal
"""
        vt = threat_data.get('virustotal', {})
        if vt.get('status') == 'ok':
            md_content += f"""
- **Reputación:** {vt.get('reputation', 'N/D')}
- **Estadísticas:** {vt.get('last_analysis_stats', {})}
- **Subdominios adicionales:** {len(vt.get('subdomains', []))}
"""
        else:
            md_content += f"- {vt.get('message', 'No disponible')}\n"

        md_content += f"""
### Shodan
"""
        sh = threat_data.get('shodan', {})
        if sh.get('status') == 'ok':
            md_content += f"""
- **Puertos abiertos:** {sh.get('ports', [])}
- **Vulnerabilidades históricas:** {sh.get('vulnerabilities', [])}
- **Tags:** {sh.get('tags', [])}
"""
        else:
            md_content += f"- {sh.get('message', 'No disponible')}\n"

        md_content += f"""
### AlienVault OTX
"""
        av = threat_data.get('alienvault', {})
        if av.get('status') == 'ok':
            md_content += f"""
- **Pulses relacionados:** {av.get('pulse_count', 0)}
- **Reputación:** {av.get('reputation', 'N/A')}
"""
        else:
            md_content += f"- {av.get('message', 'No disponible')}\n"

        md_content += f"""
### Hunter.io
"""
        hu = threat_data.get('hunter', {})
        if hu.get('status') == 'ok':
            md_content += f"""
- **Correos encontrados:** {hu.get('total_emails', 0)}
"""
            for email in hu.get('emails', [])[:5]:
                md_content += f"  - `{email['value']}`\n"
        else:
            md_content += f"- {hu.get('message', 'No disponible')}\n"

        md_content += f"""
### GitHub y GitLab
"""
        gh = threat_data.get('github', {})
        gl = threat_data.get('gitlab', {})
        if gh.get('status') == 'ok':
            md_content += f"- **GitHub:** {gh.get('total_count', 0)} menciones\n"
        if gl.get('status') == 'ok':
            md_content += f"- **GitLab:** {gl.get('total_count', 0)} proyectos\n"

        # ==================== FINGERPRINTING ====================
        fp = threat_data.get('fingerprinting', {})
        md_content += f"""

## 🧬 Fingerprinting Tecnológico

"""
        if fp.get('status') == 'skipped':
            md_content += "⏩ Análisis de fingerprinting omitido por el usuario.\n"
        elif fp.get('status') == 'error':
            md_content += f"⚠️ **Error:** {fp.get('message', 'Desconocido')}\n"
        elif fp.get('results'):
            md_content += "Las siguientes tecnologías fueron detectadas en los subdominios activos:\n\n"
            md_content += "| URL | Tecnologías detectadas |\n"
            md_content += "|-----|------------------------|\n"

            tecnologias_por_url = {}
            for tech_item in fp.get('results', []):
                url = tech_item.get('url', 'N/A')
                tech_name = tech_item.get('technology', 'N/A')
                version = tech_item.get('version', '')
                if version and version != 'N/A':
                    tech_str = f"{tech_name} {version}".strip()
                else:
                    tech_str = tech_name
                if url not in tecnologias_por_url:
                    tecnologias_por_url[url] = []
                tecnologias_por_url[url].append(tech_str)

            for url, tecnologias in tecnologias_por_url.items():
                tecnologias_unicas = sorted(set(tecnologias))
                techs_str = ", ".join(tecnologias_unicas)
                md_content += f"| `{url[:60]}` | {techs_str} |\n"

            total_tech = fp.get('total_technologies', len(fp.get('results', [])))
            md_content += f"\n*Total de tecnologías detectadas: {total_tech}*\n"
        else:
            md_content += "No se detectaron tecnologías (o no se pudo realizar el análisis).\n"

        # ==================== VULNERABILIDADES ====================
        vuln = threat_data.get('vulnerabilities', {})
        md_content += f"""
        
## 🚨 Vulnerabilidades y Exploits

"""
        if vuln.get('status') == 'skipped':
            md_content += "⏩ Búsqueda de vulnerabilidades omitida por el usuario.\n"
        elif vuln.get('status') == 'error':
            md_content += f"⚠️ **Error:** {vuln.get('message', 'Desconocido')}\n"
        elif vuln.get('results'):
            md_content += "A continuación se listan las vulnerabilidades (CVE) asociadas a las tecnologías detectadas, junto con la disponibilidad de exploits públicos en Exploit-DB.\n\n"
            for tech_item in vuln.get('results', []):
                technology = tech_item.get('technology', 'Desconocida')
                version = tech_item.get('version', '')
                cves = tech_item.get('cves', [])
                if not cves:
                    continue
                md_content += f"#### Tecnología: `{technology} {version}`\n\n"
                md_content += "| CVE | Severidad | Descripción | Exploit público | INCIBE-CERT |\n"
                md_content += "|-----|-----------|-------------|-----------------|-------------|\n"
                for cve in cves:
                    cve_id = cve.get('id', 'N/A')
                    severity = cve.get('severity', 'N/A')
                    description = cve.get('description', '')[:80]
                    exploit_available = "✅ Sí" if cve.get('exploit_available') else "❌ No"
                    incibe = cve.get('incibe', {}) or {}
                    if incibe.get('url') and incibe.get('disponible'):
                        flag = " ⚠️ alerta temprana" if incibe.get('en_alerta_temprana') else ""
                        incibe_cell = f"[ficha]({incibe['url']}){flag}"
                    elif incibe.get('url'):
                        incibe_cell = f"[buscar]({incibe['url']})"
                    else:
                        incibe_cell = "-"
                    md_content += f"| `{cve_id}` | {severity} | {description} | {exploit_available} | {incibe_cell} |\n"
                md_content += "\n"
            total_cves = vuln.get('total_cves', 0)
            total_exploits = vuln.get('total_exploits', 0)
            incibe_refs = vuln.get('incibe_refs', 0)
            md_content += (
                f"\n*Total de CVEs: {total_cves} | Con exploits públicos: {total_exploits} | "
                f"Con ficha en INCIBE-CERT: {incibe_refs}*\n"
            )

            # Alerta temprana de INCIBE-CERT relacionada con las tecnologías detectadas
            early = vuln.get('incibe_early_warning', [])
            if early:
                md_content += "\n#### 🇪🇸 Alerta Temprana INCIBE-CERT (tecnologías detectadas)\n\n"
                md_content += "Vulnerabilidades recientes publicadas por INCIBE-CERT que mencionan las tecnologías detectadas:\n\n"
                md_content += "| CVE | Gravedad | CVSS | Fecha | Ficha |\n"
                md_content += "|-----|----------|------|-------|-------|\n"
                for ew in early[:20]:
                    md_content += (
                        f"| `{ew.get('cve', 'N/A')}` | {ew.get('gravedad_31') or ew.get('gravedad_40', 'N/A')} "
                        f"| {ew.get('cvss_31') or ew.get('cvss_40', 'N/A')} | {ew.get('fecha_publicacion', 'N/A')} "
                        f"| [ver]({ew.get('url', '')}) |\n"
                    )
        else:
            md_content += "No se encontraron vulnerabilidades asociadas (o no se pudo completar el análisis).\n"

        # ==================== DARK WEB ====================
        md_content += f"""
## 🛡️ Monitorización de Exposición y Filtraciones

"""
        dw = threat_data.get('darkweb', {})
        if dw.get('status') == 'error':
            md_content += f"⚠️ **Error:** {dw.get('message', 'Desconocido')}\n"
        elif dw.get('status') == 'skipped':
            md_content += "⏩ Monitorización de exposición omitida por el usuario.\n"
        elif dw.get('status') == 'success':
            summary = dw.get('summary', {})
            nivel = summary.get('nivel_exposicion', 'N/A')
            nivel_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(nivel, "⚪")
            md_content += f"- **Nivel de exposición:** {nivel_icon} **{nivel}**\n"
            md_content += f"- **Correos comprometidos:** {summary.get('emails_comprometidos', 0)}\n"
            md_content += f"- **Menciones en .onion (Capa 2):** {summary.get('menciones_onion', 0)}\n"
            md_content += f"- **Análisis URLScan histórico (Capa 3):** {summary.get('urlscan_historico', 0)}\n"
            md_content += f"- **Menciones en repos públicos — GitHub (Capa 3):** {summary.get('github_menciones', 0)}\n"
            rw_incidents = summary.get('ransomware_incidents', 0)
            rw_nivel = summary.get('ransomware_nivel', 'LOW')
            md_content += f"- **Incidentes ransomware/ciberataques (Capa 4):** {rw_incidents} · riesgo {rw_nivel}\n"
            md_content += f"- **Maltiverse clasificación:** {summary.get('maltiverse_clasificacion', 'neutral')}\n"
            if summary.get('intelx_pastes', 0):
                md_content += f"- **Registros IntelX (pastes/buckets):** {summary.get('intelx_pastes', 0)}\n"
            md_content += "\n"

            # Capa 1: brechas de datos (lo más accionable)
            breaches = dw.get('breaches', {})
            comprometidos = [r for r in breaches.get('results', []) if r.get('found')]
            db = breaches.get('domain_breaches', {})
            lc_hits = [r for r in breaches.get('leakcheck', []) if not r.get('error')]
            dh_hits = breaches.get('dehashed', [])

            md_content += "#### 📧 Capa 1 — Brechas de datos\n\n"
            if comprometidos:
                md_content += "**XposedOrNot (por email):**\n\n"
                md_content += "| Email | Brechas |\n|-------|--------|\n"
                for r in comprometidos:
                    md_content += f"| `{r.get('email','')}` | {', '.join(r.get('breaches', [])[:8])} |\n"
                md_content += "\n"
            else:
                checked = breaches.get('checked_emails', 0)
                if checked:
                    md_content += f"✅ XposedOrNot: {checked} correos revisados — sin filtraciones detectadas.\n\n"

            if db.get('count', 0):
                md_content += f"**XposedOrNot domain-level:** {db.get('count',0)} brechas afectan al dominio.\n\n"
                if db.get('breaches'):
                    md_content += "| Brecha |\n|--------|\n"
                    for b in db['breaches'][:15]:
                        md_content += f"| {b} |\n"
                    md_content += "\n"

            if lc_hits:
                md_content += f"**⚠️ LeakCheck: {len(lc_hits)} credenciales filtradas del dominio**\n\n"
                md_content += "| Email / Usuario | Fuente(s) |\n|----------------|----------|\n"
                for r in lc_hits[:20]:
                    ident = r.get('email') or r.get('username', '')
                    src = ', '.join(r.get('source', [])[:3]) if r.get('source') else '—'
                    md_content += f"| `{ident}` | {src} |\n"
                md_content += "\n"
            elif breaches.get('leakcheck_error', {}).get('error') == 'rate_limit':
                md_content += "> ℹ️ LeakCheck: límite diario alcanzado (5/día plan free).\n\n"
            elif self and not breaches.get('leakcheck'):
                md_content += "> ℹ️ LeakCheck: sin LEAKCHECK_API_KEY — regístrate en https://leakcheck.io (gratis, 5 búsquedas/día).\n\n"

            if dh_hits:
                md_content += f"**💀 Dehashed: {len(dh_hits)} registros con credenciales del dominio**\n\n"
                md_content += "| Email | Usuario | Base de datos |\n|-------|---------|---------------|\n"
                for r in dh_hits[:20]:
                    md_content += f"| `{r.get('email','')}` | {r.get('username','')} | {r.get('database','')} |\n"
                md_content += "\n"

            # Capa 2: índice dark web
            ahmia = dw.get('ahmia', {})
            ahmia_status = ahmia.get('status', '')
            if ahmia_status == 'requires_tor_or_intelx':
                md_content += "#### 🌑 Capa 2 — Índice dark web\n\n"
                md_content += f"> ⚠️ {ahmia.get('message', 'Activa Tor para búsqueda en dark web.')}\n\n"
            elif ahmia.get('total', 0) > 0:
                md_content += f"#### 🌑 Capa 2 — Índice dark web: {ahmia.get('total', 0)} enlace(s) .onion [{ahmia.get('method','')}]\n\n"
                links = ahmia.get('links', [])
                if links:
                    md_content += "| Título | .onion | Fuente |\n|--------|--------|--------|\n"
                    for ln in links[:10]:
                        md_content += f"| {ln.get('title','')[:60]} | `{ln.get('onion','')}` | {ln.get('source','')} |\n"
                    md_content += "\n"
            else:
                metodo = ahmia.get('method', '')
                md_content += f"#### 🌑 Capa 2 — Índice dark web\n\n✅ Sin menciones del dominio en dark web [{metodo}].\n\n"

            # Capa 3: leaks en fuentes abiertas
            pastes_data = dw.get('pastes', {})
            pastes_list = pastes_data.get('pastes', [])
            notas_pastes = pastes_data.get('notas', [])
            if notas_pastes:
                for nota in notas_pastes:
                    md_content += f"> ℹ️ {nota}\n"
                md_content += "\n"
            if pastes_list:
                fuentes_str = " | ".join(pastes_data.get('fuentes', []))
                md_content += f"#### 📋 Capa 3 — Leaks en fuentes abiertas — {fuentes_str}\n\n"
                md_content += "| Fecha | Fuente | Enlace / Referencia |\n|-------|--------|---------------------|\n"
                for p in pastes_list[:30]:
                    tags   = p.get('tags', '')
                    fecha  = p.get('date', '') or '—'
                    url    = p.get('url', '')
                    fuente = tags.split('|')[0].strip() if '|' in tags else tags
                    md_content += f"| {fecha} | {fuente} | `{url[:80]}` |\n"
                if pastes_data.get('github_total', 0) > 15:
                    resto = pastes_data['github_total'] - 15
                    md_content += f"\n*+ {resto} menciones más en GitHub no mostradas.*\n"
                md_content += "\n"
            else:
                md_content += "#### 📋 Capa 3 — Leaks en fuentes abiertas\n\n✅ Sin leaks detectados en fuentes abiertas.\n\n"

            # Capa 4: ransomware & ciberataques (NUEVO)
            ransomware = dw.get('ransomware', {})
            if ransomware:
                rw_nivel_str = ransomware.get('nivel_riesgo', 'LOW')
                rw_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(rw_nivel_str, "⚪")
                md_content += f"#### 🦠 Capa 4 — Ransomware & Ciberataques — {rw_icon} {rw_nivel_str}\n\n"

                victims   = ransomware.get('victims', [])
                attacks   = ransomware.get('cyberattacks', [])
                rl_hits   = ransomware.get('ransomlook', [])
                maltiverse = ransomware.get('maltiverse', {})
                infostealer = ransomware.get('infostealer', {})

                if victims:
                    md_content += "**⚠️ ALERTA: Dominio / empresa encontrado en leak sites de ransomware**\n\n"
                    md_content += "| Grupo ransomware | Víctima | Sitio | Publicado |\n|------------------|---------|-------|-----------|\n"
                    for v in victims[:10]:
                        md_content += (f"| {v.get('grupo','')} | {v.get('victima','')[:60]} "
                                       f"| {v.get('sitio','')} | {v.get('publicado','')} |\n")
                    md_content += "\n"
                    if infostealer:
                        md_content += (f"> 💀 **Infostealer data:** "
                                       f"{infostealer.get('empleados_comprometidos', 0)} empleados comprometidos, "
                                       f"{infostealer.get('usuarios_comprometidos', 0)} usuarios, "
                                       f"{infostealer.get('terceros_afectados', 0)} terceros afectados.\n\n")
                elif attacks:
                    md_content += "**ℹ️ Ciberataques relacionados detectados:**\n\n"
                    md_content += "| Título | Dominio | País | Fecha |\n|--------|---------|------|-------|\n"
                    for a in attacks[:10]:
                        md_content += (f"| {a.get('titulo','')[:60]} | {a.get('dominio','')} "
                                       f"| {a.get('pais','')} | {a.get('fecha','')} |\n")
                    md_content += "\n"
                else:
                    md_content += "✅ Sin presencia en leak sites de grupos de ransomware activos.\n\n"

                if rl_hits:
                    md_content += "**RansomLook:**\n"
                    for h in rl_hits[:5]:
                        md_content += f"- {h.get('grupo','')} · {h.get('victima','')} · {h.get('fecha','')}\n"
                    md_content += "\n"

                if maltiverse:
                    cls = maltiverse.get('clasificacion', 'neutral')
                    bls = maltiverse.get('blacklist', [])
                    tags = maltiverse.get('tags', [])
                    md_content += f"**Maltiverse:** clasificación `{cls}`"
                    if bls:
                        md_content += f" · blacklists: {', '.join(str(b) for b in bls[:3])}"
                    if tags:
                        md_content += f" · tags: {', '.join(str(t) for t in tags[:5])}"
                    md_content += f"\n\n> *Nota: {ransomware.get('nota','')}*\n\n"

            # Capa 5: crawling .onion via Tor (si se ejecutó)
            raw_results = dw.get('raw_results', [])
            if raw_results:
                md_content += "#### 🔎 Capa 5 — Resultados dark web (crawling Tor)\n\n"
                md_content += "| # | Título | Enlace |\n"
                md_content += "|---|--------|--------|\n"
                for i, r in enumerate(raw_results[:20], 1):
                    title = r.get('title', 'N/A')[:60]
                    link  = r.get('link', 'N/A')
                    md_content += f"| {i} | {title} | `{link}` |\n"
            analyzed = dw.get('analyzed_threats', [])
            if analyzed:
                md_content += "\n#### 🚨 Análisis de amenazas por crawling (Tor)\n\n"
                md_content += "| # | URL | Título | Nivel de amenaza | Correos encontrados |\n"
                md_content += "|---|-----|--------|------------------|---------------------|\n"
                for i, a in enumerate(analyzed, 1):
                    threat_icon = "🔴" if a['threat_level'] == 'HIGH' else "🟠" if a['threat_level'] == 'MEDIUM' else "🟢"
                    emails_str = ", ".join(a.get('emails', [])[:2]) if a.get('emails') else "-"
                    url_short  = a['url'][:60] + '...' if len(a['url']) > 60 else a['url']
                    title_short = a['title'][:40] + '...' if len(a['title']) > 40 else a['title']
                    md_content += f"| {i} | `{url_short}` | {title_short} | {threat_icon} {a['threat_level']} | {emails_str} |\n"
        else:
            md_content += "No se realizó búsqueda.\n"

        # ==================== ADVERTENCIAS (todas las APIs con error) ====================
        md_content += """
## ⚠️ Advertencias sobre APIs

"""
        warnings = []
        for api_name, api_result in threat_data.items():
            if isinstance(api_result, dict) and api_result.get('status') == 'error':
                error_type = api_result.get('error_type')
                msg = api_result.get('message', 'Error desconocido')
                if error_type:
                    warnings.append(f"- **{api_name.capitalize()}**: {msg}")
                else:
                    warnings.append(f"- **{api_name.capitalize()}**: {msg}")
        if warnings:
            md_content += "\n".join(warnings) + "\n"
        else:
            md_content += "No se detectaron problemas con las API keys o cuotas.\n"

        # ========== HERRAMIENTAS MANUALES Y LIMITACIONES ==========
        md_content += f"""

---

## 🛠️ Herramientas y APIs Utilizadas

| Categoría | Herramientas/APIs |
|-----------|-------------------|
| Descubrimiento | crt.sh, DNSdumpster, Subfinder, DNS, WHOIS |
| Threat Intel | Shodan, Censys, VirusTotal, AlienVault OTX |
| Geolocalización | IPinfo, IPdata |
| Búsqueda de emails | Hunter.io |
| Activos expuestos | Netlas, urlscan.io |
| Reputación de IP | AbuseIPDB |
| Subdominios | BeVigil |
| Repositorios | GitHub, GitLab |
| Dark Web | osint-darkweb-pkg (multi-motor), Ahmia, crawling propio |
| Fingerprinting | Wappalyzer (wappalyzer-next) |
| Vulnerabilidades | NVD API (nvdlib), INCIBE-CERT (alerta temprana) |
| Exploits | Exploit-DB (searchsploit) |

---

*Informe generado por **OSINT Recon Suite** — Created by Cristian & Luisber*
"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"[✓] Informe Markdown guardado en: {filename}")
        return filename

    # ============================================================
    # INFORME HTML (visual, autocontenido, se abre en el navegador)
    # ============================================================
    def to_html(self, discovery_data: Dict, threat_data: Dict, diagnostics: Dict = None, filename: str = None) -> str:
        from html import escape

        if filename is None:
            filename = f"{self.output_dir}/informe_{self.dominio_slug}_{self.timestamp}.html"

        domain = discovery_data.get('domain', 'N/D')
        activos = discovery_data.get('activos', {}).get('resumen', {})
        activos_det = discovery_data.get('activos', {}).get('resultados_detallados', [])
        fp = threat_data.get('fingerprinting', {})
        vuln = threat_data.get('vulnerabilities', {})
        dw = threat_data.get('darkweb', {})
        diag = diagnostics or {}
        src_map = discovery_data.get('subdomain_sources', {})

        def badge(text, kind):
            return f'<span class="badge {kind}">{escape(str(text))}</span>'

        def sev_kind(sev):
            return {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get(
                (sev or "").upper(), "unk")

        # ---- Tarjetas de resumen ----
        cards = [
            ("Subdominios", discovery_data.get('total_subdomains', 0), "blue"),
            ("Hosts activos", f"{activos.get('activos', 0)}/{activos.get('total_hosts', 0)}" if activos else "—", "green"),
            ("APIs OK", f"{diag.get('apis_ok', 0)}/{diag.get('apis_total', 0)}" if diag else "—", "cyan"),
            ("Tecnologías", fp.get('total_technologies', 0) if fp.get('status') == 'success' else "—", "violet"),
            ("CVEs", vuln.get('total_cves', 0) if vuln.get('status') == 'success' else "—", "red"),
            ("Exploits", vuln.get('total_exploits', 0) if vuln.get('status') == 'success' else "—", "orange"),
            ("Fichas INCIBE", vuln.get('incibe_refs', 0) if vuln.get('status') == 'success' else "—", "yellow"),
            ("Enlaces .onion", dw.get('total_links_found', 0) if dw.get('status') == 'success' else "—", "gray"),
        ]
        cards_html = "".join(
            f'<div class="card {c}"><div class="num">{escape(str(v))}</div><div class="lbl">{escape(t)}</div></div>'
            for t, v, c in cards
        )

        # ---- Aviso de claves a renovar ----
        alert_html = ""
        if diag.get('keys_to_fix'):
            items = "".join(f"<li><b>{escape(a['name'])}</b> — {escape(a['label'])}: {escape(a['action'])}</li>"
                            for a in diag['keys_to_fix'])
            alert_html = f'<div class="alert"><h3>🔑 Acción requerida: claves a renovar/actualizar en <code>.env</code></h3><ul>{items}</ul></div>'

        # ---- Diagnóstico APIs ----
        api_status_badge = {
            "ok": ("OK", "low"), "no_api_key": ("sin clave", "unk"),
            "invalid_key": ("inválida/caducada", "crit"), "quota_exceeded": ("cuota agotada", "high"),
            "error": ("error", "high"),
        }
        api_rows = ""
        for a in diag.get('apis', []):
            label, kind = api_status_badge.get(a['status'], (a['status'], "unk"))
            renew = f'<a href="{escape(a["renew"])}" target="_blank">{escape(a["renew"])}</a>' if a['status'] != 'ok' else ""
            api_rows += f"<tr><td>{escape(a['name'])}</td><td>{badge(label, kind)}</td><td>{escape(a['action'] or '—')}<br>{renew}</td></tr>"

        tool_rows = ""
        for t in diag.get('tools', []):
            est = badge("disponible", "low") if t['ok'] else badge("no disponible", "high")
            tool_rows += f"<tr><td>{escape(t['tool'])}</td><td>{est}</td><td>{escape(t['impact'])}</td><td>{'' if t['ok'] else escape(t['fix'])}</td></tr>"

        diag_html = ""
        if diag:
            diag_html = f"""
            <section><h2>🩺 Diagnóstico del escaneo</h2>
            <table><thead><tr><th>API</th><th>Estado</th><th>Acción recomendada</th></tr></thead><tbody>{api_rows}</tbody></table>
            <h3>Herramientas externas</h3>
            <table><thead><tr><th>Herramienta</th><th>Estado</th><th>Aporta</th><th>Cómo solucionarlo</th></tr></thead><tbody>{tool_rows}</tbody></table>
            </section>"""

        # ---- Subdominios ----
        estado_map = {r.get('host'): r for r in activos_det}
        sub_rows = ""
        for i, sub in enumerate(discovery_data.get('subdomains', []), 1):
            est = estado_map.get(sub, {})
            if est.get('estado') == 'ACTIVA':
                estado = badge(f"activo · {est.get('metodo_deteccion', '')}", "low")
            elif est.get('estado'):
                estado = badge("inactivo", "unk")
            else:
                estado = "—"
            fuentes = escape(", ".join(src_map.get(sub, [])) or "—")
            sub_rows += f"<tr><td>{i}</td><td><code>{escape(sub)}</code></td><td>{estado}</td><td class='muted'>{fuentes}</td></tr>"

        # ---- DNS ----
        dns_rows = "".join(
            f"<tr><td><b>{escape(k)}</b></td><td><code>{escape(', '.join(str(x) for x in v[:8]))}</code></td></tr>"
            for k, v in discovery_data.get('dns_records', {}).items() if v
        )

        # ---- Tecnologías ----
        tech_by_url = {}
        for it in fp.get('results', []) if isinstance(fp, dict) else []:
            ver = it.get('version', '')
            lbl = f"{it.get('technology')} {ver}".strip() if ver and ver != 'N/A' else it.get('technology', '')
            tech_by_url.setdefault(it.get('url', ''), set()).add(lbl)
        tech_rows = "".join(
            f"<tr><td><a href='{escape(u)}' target='_blank'>{escape(u)}</a></td><td>{escape(', '.join(sorted(ts)))}</td></tr>"
            for u, ts in tech_by_url.items()
        )

        # ---- CVEs ----
        cve_rows = ""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        flat = []
        for tech in vuln.get('results', []) if isinstance(vuln, dict) else []:
            for cve in tech.get('cves', []):
                flat.append((tech, cve))
        flat.sort(key=lambda x: order.get((x[1].get('severity') or 'UNKNOWN').upper(), 4))
        for tech, cve in flat:
            inc = cve.get('incibe', {}) or {}
            if inc.get('disponible'):
                tag = "⚠️ alerta temprana" if inc.get('en_alerta_temprana') else "ficha"
                inc_cell = f'<a href="{escape(inc.get("url", ""))}" target="_blank">{tag}</a>'
            else:
                inc_cell = "—"
            exploit = badge("sí", "crit") if cve.get('exploit_available') else "<span class='muted'>no</span>"
            cve_rows += (
                f"<tr><td><code>{escape(cve.get('id', ''))}</code></td>"
                f"<td>{badge(cve.get('severity', 'UNKNOWN'), sev_kind(cve.get('severity')))}</td>"
                f"<td>{escape(tech['technology'])} {escape(tech['version'])}</td>"
                f"<td class='muted'>{escape((cve.get('description') or '')[:120])}</td>"
                f"<td>{exploit}</td><td>{inc_cell}</td></tr>"
            )
        cve_section = ""
        if cve_rows:
            cve_section = f"""<section><h2>🚨 Vulnerabilidades (CVEs)</h2>
            <p class="muted">Total: {vuln.get('total_cves', 0)} · con exploit público: {vuln.get('total_exploits', 0)} · con ficha INCIBE-CERT: {vuln.get('incibe_refs', 0)}</p>
            <table><thead><tr><th>CVE</th><th>Severidad</th><th>Tecnología</th><th>Descripción</th><th>Exploit</th><th>INCIBE-CERT</th></tr></thead><tbody>{cve_rows}</tbody></table></section>"""
        elif fp.get('status') == 'success':
            cve_section = '<section><h2>🚨 Vulnerabilidades (CVEs)</h2><p class="muted">No se encontraron CVEs asociados a las tecnologías con versión detectada.</p></section>'

        # ---- INCIBE alerta temprana ----
        ew = vuln.get('incibe_early_warning', []) if isinstance(vuln, dict) else []
        ew_rows = "".join(
            f"<tr><td><code>{escape(e.get('cve', ''))}</code></td><td>{escape(e.get('gravedad_31') or e.get('gravedad_40') or '—')}</td>"
            f"<td>{escape(e.get('cvss_31') or e.get('cvss_40') or '—')}</td><td>{escape(e.get('fecha_publicacion', '—'))}</td>"
            f"<td><a href='{escape(e.get('url', ''))}' target='_blank'>ver ficha</a></td></tr>" for e in ew[:25]
        )
        ew_section = f"""<section><h2>🇪🇸 Alerta Temprana INCIBE-CERT</h2>
            <p class="muted">Vulnerabilidades recientes de INCIBE-CERT que mencionan las tecnologías detectadas.</p>
            <table><thead><tr><th>CVE</th><th>Gravedad</th><th>CVSS</th><th>Fecha</th><th>Ficha</th></tr></thead><tbody>{ew_rows}</tbody></table></section>""" if ew_rows else ""

        # ---- Dark web ----
        dw_section = ""
        if dw.get('status') == 'success':
            rows = ""
            for a in dw.get('analyzed_threats', []):
                lvl = a.get('threat_level', 'LOW')
                kind = {"HIGH": "crit", "MEDIUM": "high", "LOW": "low"}.get(lvl, "unk")
                rows += (f"<tr><td class='muted'>{escape(a.get('url', '')[:60])}</td><td>{escape(a.get('title', '')[:50])}</td>"
                         f"<td>{badge(lvl, kind)}</td><td class='muted'>{escape(', '.join(a.get('emails', [])[:2]))}</td></tr>")
            body = f"<table><thead><tr><th>URL .onion</th><th>Título</th><th>Riesgo</th><th>Emails</th></tr></thead><tbody>{rows}</tbody></table>" if rows else ""
            dw_section = f"<section><h2>🌑 Dark Web</h2><p class='muted'>{dw.get('total_links_found', 0)} enlaces .onion encontrados.</p>{body}</section>"
        elif dw.get('status') == 'error':
            dw_section = f"<section><h2>🌑 Dark Web</h2><p class='alert-inline'>⚠️ {escape(dw.get('message', ''))}</p></section>"

        whois = discovery_data.get('whois', {})
        whois_html = "".join(
            f"<tr><td><b>{escape(k)}</b></td><td>{escape(str(v)[:120])}</td></tr>"
            for k, v in whois.items() if k != 'error'
        )

        html = _HTML_TEMPLATE.format(
            domain=escape(domain),
            ip=escape(str(threat_data.get('ip_address', 'N/D'))),
            ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            cards=cards_html,
            alert=alert_html,
            diag=diag_html,
            sub_rows=sub_rows or "<tr><td colspan=4 class='muted'>Sin subdominios</td></tr>",
            sub_total=discovery_data.get('total_subdomains', 0),
            dns_rows=dns_rows or "<tr><td colspan=2 class='muted'>Sin registros</td></tr>",
            whois_rows=whois_html or "<tr><td colspan=2 class='muted'>No disponible</td></tr>",
            tech_rows=tech_rows or "<tr><td colspan=2 class='muted'>Sin datos (fingerprinting omitido o sin resultados)</td></tr>",
            cve_section=cve_section,
            ew_section=ew_section,
            dw_section=dw_section,
        )
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[✓] Informe HTML guardado en: {filename}")
        return filename