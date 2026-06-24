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
import os
from datetime import datetime
from typing import Dict, List

# Librería del grafo vendorizada (scripts/assets/vis-network.min.js). Se inlina en
# el HTML para que el informe sea un ÚNICO archivo que funciona SIN internet (clave
# al abrirlo en otro equipo, p. ej. un Mac). Si el fichero no está, se cae al CDN.
_VIS_NETWORK_PATH = os.path.join(
    os.path.dirname(__file__), "..", "assets", "vis-network.min.js")


def _vis_network_loader() -> str:
    """Devuelve el <script> que carga vis-network: inline si está vendorizado,
    si no, etiqueta <script src=CDN> como respaldo."""
    try:
        with open(_VIS_NETWORK_PATH, "r", encoding="utf-8") as fh:
            js = fh.read()
        # Evitar que un '</script>' dentro de la librería cierre la etiqueta.
        js = js.replace("</script>", "<\\/script>")
        return f"<script>{js}</script>"
    except OSError:
        return ("<script src='https://unpkg.com/vis-network@9.1.9/standalone/umd/"
                "vis-network.min.js'></script>")

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
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;overflow-wrap:anywhere;word-break:break-word}}
th{{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
tbody tr:hover{{background:var(--panel2)}}
code{{background:#0b0f14;padding:1px 6px;border-radius:5px;font-size:12.5px;color:#79c0ff;word-break:break-all}}
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
html{{scroll-behavior:smooth}}
section[id]{{scroll-margin-top:14px}}
a.card{{text-decoration:none;color:inherit;display:block;transition:border-color .15s,transform .15s}}
a.card:hover{{border-color:var(--accent);transform:translateY(-2px)}}
a.card .lbl::after{{content:" ↗";opacity:.55;font-size:10px}}
.tablewrap{{overflow-x:auto;-webkit-overflow-scrolling:touch}}
.help{{background:var(--panel2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:10px 14px;margin:10px 0;font-size:13px;color:var(--muted)}}
.help b{{color:var(--txt)}}
.gtoolbar{{display:flex;gap:6px;margin:10px 0 4px;flex-wrap:wrap}}
.gtoolbar button{{background:var(--panel2);color:var(--txt);border:1px solid var(--border);border-radius:7px;padding:5px 11px;font-size:13px;cursor:pointer;font-family:inherit}}
.gtoolbar button:hover{{border-color:var(--accent);color:var(--accent)}}
.gsearch{{width:100%;max-width:360px;background:var(--panel2);color:var(--txt);border:1px solid var(--border);border-radius:7px;padding:7px 11px;font-size:13px;font-family:inherit;margin:8px 0 0}}
.gsearch:focus{{outline:none;border-color:var(--accent)}}
.summary .exec{{list-style:none;margin:0;padding:0;display:grid;gap:8px}}
.summary .exec li{{background:var(--panel2);border:1px solid var(--border);border-left:3px solid var(--muted);border-radius:8px;padding:10px 14px;font-size:14px}}
.summary .exec li.crit{{border-left-color:#f85149}}
.summary .exec li.high{{border-left-color:#db6d28}}
.summary .exec li.warn{{border-left-color:#d4a72c}}
.summary .exec li.ok{{border-left-color:#3fb950}}
.summary .exec li b{{color:var(--txt)}}
.summary .exec a{{color:var(--accent)}}
</style></head>
<body><div class="wrap">
<header>
  <h1>🔍 Informe OSINT — {domain}</h1>
  <div class="sub">OSINT Recon Suite · Reconocimiento pasivo de activos, tecnologías, vulnerabilidades y dark web</div>
  <div class="meta">🎯 <b>{domain}</b> &nbsp;·&nbsp; 📡 IP: <b>{ip}</b> &nbsp;·&nbsp; 🕐 {ts}</div>
</header>
<div class="cards">{cards}</div>
{summary}
{alert}
{diag}
<section id="sub"><h2>🌐 Subdominios ({sub_total})</h2>
<table><thead><tr><th>#</th><th>Subdominio</th><th>Estado</th><th>Fuentes</th></tr></thead><tbody>{sub_rows}</tbody></table></section>
<section><h2>🔍 Registros DNS</h2><table><tbody>{dns_rows}</tbody></table></section>
<section><h2>🏢 WHOIS</h2><table><tbody>{whois_rows}</tbody></table></section>
{ti_section}
<section id="tech"><h2>🧬 Tecnologías detectadas</h2><div class="tablewrap"><table><thead><tr><th>URL</th><th>Tecnologías</th></tr></thead><tbody>{tech_rows}</tbody></table></div></section>
{cve_section}
{ew_section}
{dw_section}
{socradar_section}
{entities_section}
<footer>Generado por <b>OSINT Recon Suite</b> · Created by Cristian &amp; Luisber</footer>
</div></body></html>"""

class ReportGenerator:
    """
    Genera informes en tres formatos: JSON, CSV y Markdown.
    Los archivos se guardan en una carpeta (por defecto 'outputs').
    """

    def __init__(self, output_dir: str = "outputs", dominio: str = None,
                 timestamp: str = None):
        self.output_dir = output_dir
        # Sello de tiempo europeo (día-mes-año) para los nombres de archivo,
        # más legible. Se puede inyectar desde fuera para que todos los archivos
        # del mismo escaneo (json/csv/md/html/iocs) compartan exactamente el sello.
        self.timestamp = timestamp or datetime.now().strftime("%d-%m-%Y_%Hh%M")
        self.dominio_slug = dominio.replace('.', '_') if dominio else "unknown"
        import os
        os.makedirs(output_dir, exist_ok=True)

    def to_json(self, data: Dict, filename: str = None) -> str:
        if filename is None:
            filename = f"{self.output_dir}/{self.dominio_slug}_activos_{self.timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"[✓] JSON guardado en: {filename}")
        return filename

    def to_csv(self, subdomains: List[str], filename: str = None, sources: Dict = None) -> str:
        if filename is None:
            filename = f"{self.output_dir}/{self.dominio_slug}_subdominios_{self.timestamp}.csv"
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
            filename = f"{self.output_dir}/{self.dominio_slug}_informe_{self.timestamp}.md"

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

            # Capa 6: foros dark web + leak sites directos + infostealers
            ds = dw.get('dark_sources', {})
            if ds:
                ds_nivel = ds.get('nivel_riesgo', 'LOW')
                ds_icon  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(ds_nivel, "⚪")
                md_content += f"#### 🕵️ Capa 6 — Foros dark web / Leak sites directos / Infostealers — {ds_icon} {ds_nivel}\n\n"

                # Hudson Rock (infostealer intel)
                hr = ds.get('infostealer', {}) or {}
                if hr.get('status') == 'success':
                    emp = hr.get('employees', 0)
                    usr = hr.get('users', 0)
                    if emp > 0 or usr > 0:
                        md_content += f"**⚠️ Hudson Rock (Infostealer Intelligence):**\n"
                        md_content += f"- Empleados con credenciales comprometidas por infostealers: **{emp}**\n"
                        md_content += f"- Usuarios del dominio comprometidos: **{usr}**\n"
                        stealers = hr.get('stealers', [])
                        if stealers:
                            md_content += f"- Familias de malware: {', '.join(str(s) for s in stealers[:5])}\n"
                        md_content += "\n"
                    else:
                        md_content += "✅ Hudson Rock: sin credenciales comprometidas por infostealers.\n\n"

                # Leak sites directos (ransomware .onion)
                ls_hits = ds.get('leaksites_hits', [])
                scanned = ds.get('leaksites_scanned', 0)
                if ls_hits:
                    md_content += f"**⚠️ Encontrado en {len(ls_hits)} leak site(s) de ransomware (acceso directo via Tor):**\n\n"
                    md_content += "| Grupo | Variante encontrada | Contexto |\n|-------|--------------------|---------|\n"
                    for h in ls_hits[:10]:
                        md_content += f"| {h.get('grupo','')} | `{h.get('variante','')}` | {h.get('contexto','')[:80]} |\n"
                    md_content += "\n"
                elif scanned:
                    md_content += f"✅ {scanned} leak sites .onion escaneados — sin menciones del dominio.\n\n"

                # RansomLook víctimas recientes
                rl2_hits = ds.get('ransomlook_hits', [])
                if rl2_hits:
                    md_content += f"**⚠️ RansomLook — {len(rl2_hits)} víctima(s) relacionada(s):**\n\n"
                    md_content += "| Grupo | Víctima | Fecha |\n|-------|---------|-------|\n"
                    for h in rl2_hits[:5]:
                        md_content += f"| {h.get('grupo','')} | {h.get('victima','')[:60]} | {h.get('fecha','')} |\n"
                    md_content += "\n"

                # Foros (BreachForums + clearnet)
                fm_hits = ds.get('forum_hits', [])
                if fm_hits:
                    md_content += f"**⚠️ Menciones en foros de credenciales ({len(fm_hits)} resultados):**\n\n"
                    md_content += "| Foro | Variante | Extracto |\n|------|---------|----------|\n"
                    for h in fm_hits[:10]:
                        md_content += f"| {h.get('fuente','')} | `{h.get('variante','')}` | {h.get('extracto','')[:80]} |\n"
                    md_content += "\n"

                # Motores de búsqueda Tor
                ts_hits = ds.get('tor_search_hits', [])
                if ts_hits:
                    md_content += f"**⚠️ Resultados en motores .onion ({len(ts_hits)} encontrados):**\n\n"
                    md_content += "| Motor | Variante | Enlace / Contexto |\n|-------|---------|-------------------|\n"
                    for h in ts_hits[:8]:
                        enlace = h.get('enlace', '')[:80]
                        md_content += f"| {h.get('motor','')} | `{h.get('variante','')}` | `{enlace}` |\n"
                    md_content += "\n"

                # Telegram público
                tg_hits = ds.get('telegram_hits', [])
                if tg_hits:
                    md_content += f"**⚠️ Menciones en canales Telegram públicos ({len(tg_hits)}):**\n\n"
                    md_content += "| Canal | Variante | Extracto |\n|-------|---------|----------|\n"
                    for h in tg_hits[:8]:
                        md_content += f"| {h.get('fuente','')} | `{h.get('variante','')}` | {h.get('extracto','')[:80]} |\n"
                    md_content += "\n"

                # Pulsedive
                pd = ds.get('pulsedive', {}) or {}
                pd_risk = pd.get('risk', '')
                if pd_risk and pd_risk not in ('none', 'unknown', 'error', ''):
                    pd_feeds = ', '.join(pd.get('feeds', [])[:3]) or 'N/A'
                    md_content += f"**Pulsedive (domain threat intel):** riesgo `{pd_risk}` · feeds: {pd_feeds}\n\n"

                # Salud de los .onion vigilados (rotación / caídas / bloqueos)
                onion_health = ds.get('onion_health', [])
                if onion_health:
                    _htxt = {"ok": "🟢 operativo", "blocked": "🟡 bloqueado", "down": "🔴 caído"}
                    _horder = {"down": 0, "blocked": 1, "ok": 2}
                    n_down = sum(1 for h in onion_health if h.get('estado') == 'down')
                    n_blk  = sum(1 for h in onion_health if h.get('estado') == 'blocked')
                    md_content += f"**🩺 Salud de los .onion vigilados ({len(onion_health)}):**\n\n"
                    if n_down or n_blk:
                        md_content += (f"> ⚠️ {n_down} caído(s) y {n_blk} bloqueado(s). Los .onion rotan "
                                       f"con frecuencia: actualiza `darkweb_onions.json` con las "
                                       f"direcciones nuevas (ver semillas descubiertas).\n\n")
                    md_content += "| Servicio | Categoría | Estado | Nota |\n|----------|-----------|--------|------|\n"
                    for h in sorted(onion_health, key=lambda x: _horder.get(x.get('estado'), 3)):
                        md_content += (f"| {h.get('servicio','')} | {h.get('categoria','')} | "
                                       f"{_htxt.get(h.get('estado'),'?')} | {h.get('nota','')[:70]} |\n")
                    md_content += "\n"

                # Semillas .onion descubiertas (The Hidden Wiki, tortaxi…)
                onion_seeds = ds.get('onion_seeds', [])
                if onion_seeds:
                    md_content += f"**🌱 Semillas .onion descubiertas ({len(onion_seeds)}):**\n\n"
                    md_content += "> Servicios Tor hallados en directorios (descubrimiento, no menciones del dominio). Útiles para actualizar direcciones rotadas.\n\n"
                    md_content += "| .onion | Título | Fuente |\n|--------|--------|--------|\n"
                    for s in onion_seeds[:40]:
                        md_content += (f"| `{s.get('onion','')}` | {s.get('titulo','')[:50]} | "
                                       f"{s.get('fuente','')} |\n")
                    md_content += "\n"

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

        # ========== ENTIDADES CORRELACIONADAS + CONFIDENCE SCORING ==========
        ent = threat_data.get('entities', {})
        if isinstance(ent, dict) and ent.get('entities'):
            st = ent.get('stats', {})
            bg = st.get('by_grade', {})
            _glabel = {"A": "🟢 A confirmado", "B": "🟡 B verificado",
                       "C": "🟠 C una fuente", "D": "⚪ D inferencia"}
            md_content += f"\n---\n\n## 🕸️ Entidades correlacionadas ({st.get('total', 0)})\n\n"
            md_content += ("Todo lo hallado, normalizado a entidades con un **grado de confianza** "
                           "según cuántas fuentes (y de qué fiabilidad) lo corroboran "
                           f"({st.get('relations', 0)} relaciones detectadas).\n\n")
            md_content += "**Confianza:** " + " · ".join(
                f"{_glabel[g]}: {bg.get(g, 0)}" for g in ('A', 'B', 'C', 'D') if bg.get(g)) + "\n\n"
            if 'new_entities' in st or 'seen_before' in st:
                md_content += (f"**Memoria entre escaneos:** 🆕 nuevas: {st.get('new_entities', 0)} · "
                               f"↻ ya conocidas: {st.get('seen_before', 0)}\n\n")
            md_content += "| Tipo | Valor | Confianza | Visto | #Fuentes | Fuentes |\n"
            md_content += "|------|-------|-----------|-------|----------|--------|\n"
            for e in ent['entities'][:80]:
                fuentes = ', '.join(e.get('sources', []))[:90]
                visto = "🆕 nuevo" if e.get('is_new') else (str(e.get('first_seen', ''))[:10] or '—')
                md_content += (f"| {e.get('type','')} | `{str(e.get('value',''))[:70]}` | "
                               f"{e.get('grade','')} | {visto} | {e.get('n_sources',0)} | {fuentes} |\n")
            if st.get('total', 0) > 80:
                md_content += f"\n> Mostrando 80 de {st.get('total', 0)} entidades (por confianza). Todas en el JSON.\n"
            md_content += "\n"

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
            filename = f"{self.output_dir}/{self.dominio_slug}_informe_{self.timestamp}.html"

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
        # 4º campo = ancla de la sección a la que salta el card al hacer clic.
        cards = [
            ("Subdominios", discovery_data.get('total_subdomains', 0), "blue", "sub"),
            ("Hosts activos", f"{activos.get('activos', 0)}/{activos.get('total_hosts', 0)}" if activos else "—", "green", "sub"),
            ("APIs OK", f"{diag.get('apis_ok', 0)}/{diag.get('apis_total', 0)}" if diag else "—", "cyan", "diag"),
            ("Tecnologías", fp.get('total_technologies', 0) if fp.get('status') == 'success' else "—", "violet", "tech"),
            ("CVEs", vuln.get('total_cves', 0) if vuln.get('status') == 'success' else "—", "red", "cve"),
            ("Exploits", vuln.get('total_exploits', 0) if vuln.get('status') == 'success' else "—", "orange", "cve"),
            ("Fichas INCIBE", vuln.get('incibe_refs', 0) if vuln.get('status') == 'success' else "—", "yellow", "cve"),
            ("Enlaces .onion", dw.get('total_links_found', 0) if dw.get('status') == 'success' else "—", "gray", "darkweb"),
        ]
        _sr = threat_data.get('socradar', {})
        if isinstance(_sr, dict) and _sr.get('status') == 'success':
            cards.append(("Activos SOCRadar",
                          _sr.get('asm', {}).get('total', 0), "cyan", "socradar"))
        cards_html = "".join(
            f'<a class="card {c}" href="#{anchor}"><div class="num">{escape(str(v))}</div><div class="lbl">{escape(t)}</div></a>'
            for t, v, c, anchor in cards
        )

        # ---- Aviso de claves a renovar ----
        alert_html = ""
        if diag.get('keys_to_fix'):
            items = "".join(f"<li><b>{escape(a['name'])}</b> — {escape(a['label'])}: {escape(a['action'])}</li>"
                            for a in diag['keys_to_fix'])
            alert_html = f'<div class="alert"><h3>🔑 Acción requerida: claves a renovar/actualizar en <code>.env</code></h3><ul>{items}</ul></div>'

        # ---- Resumen ejecutivo ----
        # Destaca de un vistazo lo accionable: vulnerabilidades graves, claves a
        # renovar, novedades desde el último escaneo y exposición. Cada punto
        # enlaza a su sección. Si no hay nada reseñable, lo dice claramente.
        sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for _tech in vuln.get('results', []) if isinstance(vuln, dict) else []:
            for _cve in _tech.get('cves', []):
                _s = (_cve.get('severity') or 'UNKNOWN').upper()
                if _s in sev_count:
                    sev_count[_s] += 1
        n_exploits = vuln.get('total_exploits', 0) if vuln.get('status') == 'success' else 0
        n_keys = len(diag.get('keys_to_fix', []) or [])
        ent_stats = ent_main.get('stats', {}) if isinstance((ent_main := threat_data.get('entities', {})), dict) else {}
        n_new_ent = ent_stats.get('new_entities', 0)
        n_links = dw.get('total_links_found', 0) if dw.get('status') == 'success' else 0
        dw_mentions = dw.get('total_mentions', 0) if dw.get('status') == 'success' else 0
        n_active = activos.get('activos', 0) if activos else 0
        _hunter = threat_data.get('hunter', {}) if isinstance(threat_data.get('hunter'), dict) else {}
        n_emails = _hunter.get('total_emails', 0)

        exec_items = []
        crit_high = sev_count["CRITICAL"] + sev_count["HIGH"]
        if crit_high:
            expl = f" · <b>{n_exploits}</b> con exploit público conocido" if n_exploits else ""
            exec_items.append(("crit",
                f"🔴 <b>{crit_high}</b> vulnerabilidad(es) crítica(s)/alta(s) "
                f"({sev_count['CRITICAL']} críticas, {sev_count['HIGH']} altas){expl}. "
                f"<a href='#cve'>Ver detalle →</a>"))
        if n_keys:
            exec_items.append(("high",
                f"🔑 <b>{n_keys}</b> clave(s) de API a renovar/actualizar en <code>.env</code>. "
                f"<a href='#diag'>Ver diagnóstico →</a>"))
        if n_links or dw_mentions:
            partes = []
            if n_links:
                partes.append(f"<b>{n_links}</b> enlace(s) .onion")
            if dw_mentions:
                partes.append(f"<b>{dw_mentions}</b> mención(es)")
            exec_items.append(("warn",
                f"🧅 Exposición en dark web: {' y '.join(partes)} relacionadas con el dominio. "
                f"<a href='#darkweb'>Ver dark web →</a>"))
        if n_new_ent:
            exec_items.append(("ok",
                f"🆕 <b>{n_new_ent}</b> entidad(es) nueva(s) desde el último escaneo. "
                f"<a href='#entidades'>Ver entidades →</a>"))
        _sr_exec = threat_data.get('socradar', {})
        if isinstance(_sr_exec, dict) and _sr_exec.get('status') == 'success':
            _sr_assets = _sr_exec.get('asm', {}).get('total', 0)
            _sr_dw = _sr_exec.get('dark_web', {}).get('total', 0)
            _kind = "warn" if _sr_dw else "ok"
            _dw_txt = f" · <b>{_sr_dw}</b> hallazgo(s) dark web" if _sr_dw else ""
            exec_items.append((_kind,
                f"🛰️ SOCRadar: <b>{_sr_assets}</b> activo(s) en la superficie externa{_dw_txt}. "
                f"<a href='#socradar'>Ver SOCRadar →</a>"))
        # Contexto siempre útil (sin severidad): superficie descubierta.
        ctx = (f"🌐 <b>{discovery_data.get('total_subdomains', 0)}</b> subdominios "
               f"(<b>{n_active}</b> activos)")
        if fp.get('status') == 'success' and fp.get('total_technologies'):
            ctx += f" · 🧬 <b>{fp.get('total_technologies')}</b> tecnologías"
        if n_emails:
            ctx += f" · 📧 <b>{n_emails}</b> email(s) públicos"
        exec_items.append(("", ctx + "."))

        if not (crit_high or n_keys or n_links or dw_mentions):
            exec_items.insert(0, ("ok",
                "✅ Sin vulnerabilidades graves, claves caducadas ni exposición en dark web "
                "detectadas en este escaneo."))

        summary_html = (
            "<section id='resumen' class='summary'><h2>📋 Resumen ejecutivo</h2>"
            "<ul class='exec'>"
            + "".join(f"<li class='{kind}'>{txt}</li>" for kind, txt in exec_items)
            + "</ul></section>"
        )

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
            <section id="diag"><h2>🩺 Diagnóstico del escaneo</h2>
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
            cve_section = f"""<section id="cve"><h2>🚨 Vulnerabilidades (CVEs)</h2>
            <p class="muted">Total: {vuln.get('total_cves', 0)} · con exploit público: {vuln.get('total_exploits', 0)} · con ficha INCIBE-CERT: {vuln.get('incibe_refs', 0)}</p>
            <div class="tablewrap"><table><thead><tr><th>CVE</th><th>Severidad</th><th>Tecnología</th><th>Descripción</th><th>Exploit</th><th>INCIBE-CERT</th></tr></thead><tbody>{cve_rows}</tbody></table></div></section>"""
        elif fp.get('status') == 'success':
            cve_section = '<section id="cve"><h2>🚨 Vulnerabilidades (CVEs)</h2><p class="muted">No se encontraron CVEs asociados a las tecnologías con versión detectada.</p></section>'

        # ---- INCIBE alerta temprana ----
        ew = vuln.get('incibe_early_warning', []) if isinstance(vuln, dict) else []
        ew_rows = "".join(
            f"<tr><td><code>{escape(e.get('cve', ''))}</code></td><td>{escape(e.get('gravedad_31') or e.get('gravedad_40') or '—')}</td>"
            f"<td>{escape(e.get('cvss_31') or e.get('cvss_40') or '—')}</td><td>{escape(e.get('fecha_publicacion', '—'))}</td>"
            f"<td><a href='{escape(e.get('url', ''))}' target='_blank'>ver ficha</a></td></tr>" for e in ew[:25]
        )
        ew_section = f"""<section id="incibe"><h2>🇪🇸 Alerta Temprana INCIBE-CERT</h2>
            <p class="muted">Vulnerabilidades recientes de INCIBE-CERT que mencionan las tecnologías detectadas.</p>
            <div class="tablewrap"><table><thead><tr><th>CVE</th><th>Gravedad</th><th>CVSS</th><th>Fecha</th><th>Ficha</th></tr></thead><tbody>{ew_rows}</tbody></table></div></section>""" if ew_rows else ""

        # ---- Dark web / Exposición (todas las capas) ----
        dw_section = ""
        if dw.get('status') in ('success', 'error') or dw:
            dw_summary  = dw.get('summary', {})
            breaches_dw = dw.get('breaches', {})
            ahmia_dw    = dw.get('ahmia', {})
            pastes_dw   = dw.get('pastes', {})
            rw_dw       = dw.get('ransomware', {})
            ds_dw       = dw.get('dark_sources', {})

            nivel_global = dw_summary.get('nivel_exposicion', 'LOW')
            nivel_kind   = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get(nivel_global, "unk")
            nivel_icon   = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(nivel_global, "⚪")

            # ── Resumen de capas (tabla) ──────────────────────────────────────
            def capa_badge(val, ok_zero=True):
                """Verde si 0 (sin alertas), rojo si >0"""
                if isinstance(val, int) and val > 0:
                    return badge(val, "crit")
                if isinstance(val, int):
                    return badge(val, "low") if ok_zero else badge(val, "unk")
                return escape(str(val))

            c1_comp    = dw_summary.get('emails_comprometidos', 0)
            c2_onion   = dw_summary.get('menciones_onion', 0)
            c3_url     = dw_summary.get('urlscan_historico', 0)
            c3_gh      = dw_summary.get('github_menciones', 0)
            c4_rw      = dw_summary.get('ransomware_incidents', 0)
            c4_nivel   = dw_summary.get('ransomware_nivel', 'LOW')
            c6_ls      = dw_summary.get('leaksite_hits', 0)
            c6_rl      = dw_summary.get('ransomlook_hits', 0)
            c6_fm      = dw_summary.get('forum_hits', 0)
            c6_ts      = dw_summary.get('tor_search_hits', 0)
            c6_tg      = dw_summary.get('telegram_hits', 0)
            c6_emp     = dw_summary.get('infostealer_empleados', 0)
            c6_usr     = dw_summary.get('infostealer_usuarios', 0)
            c6_nivel   = dw_summary.get('dark_sources_nivel', 'LOW')
            c6_kind    = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get(c6_nivel, "unk")

            summary_rows = (
                f"<tr><td>1 · Brechas de datos</td><td>{capa_badge(c1_comp)} email(s) comprometidos</td></tr>"
                f"<tr><td>2 · Índice dark web</td><td>{capa_badge(c2_onion)} mención(es) .onion</td></tr>"
                f"<tr><td>3 · Leaks fuentes abiertas</td><td>URLScan: {escape(str(c3_url))} · GitHub: {escape(str(c3_gh))}</td></tr>"
                f"<tr><td>4 · Ransomware &amp; ciberataques</td><td>{capa_badge(c4_rw)} incidente(s) · nivel {escape(c4_nivel)}</td></tr>"
                f"<tr><td>6 · Leak sites / Foros / Infostealers</td>"
                f"<td>{badge(c6_nivel, c6_kind)} leaksites:{escape(str(c6_ls))} rl:{escape(str(c6_rl))} "
                f"foros:{escape(str(c6_fm))} tor-search:{escape(str(c6_ts))} "
                f"telegram:{escape(str(c6_tg))} · infostealers: {capa_badge(c6_emp)} emp / {escape(str(c6_usr))} usr</td></tr>"
            )
            overview = (
                f"<p>{nivel_icon} <b>Nivel de exposición: {badge(nivel_global, nivel_kind)}</b></p>"
                f"<table><thead><tr><th>Capa</th><th>Resultado</th></tr></thead><tbody>{summary_rows}</tbody></table>"
            )

            # ── Capa 1: brechas de emails ─────────────────────────────────────
            c1_section = ""
            comp_emails = breaches_dw.get('compromised', [])
            if comp_emails:
                erows = "".join(
                    f"<tr><td><code>{escape(e.get('email',''))}</code></td>"
                    f"<td class='muted'>{escape(', '.join(e.get('breaches', [])[:3]))}</td></tr>"
                    for e in comp_emails[:10]
                )
                c1_section = (
                    f"<h3>📧 Capa 1 — Brechas de datos</h3>"
                    f"<table><thead><tr><th>Email</th><th>Brechas</th></tr></thead><tbody>{erows}</tbody></table>"
                )
            xon_domain = breaches_dw.get('xon_domain_breaches', {})
            if xon_domain and xon_domain.get('ExposedBreaches'):
                c1_section += (
                    f"<p class='muted'>XposedOrNot dominio: "
                    f"{escape(str(xon_domain.get('BreachesSummary', {}).get('site', 0)))} brecha(s) asociadas al dominio.</p>"
                )

            # ── Capa 2: .onion links ──────────────────────────────────────────
            c2_section = ""
            onion_links = dw.get('raw_results', [])
            if onion_links:
                lrows = "".join(
                    f"<tr><td class='muted'><code>{escape(lk.get('link','')[:80])}</code></td>"
                    f"<td>{escape(lk.get('title','')[:60])}</td>"
                    f"<td class='muted'>{escape(lk.get('source',''))}</td></tr>"
                    for lk in onion_links[:15]
                )
                c2_section = (
                    f"<h3>🌑 Capa 2 — Índice dark web ({len(onion_links)} enlace(s) .onion)</h3>"
                    f"<table><thead><tr><th>URL .onion</th><th>Título</th><th>Fuente</th></tr></thead>"
                    f"<tbody>{lrows}</tbody></table>"
                )

            # ── Capa 3: paste / GitHub highlights ────────────────────────────
            c3_section = ""
            gh_repos = pastes_dw.get('github_repos', [])
            if gh_repos:
                grepos = "".join(
                    f"<tr><td><code>{escape(r.get('repo','')[:60])}</code></td>"
                    f"<td class='muted'>{escape(r.get('file','')[:60])}</td></tr>"
                    for r in gh_repos[:8]
                )
                c3_section = (
                    f"<h3>📋 Capa 3 — Repos públicos con menciones ({c3_gh})</h3>"
                    f"<table><thead><tr><th>Repositorio</th><th>Archivo</th></tr></thead>"
                    f"<tbody>{grepos}</tbody></table>"
                )

            # ── Capa 4: ransomware ────────────────────────────────────────────
            c4_section = ""
            rw_victims  = rw_dw.get('victims', [])
            rw_attacks  = rw_dw.get('cyberattacks', [])
            rl_victims  = rw_dw.get('ransomlook', [])
            if rw_victims or rw_attacks or rl_victims:
                vrows = "".join(
                    f"<tr><td class='muted'>{escape(v.get('grupo',''))}</td>"
                    f"<td>{escape(v.get('victima','')[:60])}</td>"
                    f"<td class='muted'>{escape(v.get('fecha',''))}</td></tr>"
                    for v in (rw_victims + rl_victims)[:10]
                )
                c4_section = (
                    f"<h3>🦠 Capa 4 — Ransomware &amp; ciberataques {badge(c4_nivel, {'CRITICAL':'crit','HIGH':'high','MEDIUM':'med','LOW':'low'}.get(c4_nivel,'unk'))}</h3>"
                    f"<table><thead><tr><th>Grupo</th><th>Víctima</th><th>Fecha</th></tr></thead>"
                    f"<tbody>{vrows}</tbody></table>"
                )

            # ── Capa 6: foros / leak sites / infostealers ─────────────────────
            c6_section = f"<h3>🕵️ Capa 6 — Foros / Leak sites directos / Infostealers {badge(c6_nivel, c6_kind)}</h3>"

            # Hudson Rock
            hr = ds_dw.get('infostealer', {}) or {}
            if hr.get('status') == 'success':
                if c6_emp > 0 or c6_usr > 0:
                    stealers = ', '.join(str(s) for s in hr.get('stealers', [])[:5]) or 'N/D'
                    c6_section += (
                        f"<p><b>⚠️ Hudson Rock (infostealers):</b> "
                        f"{badge(c6_emp, 'crit')} empleados · {escape(str(c6_usr))} usuarios comprometidos"
                        f" · malware: {escape(stealers)}</p>"
                    )
                else:
                    c6_section += "<p>✅ Hudson Rock: sin credenciales comprometidas por infostealers.</p>"

            # Leak sites escaneados
            ls_scanned = ds_dw.get('leaksites_scanned', 0)
            ls_hits_list = ds_dw.get('leaksites_hits', [])
            if ls_hits_list:
                lhrows = "".join(
                    f"<tr><td>{escape(h.get('grupo',''))}</td>"
                    f"<td><code>{escape(h.get('variante',''))}</code></td>"
                    f"<td class='muted'>{escape(h.get('contexto','')[:80])}</td></tr>"
                    for h in ls_hits_list[:10]
                )
                c6_section += (
                    f"<p><b>⚠️ {len(ls_hits_list)} leak site(s) de ransomware mencionan el dominio:</b></p>"
                    f"<table><thead><tr><th>Grupo</th><th>Variante</th><th>Contexto</th></tr></thead>"
                    f"<tbody>{lhrows}</tbody></table>"
                )
            elif ls_scanned:
                c6_section += f"<p class='muted'>✅ {ls_scanned} leak sites .onion escaneados — sin menciones.</p>"

            # Foros
            fm_hits_list = ds_dw.get('forum_hits', [])
            if fm_hits_list:
                fhrows = "".join(
                    f"<tr><td>{escape(h.get('fuente',''))}</td>"
                    f"<td><code>{escape(h.get('variante',''))}</code></td>"
                    f"<td class='muted'>{escape(h.get('extracto','')[:80])}</td></tr>"
                    for h in fm_hits_list[:10]
                )
                c6_section += (
                    f"<p><b>⚠️ {len(fm_hits_list)} menciones en foros de credenciales:</b></p>"
                    f"<table><thead><tr><th>Foro</th><th>Variante</th><th>Extracto</th></tr></thead>"
                    f"<tbody>{fhrows}</tbody></table>"
                )

            # Motores Tor
            ts_hits_list = ds_dw.get('tor_search_hits', [])
            if ts_hits_list:
                throws = "".join(
                    f"<tr><td>{escape(h.get('motor',''))}</td>"
                    f"<td><code>{escape(h.get('variante',''))}</code></td>"
                    f"<td class='muted'><code>{escape(h.get('enlace','')[:80])}</code></td></tr>"
                    for h in ts_hits_list[:8]
                )
                c6_section += (
                    f"<p><b>⚠️ {len(ts_hits_list)} resultado(s) en motores .onion:</b></p>"
                    f"<table><thead><tr><th>Motor</th><th>Variante</th><th>Enlace</th></tr></thead>"
                    f"<tbody>{throws}</tbody></table>"
                )

            # Telegram
            tg_hits_list = ds_dw.get('telegram_hits', [])
            if tg_hits_list:
                def _tg_msg_cell(h):
                    extracto = escape(h.get('extracto', '')[:120])
                    link = h.get('url', '')
                    if link.startswith('http'):
                        return f"<a href='{escape(link)}' target='_blank'>{extracto}</a>"
                    return f"<span class='muted'>{extracto}</span>"
                tgrows = "".join(
                    f"<tr><td>{escape(h.get('fuente',''))}</td>"
                    f"<td class='muted'>{escape(h.get('fecha','') or '—')}</td>"
                    f"<td><code>{escape(h.get('variante',''))}</code></td>"
                    f"<td>{_tg_msg_cell(h)}</td></tr>"
                    for h in tg_hits_list[:12]
                )
                c6_section += (
                    f"<p><b>⚠️ {len(tg_hits_list)} mensajes con menciones en canales Telegram públicos:</b></p>"
                    f"<table><thead><tr><th>Canal</th><th>Fecha</th><th>Variante</th><th>Mensaje (enlace)</th></tr></thead>"
                    f"<tbody>{tgrows}</tbody></table>"
                )

            # RansomLook
            rl2_hits = ds_dw.get('ransomlook_hits', [])
            if rl2_hits:
                rl2rows = "".join(
                    f"<tr><td>{escape(h.get('grupo',''))}</td>"
                    f"<td>{escape(h.get('victima','')[:60])}</td>"
                    f"<td class='muted'>{escape(h.get('fecha',''))}</td></tr>"
                    for h in rl2_hits[:5]
                )
                c6_section += (
                    f"<p><b>⚠️ RansomLook: {len(rl2_hits)} víctima(s) encontrada(s):</b></p>"
                    f"<table><thead><tr><th>Grupo</th><th>Víctima</th><th>Fecha</th></tr></thead>"
                    f"<tbody>{rl2rows}</tbody></table>"
                )

            # Pulsedive
            pd_r = (ds_dw.get('pulsedive') or {}).get('risk', '')
            if pd_r and pd_r not in ('none', 'unknown', 'error', ''):
                c6_section += f"<p><b>Pulsedive:</b> riesgo {badge(pd_r, sev_kind(pd_r))}</p>"

            # ── Capa 5: crawling Tor ──────────────────────────────────────────
            c5_section = ""
            analyzed = dw.get('analyzed_threats', [])
            if analyzed:
                arows = "".join(
                    f"<tr><td class='muted'>{escape(a.get('url','')[:60])}</td>"
                    f"<td>{escape(a.get('title','')[:50])}</td>"
                    f"<td>{badge(a.get('threat_level','LOW'), {'HIGH':'crit','MEDIUM':'high','LOW':'low'}.get(a.get('threat_level','LOW'),'unk'))}</td>"
                    f"<td class='muted'>{escape(', '.join(a.get('emails',[])[:2]))}</td></tr>"
                    for a in analyzed[:15]
                )
                c5_section = (
                    f"<h3>🔎 Capa 5 — Crawling .onion profundo</h3>"
                    f"<table><thead><tr><th>URL</th><th>Título</th><th>Riesgo</th><th>Emails</th></tr></thead>"
                    f"<tbody>{arows}</tbody></table>"
                )

            # ── IOCs detectados (extraídos de toda la dark web) ───────────────
            ioc_section = ""
            ioc_data = dw.get('iocs', {}) if isinstance(dw, dict) else {}
            iocs = ioc_data.get('iocs', {}) if isinstance(ioc_data, dict) else {}
            ioc_total = ioc_data.get('total', 0) if isinstance(ioc_data, dict) else 0
            if ioc_total:
                IOC_LABELS = {
                    'emails_dominio': 'Emails del dominio', 'emails': 'Emails',
                    'credenciales': 'Credenciales (user:pass)',
                    'subdominios_objetivo': 'Subdominios del objetivo', 'dominios': 'Dominios',
                    'ips': 'IPv4', 'ipv6': 'IPv6',
                    'md5': 'MD5', 'sha1': 'SHA1', 'sha256': 'SHA256', 'sha512': 'SHA512',
                    'btc': 'BTC', 'eth': 'ETH', 'xmr': 'XMR',
                    'cve': 'CVE', 'onion': 'Servicios .onion',
                }
                counts = ioc_data.get('counts', {})
                chips = "".join(
                    f"<span class='badge unk'>{escape(IOC_LABELS.get(t, t))}: {n}</span> "
                    for t, n in counts.items() if n
                )

                def ioc_table(title, types):
                    rows = []
                    for t in types:
                        for v in iocs.get(t, [])[:50]:
                            rows.append(
                                f"<tr><td class='muted'>{escape(IOC_LABELS.get(t, t))}</td>"
                                f"<td>{escape(str(v))}</td></tr>"
                            )
                    if not rows:
                        return ""
                    return (f"<h4>{title}</h4>"
                            f"<table><thead><tr><th>Tipo</th><th>Valor</th></tr></thead>"
                            f"<tbody>{''.join(rows)}</tbody></table>")

                tablas = (
                    ioc_table("🔑 Credenciales y emails", ['credenciales', 'emails_dominio', 'emails'])
                    + ioc_table("🌐 Dominios e IPs", ['subdominios_objetivo', 'dominios', 'ips', 'ipv6'])
                    + ioc_table("#️⃣ Hashes", ['md5', 'sha1', 'sha256', 'sha512'])
                    + ioc_table("💰 Wallets de criptomoneda", ['btc', 'eth', 'xmr'])
                    + ioc_table("🧅 Otros", ['onion', 'cve'])
                )
                ioc_section = (
                    f"<h3>🔎 IOCs detectados ({ioc_total})</h3>"
                    f"<p>{chips}</p>"
                    f"<p class='muted'>Exportados también a "
                    f"<code>&lt;dominio&gt;_iocs_&lt;fecha&gt;.json</code> / "
                    f"<code>.csv</code>. Se muestran hasta 50 por tipo.</p>"
                    f"{tablas}"
                )

            # ── Pivoting (búsqueda relanzada con los IOCs encontrados) ────────
            pivot_section = ""
            pivot = dw.get('pivoting', {}) if isinstance(dw, dict) else {}
            if isinstance(pivot, dict) and pivot.get('status') == 'success':
                p_seeds = pivot.get('seeds', {})
                p_hits = pivot.get('hits', [])
                seed_chips = "".join(
                    f"<span class='badge unk'>{escape(tipo)}: {len(p_seeds.get(tipo, []))}</span> "
                    for tipo in ('emails', 'credenciales', 'dominios')
                    if p_seeds.get(tipo)
                )
                hit_rows = "".join(
                    f"<tr><td class='muted'>{escape(str(h.get('fuente') or h.get('foro', '')))}</td>"
                    f"<td>{escape(str(h.get('variante') or h.get('termino', '')))}</td>"
                    f"<td>{escape(str(h.get('extracto', ''))[:200])}</td></tr>"
                    for h in p_hits[:30]
                )
                hit_table = (
                    f"<table><thead><tr><th>Fuente</th><th>Semilla</th><th>Extracto</th></tr></thead>"
                    f"<tbody>{hit_rows}</tbody></table>" if hit_rows else
                    "<p class='muted'>Sin hits nuevos al pivotar sobre los IOCs.</p>"
                )
                pivot_section = (
                    f"<h3>🔗 Pivoting sobre IOCs ({pivot.get('total', 0)} hit(s))</h3>"
                    f"<p class='muted'>Búsqueda relanzada usando los IOCs hallados como nuevas "
                    f"queries (profundidad 1). Validación manual recomendada.</p>"
                    f"<p>{seed_chips}</p>{hit_table}"
                )

            # ── Salud de los .onion vigilados (rotación / caídas / bloqueos) ──
            health_section = ""
            onion_health = ds_dw.get('onion_health', []) if isinstance(ds_dw, dict) else []
            if onion_health:
                _hbadge = {"ok": "low", "blocked": "med", "down": "crit"}
                _htxt   = {"ok": "operativo", "blocked": "bloqueado", "down": "caído"}
                _horder = {"down": 0, "blocked": 1, "ok": 2}
                n_down = sum(1 for h in onion_health if h.get('estado') == 'down')
                n_blk  = sum(1 for h in onion_health if h.get('estado') == 'blocked')
                hrows = "".join(
                    f"<tr><td>{escape(str(h.get('servicio', '')))}</td>"
                    f"<td class='muted'>{escape(str(h.get('categoria', '')))}</td>"
                    f"<td><span class='badge {_hbadge.get(h.get('estado'), 'unk')}'>"
                    f"{_htxt.get(h.get('estado'), '?')}</span></td>"
                    f"<td class='muted'>{escape(str(h.get('onion', '')))}</td>"
                    f"<td class='muted'>{escape(str(h.get('nota', '')))}</td></tr>"
                    for h in sorted(onion_health, key=lambda x: _horder.get(x.get('estado'), 3))
                )
                aviso = ""
                if n_down or n_blk:
                    aviso = (
                        f"<p class='muted'>⚠️ {n_down} caído(s) y {n_blk} bloqueado(s). "
                        f"Los .onion rotan con frecuencia: actualiza "
                        f"<code>darkweb_onions.json</code> con las direcciones nuevas "
                        f"(mira las semillas descubiertas más abajo).</p>"
                    )
                health_section = (
                    f"<h3>🩺 Salud de los .onion vigilados ({len(onion_health)})</h3>"
                    f"{aviso}"
                    f"<div class='tablewrap'><table><thead><tr><th>Servicio</th><th>Categoría</th><th>Estado</th>"
                    f"<th>.onion</th><th>Nota</th></tr></thead>"
                    f"<tbody>{hrows}</tbody></table></div>"
                )

            # ── Semillas .onion descubiertas (directorios tipo tortaxi) ───────
            seeds_section = ""
            onion_seeds = ds_dw.get('onion_seeds', []) if isinstance(ds_dw, dict) else []
            if onion_seeds:
                seed_rows = "".join(
                    f"<tr><td>{escape(str(s.get('onion', '')))}</td>"
                    f"<td>{escape(str(s.get('titulo', '')))}</td>"
                    f"<td class='muted'>{escape(str(s.get('fuente', '')))}</td></tr>"
                    for s in onion_seeds[:60]
                )
                seeds_section = (
                    f"<h3>🌱 Semillas .onion descubiertas ({len(onion_seeds)})</h3>"
                    f"<div class='help'>📚 <b>¿Qué es esto?</b> Algunos directorios de la dark web "
                    f"(tipo <i>The Hidden Wiki</i>) listan servicios <code>.onion</code> activos. "
                    f"Aquí guardamos los que aparecen en esos directorios para tener un catálogo de "
                    f"direcciones actualizadas — los <code>.onion</code> cambian de dirección a menudo, "
                    f"y así podemos refrescar los <i>leak sites</i> que vigilamos en "
                    f"<code>darkweb_onions.json</code> cuando caen o rotan.<br>"
                    f"⚠️ <b>No</b> son menciones de <b>{escape(domain)}</b>: es material de "
                    f"<b>descubrimiento</b>, no una alerta sobre tu dominio.</div>"
                    f"<div class='tablewrap'><table><thead><tr><th>.onion</th><th>Título</th><th>Fuente</th></tr></thead>"
                    f"<tbody>{seed_rows}</tbody></table></div>"
                )

            dw_section = (
                f"<section id=\"darkweb\"><h2>🛡️ Exposición &amp; Dark Web</h2>"
                f"{overview}"
                f"{c1_section}{c2_section}{c3_section}{c4_section}{c6_section}{c5_section}"
                f"{ioc_section}{pivot_section}{health_section}{seeds_section}"
                f"</section>"
            )

        # ---- Grafo de entidades + confidence scoring ----
        entities_section = ""
        ent = threat_data.get('entities', {})
        if isinstance(ent, dict) and ent.get('entities'):
            st = ent.get('stats', {})
            bg = st.get('by_grade', {})
            bt = st.get('by_type', {})
            _gbadge = {"A": "low", "B": "med", "C": "high", "D": "unk"}
            _glabel = {"A": "A · confirmado", "B": "B · verificado",
                       "C": "C · una fuente", "D": "D · inferencia"}
            grade_chips = "".join(
                f"<span class='badge {_gbadge.get(gr, 'unk')}'>{_glabel[gr]}: {bg.get(gr, 0)}</span> "
                for gr in ('A', 'B', 'C', 'D') if bg.get(gr)
            )
            type_chips = "".join(
                f"<span class='badge unk'>{escape(t)}: {n}</span> "
                for t, n in sorted(bt.items(), key=lambda x: -x[1])
            )
            def _visto(e):
                # 🆕 si es nueva en este escaneo; si no, desde cuándo se conoce.
                if e.get('is_new'):
                    return "<span class='badge low'>🆕 nuevo</span>"
                fs = escape(str(e.get('first_seen', ''))[:10])
                runs = e.get('runs', 0)
                run_txt = f" ·{runs}×" if runs else ""
                return f"<span class='muted'>{fs}{run_txt}</span>" if fs else "<span class='muted'>—</span>"

            ent_rows = "".join(
                f"<tr><td class='muted'>{escape(str(e.get('type', '')))}</td>"
                f"<td>{escape(str(e.get('value', ''))[:90])}</td>"
                f"<td><span class='badge {_gbadge.get(e.get('grade'), 'unk')}'>"
                f"{escape(str(e.get('grade', '')))}</span></td>"
                f"<td>{_visto(e)}</td>"
                f"<td class='muted'>{e.get('n_sources', 0)}</td>"
                f"<td class='muted'>{escape(', '.join(e.get('sources', []))[:120])}</td></tr>"
                for e in ent['entities'][:120]
            )
            # Chip de memoria entre escaneos (solo si intel.db enriqueció el grafo).
            mem_chip = ""
            if 'new_entities' in st or 'seen_before' in st:
                mem_chip = (
                    f"<p><span class='badge low'>🆕 nuevas: {st.get('new_entities', 0)}</span> "
                    f"<span class='badge unk'>↻ ya conocidas: {st.get('seen_before', 0)}</span></p>"
                )
            extra = ""
            if st.get('total', 0) > 120:
                extra = (f"<p class='muted'>Mostrando 120 de {st.get('total', 0)} entidades "
                         f"(ordenadas por confianza). Todas en el JSON.</p>")

            # ── Grafo visual interactivo (vis-network) ────────────────────────
            # Se dibuja DENTRO del propio .html: nodos = entidades, aristas =
            # relaciones, color = grado de confianza. La librería se carga por
            # CDN; si no hay conexión, aparece un aviso y queda la tabla de abajo
            # (que tiene los mismos datos). Cap de nodos para que sea fluido.
            GRAPH_CAP = 250
            _gcolor = {"A": "#3fb950", "B": "#58a6ff", "C": "#d29922", "D": "#8b949e"}
            ents_g = ent['entities'][:GRAPH_CAP]
            id_of, nodes_g = {}, []
            for i, e in enumerate(ents_g):
                key = (e.get('type', ''), e.get('value', ''))
                id_of[key] = i
                nodes_g.append({
                    "id": i,
                    "label": str(e.get('value', ''))[:26],
                    "title": f"{e.get('type','')}: {e.get('value','')} · grado "
                             f"{e.get('grade','?')} · {e.get('n_sources',0)} fuente(s)",
                    "color": _gcolor.get(e.get('grade'), "#8b949e"),
                    "group": e.get('type', ''),
                    # Texto completo (sin truncar) para el buscador del grafo.
                    "search": f"{e.get('type','')} {e.get('value','')}".lower(),
                })
            edges_g = []
            for r in ent.get('relations', []) or []:
                fk = (r.get('from', {}).get('type', ''), r.get('from', {}).get('value', ''))
                tk = (r.get('to', {}).get('type', ''), r.get('to', {}).get('value', ''))
                if fk in id_of and tk in id_of:
                    edges_g.append({"from": id_of[fk], "to": id_of[tk],
                                    "label": str(r.get('rel', '')), "arrows": "to"})

            graph_block = ""
            if len(nodes_g) >= 2:
                # Evitar que un valor con "</script>" rompa el documento.
                nodes_json = json.dumps(nodes_g, ensure_ascii=False).replace("</", "<\\/")
                edges_json = json.dumps(edges_g, ensure_ascii=False).replace("</", "<\\/")
                cap_txt = (f" (mostrando {len(nodes_g)} de {st.get('total', 0)} entidades)"
                           if st.get('total', 0) > len(nodes_g) else "")
                graph_block = (
                    "<div class='help'>🕸️ <b>¿Para qué sirve este grafo?</b> Es un mapa visual "
                    "de cómo se relacionan los hallazgos: cada <b>punto</b> es una entidad "
                    "(un subdominio, una IP, una tecnología, un email…) y cada <b>línea</b> une "
                    "entidades relacionadas (p. ej. un subdominio que resuelve a una IP). "
                    "El <b>color</b> indica la confianza: "
                    "<span style='color:#3fb950'>■</span> A (confirmado) · "
                    "<span style='color:#58a6ff'>■</span> B (verificado) · "
                    "<span style='color:#d29922'>■</span> C (una fuente) · "
                    "<span style='color:#8b949e'>■</span> D (inferencia). "
                    "Pasa el ratón por un punto para ver el detalle.<br>"
                    "🖱️ <b>Cómo moverse:</b> <b>arrastra</b> un punto para moverlo, "
                    "arrastra el fondo para desplazarte y haz <b>pellizco (pinch) "
                    "en el trackpad</b> o <b>Ctrl/⌘ + scroll</b> sobre el grafo para "
                    "acercar/alejar (el scroll normal sigue moviendo la página). "
                    "También tienes los botones <b>＋ / −</b> de aquí abajo. "
                    "<b>Haz clic</b> en un punto para resaltar solo sus conexiones.</div>"
                    f"<p class='muted'>{cap_txt.strip() or 'Grafo interactivo de entidades.'}</p>"
                    "<input id='entgraph_q' class='gsearch' type='search' "
                    "autocomplete='off' placeholder='🔎 Buscar entidad (subdominio, IP, email, tecnología…)' "
                    "oninput='entgraphSearch(this.value)'>"
                    "<div class='gtoolbar'>"
                    "<button type='button' onclick='entgraphZoom(1.3)'>＋ Acercar</button>"
                    "<button type='button' onclick='entgraphZoom(0.77)'>− Alejar</button>"
                    "<button type='button' onclick='entgraphFit()'>⤢ Ajustar todo</button>"
                    "</div>"
                    "<div id='entgraph' style='height:520px;border:1px solid var(--border);"
                    "border-radius:8px;background:var(--panel2);margin:8px 0;'>"
                    "<p style='padding:1em;color:#8b949e'>Cargando grafo…</p></div>"
                    + _vis_network_loader() +
                    "<script>(function(){var c=document.getElementById('entgraph');"
                    "if(!window.vis){c.innerHTML="
                    "'<p style=\"padding:1em;color:#8b949e\">No se pudo cargar la librería del "
                    "grafo. La tabla de abajo tiene exactamente los mismos datos.</p>';"
                    "return;}c.innerHTML='';"
                    f"var nodes=new vis.DataSet({nodes_json});"
                    f"var edges=new vis.DataSet({edges_json});"
                    # Copia de los datos originales para poder restaurar colores
                    # tras resaltar las conexiones de un nodo.
                    "var baseNodes=nodes.get();var baseEdges=edges.get();"
                    "var EDGE_ON={color:'#2d3543',highlight:'#58a6ff'};"
                    "var net=new vis.Network(c,{nodes:nodes,edges:edges},{"
                    "nodes:{shape:'dot',size:12,font:{color:'#e6edf3',size:12}},"
                    "edges:{color:EDGE_ON,"
                    "font:{color:'#8b949e',size:10,strokeWidth:0},smooth:false},"
                    "physics:{stabilization:true,barnesHut:{gravitationalConstant:-8000,"
                    "springLength:120}},"
                    # dragNodes/dragView ON; zoomView OFF para no secuestrar el scroll
                    # de la página. El zoom va por pinch (Ctrl/⌘+wheel) y por botones.
                    "interaction:{hover:true,tooltipDelay:120,dragNodes:true,"
                    "dragView:true,zoomView:false}});"
                    "net.once('stabilizationIterationsDone',function(){net.fit();});"
                    # Zoom anclado al cursor: el punto bajo el puntero se queda fijo.
                    "function zoomAt(p,f){var b=net.DOMtoCanvas(p);"
                    "var s=Math.min(Math.max(net.getScale()*f,0.15),5);"
                    "net.moveTo({scale:s});var a=net.DOMtoCanvas(p);"
                    "var v=net.getViewPosition();"
                    "net.moveTo({scale:s,position:{x:v.x+(b.x-a.x),y:v.y+(b.y-a.y)}});}"
                    # Pinch del trackpad (y Ctrl/⌘+rueda) llegan como 'wheel' con
                    # ctrlKey/metaKey=true. Solo entonces hacemos zoom y bloqueamos
                    # el scroll; el scroll de dos dedos normal mueve la página.
                    "c.addEventListener('wheel',function(e){"
                    "if(e.ctrlKey||e.metaKey){e.preventDefault();"
                    "var r=c.getBoundingClientRect();"
                    "zoomAt({x:e.clientX-r.left,y:e.clientY-r.top},e.deltaY<0?1.12:0.892);}"
                    "},{passive:false});"
                    # Clic en un nodo: resalta él y sus vecinos, atenúa el resto.
                    "function restore(){nodes.update(baseNodes.map(function(n){"
                    "return{id:n.id,color:n.color};}));"
                    "edges.update(baseEdges.map(function(ed){"
                    "return{id:ed.id,color:EDGE_ON};}));}"
                    "net.on('selectNode',function(p){var sel=p.nodes[0];"
                    "var keep=net.getConnectedNodes(sel);keep.push(sel);"
                    "var ke=net.getConnectedEdges(sel);"
                    "nodes.update(baseNodes.map(function(n){return{id:n.id,"
                    "color:keep.indexOf(n.id)>=0?n.color:'rgba(139,148,158,0.12)'};}));"
                    "edges.update(baseEdges.map(function(ed){return{id:ed.id,"
                    "color:ke.indexOf(ed.id)>=0?{color:'#58a6ff'}:"
                    "{color:'rgba(45,53,67,0.18)'}};}));});"
                    "net.on('deselectNode',restore);"
                    # Buscador: resalta las entidades que coinciden y atenúa el resto,
                    # encuadrando el grafo sobre los aciertos. Sin texto, restaura todo.
                    "window.entgraphSearch=function(q){q=(q||'').trim().toLowerCase();"
                    "if(!q){restore();return;}"
                    "var on={},hit=[];baseNodes.forEach(function(n){"
                    "if((n.search||String(n.label).toLowerCase()).indexOf(q)>=0){on[n.id]=1;hit.push(n.id);}});"
                    "nodes.update(baseNodes.map(function(n){return{id:n.id,"
                    "color:on[n.id]?n.color:'rgba(139,148,158,0.10)'};}));"
                    "edges.update(baseEdges.map(function(ed){return{id:ed.id,"
                    "color:(on[ed.from]&&on[ed.to])?{color:'#58a6ff'}:"
                    "{color:'rgba(45,53,67,0.12)'}};}));"
                    "if(hit.length){net.selectNodes(hit);"
                    "net.fit({nodes:hit,animation:true});}};"
                    "window.entgraphZoom=function(f){var r=c.getBoundingClientRect();"
                    "zoomAt({x:r.width/2,y:r.height/2},f);};"
                    "window.entgraphFit=function(){var q=document.getElementById('entgraph_q');"
                    "if(q)q.value='';restore();net.unselectAll();net.fit({animation:true});};"
                    "})();</script>"
                )

            entities_section = (
                f"<section id=\"entidades\"><h2>🕸️ Entidades correlacionadas ({st.get('total', 0)})</h2>"
                f"<p class='muted'>Todo lo hallado, normalizado a entidades con un "
                f"<b>grado de confianza</b> según cuántas fuentes (y de qué fiabilidad) lo "
                f"corroboran. {st.get('relations', 0)} relaciones detectadas.</p>"
                f"<p>{grade_chips}</p><p>{type_chips}</p>{mem_chip}"
                f"{graph_block}"
                f"<table><thead><tr><th>Tipo</th><th>Valor</th><th>Confianza</th>"
                f"<th>Visto</th><th>#Fuentes</th><th>Fuentes</th></tr></thead>"
                f"<tbody>{ent_rows}</tbody></table>{extra}"
            )

        whois = discovery_data.get('whois', {})
        whois_html = "".join(
            f"<tr><td><b>{escape(k)}</b></td><td>{escape(str(v)[:120])}</td></tr>"
            for k, v in whois.items() if k != 'error'
        )

        # ---- Threat Intelligence (Shodan, VirusTotal, AbuseIPDB, AlienVault, Hunter) ----
        ti = threat_data  # alias
        ti_rows = ""

        # VirusTotal
        vt = ti.get('virustotal', {})
        if vt.get('status') == 'ok':
            stats = vt.get('last_analysis_stats', {})
            mal   = stats.get('malicious', 0)
            sus   = stats.get('suspicious', 0)
            harm  = stats.get('harmless', 0)
            rep   = vt.get('reputation', 0)
            vt_badge = badge(f"{mal} malicioso(s)", "crit") if mal > 0 else badge("limpio", "low")
            ti_rows += (
                f"<tr><td><b>VirusTotal</b></td>"
                f"<td>{vt_badge} &nbsp; "
                f"{badge(f'{sus} sospechoso(s)', 'high') if sus else ''} "
                f"Reputación: <b>{escape(str(rep))}</b> · "
                f"{harm} sin detecciones</td></tr>"
            )

        # Shodan / InternetDB
        sh = ti.get('shodan', {})
        if sh.get('status') == 'ok':
            ports = sh.get('ports', [])
            vulns = sh.get('vulnerabilities', [])
            hosts = sh.get('hostnames', [])
            sh_ports = ", ".join(str(p) for p in ports[:20]) or "ninguno"
            sh_vulns = "".join(badge(v, "crit") + " " for v in vulns[:8]) if vulns else badge("0 CVEs conocidos", "low")
            ti_rows += (
                f"<tr><td><b>Shodan / InternetDB</b></td>"
                f"<td>Puertos abiertos: <code>{escape(sh_ports)}</code> · "
                f"CVEs expuestos: {sh_vulns}"
                + (f" · Hostnames: {escape(', '.join(hosts[:3]))}" if hosts else "")
                + "</td></tr>"
            )

        # AbuseIPDB
        ab = ti.get('abuseipdb', {})
        if ab.get('status') == 'ok':
            score = ab.get('abuse_score', 0)
            reports = ab.get('total_reports', 0)
            country = ab.get('country', '')
            ab_badge = badge(f"Score: {score}%", "crit" if score > 25 else ("high" if score > 5 else "low"))
            ti_rows += (
                f"<tr><td><b>AbuseIPDB</b></td>"
                f"<td>{ab_badge} · {escape(str(reports))} reporte(s) · País: {escape(country)}</td></tr>"
            )

        # AlienVault OTX
        av = ti.get('alienvault', {})
        if av.get('status') == 'ok':
            pulses = av.get('pulse_count', 0)
            rep_av = av.get('reputation', 'N/A')
            av_badge = badge(f"{pulses} pulse(s)", "crit" if pulses > 0 else "low")
            ti_rows += (
                f"<tr><td><b>AlienVault OTX</b></td>"
                f"<td>{av_badge} · Reputación: {escape(str(rep_av))}</td></tr>"
            )

        # Hunter.io
        hu = ti.get('hunter', {})
        if hu.get('status') == 'ok':
            total_emails = hu.get('total_emails', 0)
            email_list   = [e.get('value', '') for e in hu.get('emails', [])[:8]]
            hu_badge = badge(f"{total_emails} email(s)", "med" if total_emails > 0 else "low")
            emails_str = ", ".join(f"<code>{escape(e)}</code>" for e in email_list) or "—"
            ti_rows += (
                f"<tr><td><b>Hunter.io</b></td>"
                f"<td>{hu_badge} descubiertos públicamente: {emails_str}</td></tr>"
            )

        # URLScan
        us = ti.get('urlscan', {})
        if us.get('status') == 'ok':
            total_us = us.get('total', 0)
            us_badge = badge(f"{total_us} escaneo(s) histórico(s)", "med" if total_us > 10 else "low")
            ti_rows += f"<tr><td><b>urlscan.io</b></td><td>{us_badge}</td></tr>"

        ti_section = (
            f"<section><h2>🛰️ Threat Intelligence</h2>"
            f"<table><thead><tr><th>Fuente</th><th>Resultado</th></tr></thead>"
            f"<tbody>{ti_rows}</tbody></table></section>"
        ) if ti_rows else ""

        # ---- Sección SOCRadar ----
        socradar_section = ""
        sr = threat_data.get('socradar', {})
        if isinstance(sr, dict) and sr.get('status') == 'success':
            ov = sr.get('overview', {}) or {}
            asm = sr.get('asm', {}) or {}
            creds = ov.get('credits', {}) or {}

            # Cabecera: plan + créditos
            cred_chips = "".join(
                f"<span class='badge {'low' if v else 'unk'}'>{escape(k)}: {escape(str(v))}</span> "
                for k, v in creds.items()
            )
            head = (
                f"<p class='muted'>Plan <b>{escape(str(ov.get('plan', '—')))}</b> "
                f"({escape(str(ov.get('subscription_status', '')))}, caduca {escape(str(ov.get('expire_date', '—')))}) "
                f"· empresa <b>{escape(str(ov.get('company_name', '')))}</b> "
                f"· créditos gastados en este escaneo: <b>{sr.get('credits_spent', 0)}</b></p>"
                f"<p>Saldo de créditos: {cred_chips or '—'}</p>"
            )

            # ASM: activos por tipo + listas clave
            asm_html = ""
            if asm.get('status') == 'ok':
                by_rows = "".join(
                    f"<tr><td>{escape(t)}</td><td>{escape(str(n))}</td></tr>"
                    for t, n in asm.get('by_type', {}).items()
                )
                def _lista(items, lim=40):
                    if not items:
                        return "<span class='muted'>—</span>"
                    extra = f" <span class='muted'>… +{len(items) - lim}</span>" if len(items) > lim else ""
                    return ", ".join(f"<code>{escape(x)}</code>" for x in items[:lim]) + extra
                asm_html = (
                    f"<h3>🛰️ ASM — Activos descubiertos: {asm.get('total', 0)} "
                    f"<span class='muted'>(mostrados {asm.get('fetched', 0)})</span></h3>"
                    f"<div class='tablewrap'><table><thead><tr><th>Tipo de activo</th><th>Nº</th></tr></thead>"
                    f"<tbody>{by_rows}</tbody></table></div>"
                    f"<p><b>Dominios/subdominios:</b> {_lista(asm.get('domains', []))}</p>"
                    f"<p><b>Webs:</b> {_lista(asm.get('websites', []))}</p>"
                    f"<p><b>IPs:</b> {_lista(asm.get('ips', []))}</p>"
                    f"<p><b>Tecnologías:</b> {_lista(asm.get('technologies', []), lim=60)}</p>"
                )

            # Dark web (company) + vulns + incidentes
            dw_sr = sr.get('dark_web', {}) or {}
            vul_sr = sr.get('vulnerabilities', {}) or {}
            inc_sr = sr.get('incidents', {}) or {}
            dw_html = f"<h3>🌑 Dark Web (monitorización de la empresa): {dw_sr.get('total', 0)} hallazgo(s)</h3>"
            if dw_sr.get('findings'):
                fr = "".join(
                    f"<tr><td class='muted'>{escape(str(f)[:200])}</td></tr>"
                    for f in dw_sr.get('findings', [])[:20]
                )
                dw_html += f"<div class='tablewrap'><table><tbody>{fr}</tbody></table></div>"
            else:
                dw_html += "<p class='muted'>✅ Sin hallazgos de dark web para la empresa en este momento.</p>"

            extra_html = (
                f"<p><b>Vulnerabilidades (ASM):</b> {vul_sr.get('total', 0)} · "
                f"<b>Incidentes abiertos:</b> {inc_sr.get('total', 0)}</p>"
            )

            # Identity Intelligence (si se gastaron créditos)
            ident_html = ""
            ident = sr.get('identity_intelligence')
            if ident and ident.get('results'):
                hits = [r for r in ident['results'] if isinstance(r, dict) and r.get('status') == 'ok']
                ident_html = (
                    f"<h3>🪪 Identity Intelligence <span class='muted'>(consume créditos)</span></h3>"
                    f"<p class='muted'>{len(hits)} objetivo(s) consultado(s).</p>"
                )

            socradar_section = (
                f"<section id='socradar'><h2>🛰️ SOCRadar — Inteligencia externa</h2>"
                f"{head}{asm_html}{dw_html}{extra_html}{ident_html}</section>"
            )
        elif isinstance(sr, dict) and sr.get('status') in ('error', 'no_api_key'):
            socradar_section = (
                f"<section id='socradar'><h2>🛰️ SOCRadar</h2>"
                f"<p class='muted'>{escape(str(sr.get('message', 'no disponible')))}</p></section>"
            )

        html = _HTML_TEMPLATE.format(
            domain=escape(domain),
            ip=escape(str(threat_data.get('ip_address', 'N/D'))),
            ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            cards=cards_html,
            summary=summary_html,
            alert=alert_html,
            diag=diag_html,
            sub_rows=sub_rows or "<tr><td colspan=4 class='muted'>Sin subdominios</td></tr>",
            sub_total=discovery_data.get('total_subdomains', 0),
            dns_rows=dns_rows or "<tr><td colspan=2 class='muted'>Sin registros</td></tr>",
            whois_rows=whois_html or "<tr><td colspan=2 class='muted'>No disponible</td></tr>",
            ti_section=ti_section,
            tech_rows=tech_rows or "<tr><td colspan=2 class='muted'>Sin datos (fingerprinting omitido o sin resultados)</td></tr>",
            cve_section=cve_section,
            ew_section=ew_section,
            dw_section=dw_section,
            socradar_section=socradar_section,
            entities_section=entities_section,
        )
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[✓] Informe HTML guardado en: {filename}")
        return filename