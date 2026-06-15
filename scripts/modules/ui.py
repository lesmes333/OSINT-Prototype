#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capa de interfaz de usuario para terminal.

Usa la librería `rich` para ofrecer una salida visual y agradable (paneles,
tablas con colores, severidades coloreadas, barras de progreso). Si `rich` no
está instalada, todo degrada con elegancia a texto plano, de modo que la
herramienta sigue funcionando.
"""

from typing import Dict, List, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich import box

    _RICH = True
    console = Console()
except Exception:  # pragma: no cover
    _RICH = False
    console = None


# Colores por severidad (consistentes en toda la herramienta)
SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}
SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}


def enabled() -> bool:
    return _RICH


# ============================================================
# Mensajes simples
# ============================================================
def _plain(msg):
    print(msg)


def info(msg: str):
    if _RICH:
        console.print(msg)
    else:
        _plain(msg)


def success(msg: str):
    if _RICH:
        console.print(f"[bold green]✓[/] {msg}")
    else:
        _plain(f"[OK] {msg}")


def warn(msg: str):
    if _RICH:
        console.print(f"[bold yellow]⚠[/] {msg}")
    else:
        _plain(f"[!] {msg}")


def error(msg: str):
    if _RICH:
        console.print(f"[bold red]✗[/] {msg}")
    else:
        _plain(f"[X] {msg}")


def rule(title: str = ""):
    if _RICH:
        console.rule(f"[bold cyan]{title}")
    else:
        _plain("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


# ============================================================
# Banner
# ============================================================
CREDIT = "Created by Cristian & Luisber"


def banner():
    title = "OSINT RECON SUITE"
    subtitle = "Descubrimiento pasivo · Threat Intel · Fingerprint · CVEs · INCIBE-CERT · Dark Web"
    if _RICH:
        art = Text()
        art.append("\n  ███████ ███████ ██ ███    ██ ████████\n", style="bold cyan")
        art.append("  ██   ██ ██      ██ ████   ██    ██   \n", style="bold cyan")
        art.append("  ██   ██ ███████ ██ ██ ██  ██    ██   \n", style="bold blue")
        art.append("  ██   ██      ██ ██ ██  ██ ██    ██   \n", style="bold blue")
        art.append("  ███████ ███████ ██ ██   ████    ██   \n", style="bold magenta")
        art.append(f"\n  ★ {CREDIT} ★\n", style="bold yellow")
        body = Align.center(art)
        console.print(
            Panel(
                body,
                title=f"[bold white]{title}[/]",
                subtitle=f"[dim]{subtitle}[/]",
                border_style="cyan",
                box=box.DOUBLE,
                padding=(0, 2),
            )
        )
    else:
        _plain("=" * 78)
        _plain(f"  {title}")
        _plain(f"  {subtitle}")
        _plain(f"  ★ {CREDIT} ★")
        _plain("=" * 78)


def phase(number: str, title: str, desc: str = ""):
    """Cabecera de fase destacada."""
    if _RICH:
        text = f"[bold white]{number}[/]  [bold cyan]{title}[/]"
        if desc:
            text += f"\n[dim]{desc}[/]"
        console.print(Panel(text, border_style="blue", box=box.ROUNDED, padding=(0, 2)))
    else:
        _plain("\n" + "=" * 70)
        _plain(f"{number}  {title}")
        if desc:
            _plain(desc)
        _plain("=" * 70)


def domain_header(domain: str, idx: int, total: int):
    if _RICH:
        console.print(
            Panel(
                Align.center(f"[bold white]🎯 {domain}[/]"),
                subtitle=f"[dim]objetivo {idx}/{total}[/]",
                border_style="magenta",
                box=box.HEAVY,
                padding=(0, 2),
            )
        )
    else:
        _plain(f"\n########## [{idx}/{total}] {domain} ##########")


# ============================================================
# Tablas de resultados
# ============================================================
def table_subdomains(subdomains: List[str], sources: Dict, activos: Dict, limit: int = 40):
    if not subdomains:
        warn("No se encontraron subdominios.")
        return
    estado_por_host = {
        r["host"]: r for r in activos.get("resultados_detallados", [])
    }
    if _RICH:
        t = Table(title=f"🌐 Subdominios ({len(subdomains)})", box=box.SIMPLE_HEAVY, header_style="bold cyan")
        t.add_column("#", justify="right", style="dim", width=4)
        t.add_column("Subdominio", style="white")
        t.add_column("Estado", justify="center")
        t.add_column("Fuentes", style="dim")
        for i, sub in enumerate(subdomains[:limit], 1):
            est = estado_por_host.get(sub, {})
            estado = est.get("estado", "")
            if estado == "ACTIVA":
                metodo = est.get("metodo_deteccion", "")
                estado_cell = Text(f"● activo ({metodo})", style="green")
            elif estado:
                estado_cell = Text("○ inactivo", style="red dim")
            else:
                estado_cell = Text("—", style="dim")
            src = ", ".join(sources.get(sub, []))
            t.add_row(str(i), sub, estado_cell, src)
        console.print(t)
        if len(subdomains) > limit:
            console.print(f"[dim]  … y {len(subdomains) - limit} más (ver informe completo)[/]")
    else:
        _plain(f"\nSubdominios ({len(subdomains)}):")
        for i, sub in enumerate(subdomains[:limit], 1):
            est = estado_por_host.get(sub, {}).get("estado", "")
            _plain(f"  {i:>3}. {sub}  [{est or '—'}]")


def table_dns(dns_records: Dict):
    rows = [(k, v) for k, v in dns_records.items() if v]
    if not rows:
        return
    if _RICH:
        t = Table(title="🔍 Registros DNS", box=box.SIMPLE, header_style="bold cyan")
        t.add_column("Tipo", style="bold yellow", width=8)
        t.add_column("Valores", style="white")
        for k, v in rows:
            t.add_row(k, ", ".join(str(x) for x in v[:5]))
        console.print(t)
    else:
        _plain("\nDNS:")
        for k, v in rows:
            _plain(f"  {k}: {', '.join(str(x) for x in v[:5])}")


def table_changes(diff: Dict):
    """Muestra los cambios respecto al escaneo anterior (modo monitorización)."""
    if not isinstance(diff, dict) or diff.get("status") != "ok":
        return
    if not diff.get("hay_cambios"):
        _plain("📋 Sin cambios respecto al escaneo anterior.") if not _RICH else \
            console.print("[dim]📋 Sin cambios respecto al escaneo anterior.[/]")
        return

    secciones = [
        ("🆕 Subdominios nuevos", diff.get("subdominios_nuevos", []), "bold green"),
        ("➖ Subdominios desaparecidos", diff.get("subdominios_eliminados", []), "yellow"),
        ("🔴 CVEs nuevos", diff.get("cves_nuevos", []), "bold red"),
        ("🔌 Puertos nuevos", diff.get("puertos_nuevos", []), "bold magenta"),
    ]
    ref = diff.get("previo_timestamp", "")
    if _RICH:
        t = Table(title=f"🔁 Cambios desde el último escaneo ({ref})", box=box.SIMPLE_HEAVY, header_style="bold cyan")
        t.add_column("Cambio", style="white")
        t.add_column("Elementos", style="white")
        for titulo, items, estilo in secciones:
            if items:
                t.add_row(Text(titulo, style=estilo), ", ".join(items[:30]))
        console.print(t)
    else:
        _plain(f"\nCambios desde el último escaneo ({ref}):")
        for titulo, items, _ in secciones:
            if items:
                _plain(f"  {titulo}: {', '.join(items[:30])}")


def table_technologies(fp: Dict):
    results = fp.get("results", []) if isinstance(fp, dict) else []
    if not results:
        return
    por_url: Dict[str, set] = {}
    for item in results:
        url = item.get("url", "")
        tech = item.get("technology", "")
        ver = item.get("version", "")
        label = f"{tech} {ver}".strip() if ver and ver != "N/A" else tech
        por_url.setdefault(url, set()).add(label)
    if _RICH:
        t = Table(title=f"🧬 Tecnologías detectadas ({len(results)})", box=box.SIMPLE_HEAVY, header_style="bold cyan")
        t.add_column("URL", style="blue", no_wrap=False)
        t.add_column("Tecnologías", style="white")
        for url, techs in list(por_url.items())[:30]:
            t.add_row(url, ", ".join(sorted(techs)))
        console.print(t)
    else:
        _plain("\nTecnologías:")
        for url, techs in por_url.items():
            _plain(f"  {url}: {', '.join(sorted(techs))}")


def _sev_cell(severity: str):
    severity = (severity or "UNKNOWN").upper()
    if _RICH:
        return Text(f"{SEV_ICON.get(severity, '⚪')} {severity}", style=SEV_STYLE.get(severity, "dim"))
    return f"{SEV_ICON.get(severity, '')} {severity}"


def table_cves(vuln: Dict):
    results = vuln.get("results", []) if isinstance(vuln, dict) else []
    if not results:
        return
    if _RICH:
        t = Table(
            title=f"🚨 Vulnerabilidades (CVEs): {vuln.get('total_cves', 0)} "
            f"· exploits: {vuln.get('total_exploits', 0)} · INCIBE: {vuln.get('incibe_refs', 0)}",
            box=box.SIMPLE_HEAVY,
            header_style="bold red",
        )
        t.add_column("CVE", style="bold")
        t.add_column("Severidad", justify="center")
        t.add_column("Tecnología", style="cyan")
        t.add_column("Exploit", justify="center")
        t.add_column("INCIBE-CERT", justify="center")
        # Ordenar por severidad
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        flat = []
        for tech in results:
            for cve in tech["cves"]:
                flat.append((tech, cve))
        flat.sort(key=lambda x: order.get((x[1].get("severity") or "UNKNOWN").upper(), 4))
        for tech, cve in flat[:40]:
            exploit = Text("⚔ sí", style="bold red") if cve.get("exploit_available") else Text("no", style="dim")
            inc = cve.get("incibe", {}) or {}
            if inc.get("disponible") and inc.get("en_alerta_temprana"):
                inc_cell = Text("⚠ alerta", style="bold yellow")
            elif inc.get("disponible"):
                inc_cell = Text("✓ ficha", style="green")
            else:
                inc_cell = Text("—", style="dim")
            t.add_row(
                cve.get("id", "N/A"),
                _sev_cell(cve.get("severity")),
                f"{tech['technology']} {tech['version']}",
                exploit,
                inc_cell,
            )
        console.print(t)
        early = vuln.get("incibe_early_warning", [])
        if early:
            console.print(
                f"[bold yellow]🇪🇸 INCIBE-CERT alerta temprana:[/] "
                f"{len(early)} vulnerabilidad(es) reciente(s) mencionan tecnologías detectadas."
            )
    else:
        _plain(f"\nCVEs ({vuln.get('total_cves', 0)}):")
        for tech in results:
            for cve in tech["cves"]:
                inc = (cve.get("incibe", {}) or {}).get("url", "")
                _plain(f"  {cve.get('id')} [{cve.get('severity')}] {tech['technology']}  INCIBE:{inc}")


def table_exposure(dw: Dict):
    """Resumen de la monitorización de exposición y filtraciones (Fase 4)."""
    if not isinstance(dw, dict) or dw.get("status") != "success":
        return
    summary = dw.get("summary", {})
    breaches = dw.get("breaches", {})
    ahmia = dw.get("ahmia", {})
    pastes = dw.get("pastes", {})
    nivel = summary.get("nivel_exposicion", "LOW")
    nivel_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}.get(nivel, "dim")

    if _RICH:
        console.print(f"[bold]🛡️  Exposición:[/] nivel ", end="")
        console.print(Text(nivel, style=nivel_style))
        t = Table(title="Monitorización de exposición y filtraciones", box=box.SIMPLE, header_style="bold magenta")
        t.add_column("Capa", style="cyan")
        t.add_column("Hallazgos", style="white")
        t.add_row("Brechas de datos",
                  f"{breaches.get('compromised_emails', 0)} email(s) comprometido(s) "
                  f"de {breaches.get('checked_emails', 0)} revisados")
        t.add_row("Índice dark web (Ahmia)", f"{ahmia.get('total', 0)} mención(es) en .onion")
        t.add_row("Paste sites (PSBDMP)", f"{pastes.get('total', 0)} paste(s)")
        if dw.get("tor", {}).get("status") == "success":
            t.add_row("Tor (.onion crawl)", f"{len(dw.get('analyzed_threats', []))} analizado(s)")
        console.print(t)

        # Detalle de emails comprometidos (lo más accionable)
        comprometidos = [r for r in breaches.get("results", []) if r.get("found")]
        if comprometidos:
            bt = Table(title="📧 Correos en filtraciones", box=box.SIMPLE, header_style="bold red")
            bt.add_column("Email", style="yellow")
            bt.add_column("Brechas", style="white")
            for r in comprometidos[:15]:
                bt.add_row(r.get("email", ""), ", ".join(r.get("breaches", [])[:6]))
            console.print(bt)
    else:
        _plain(f"\nExposición: nivel {nivel} | "
               f"{breaches.get('compromised_emails', 0)} emails comprometidos | "
               f"{ahmia.get('total', 0)} .onion | {pastes.get('total', 0)} pastes")


def table_darkweb(dw: Dict):
    if not isinstance(dw, dict) or dw.get("status") != "success":
        return
    analyzed = dw.get("analyzed_threats", [])
    if _RICH:
        console.print(f"[bold]🌑 Dark Web:[/] {dw.get('total_links_found', 0)} enlaces .onion encontrados")
        if analyzed:
            t = Table(title="Análisis de amenazas (.onion)", box=box.SIMPLE, header_style="bold magenta")
            t.add_column("URL", style="blue")
            t.add_column("Título", style="white")
            t.add_column("Riesgo", justify="center")
            for a in analyzed:
                lvl = a.get("threat_level", "LOW")
                style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}.get(lvl, "dim")
                t.add_row(a.get("url", "")[:50], a.get("title", "")[:40], Text(lvl, style=style))
            console.print(t)
    else:
        _plain(f"\nDark Web: {dw.get('total_links_found', 0)} enlaces .onion")


# ============================================================
# Resumen final por dominio
# ============================================================
def summary(domain: str, discovery: Dict, threat: Dict, elapsed: float):
    activos = discovery.get("activos", {}).get("resumen", {})
    fp = threat.get("fingerprinting", {})
    vuln = threat.get("vulnerabilities", {})
    dw = threat.get("darkweb", {})

    apis_ok = sum(
        1 for v in threat.values() if isinstance(v, dict) and v.get("status") == "ok"
    )

    rows = [
        ("🌐 Subdominios únicos", str(discovery.get("total_subdomains", 0))),
        ("📡 IP resuelta", str(threat.get("ip_address", "N/D"))),
        ("🟢 Hosts activos", f"{activos.get('activos', 0)}/{activos.get('total_hosts', 0)}" if activos else "—"),
        ("🛰️ APIs threat intel OK", str(apis_ok)),
    ]
    if fp.get("status") == "success":
        rows.append(("🧬 Tecnologías", str(fp.get("total_technologies", 0))))
    if vuln.get("status") == "success":
        rows.append(("🚨 CVEs / exploits", f"{vuln.get('total_cves', 0)} / {vuln.get('total_exploits', 0)}"))
        rows.append(("🇪🇸 Fichas INCIBE-CERT", str(vuln.get("incibe_refs", 0))))
    if dw.get("status") == "success":
        rows.append(("🌑 Enlaces .onion", str(dw.get("total_links_found", 0))))
    rows.append(("⏱️ Tiempo", f"{elapsed:.1f}s"))

    if _RICH:
        t = Table(box=box.ROUNDED, show_header=False, border_style="green", padding=(0, 1))
        t.add_column("Indicador", style="bold")
        t.add_column("Valor", style="bold cyan", justify="right")
        for k, v in rows:
            t.add_row(k, v)
        console.print(Panel(t, title=f"[bold green]📊 RESUMEN — {domain}[/]", border_style="green"))
    else:
        _plain(f"\n----- RESUMEN {domain} -----")
        for k, v in rows:
            _plain(f"  {k}: {v}")


_API_STATUS_STYLE = {
    "ok": ("green", "✓ OK"),
    "no_api_key": ("dim", "○ sin clave"),
    "invalid_key": ("bold red", "✗ inválida/caducada"),
    "quota_exceeded": ("bold yellow", "⏳ cuota agotada"),
    "error": ("red", "✗ error"),
}


def diagnostics(diag: Dict):
    """Renderiza el estado de las APIs y herramientas, con avisos accionables."""
    apis = diag.get("apis", [])
    tools = diag.get("tools", [])
    keys_to_fix = diag.get("keys_to_fix", [])

    if _RICH:
        # Tabla de APIs
        t = Table(
            title=f"🛰️ Estado de las APIs ({diag.get('apis_ok', 0)}/{diag.get('apis_total', 0)} OK)",
            box=box.SIMPLE_HEAVY, header_style="bold cyan",
        )
        t.add_column("API", style="white")
        t.add_column("Estado", justify="left")
        t.add_column("Acción recomendada", style="dim")
        for a in apis:
            style, label = _API_STATUS_STYLE.get(a["status"], ("dim", a["status"]))
            t.add_row(a["name"], Text(label, style=style), a["action"] or "—")
        console.print(t)

        # Tabla de herramientas externas
        tt = Table(title="🧰 Herramientas externas", box=box.SIMPLE, header_style="bold cyan")
        tt.add_column("Herramienta", style="white")
        tt.add_column("Estado", justify="center")
        tt.add_column("Aporta", style="dim")
        tt.add_column("Cómo solucionarlo", style="dim")
        for tool in tools:
            est = Text("● disponible", style="green") if tool["ok"] else Text("○ no disponible", style="yellow")
            tt.add_row(tool["tool"], est, tool["impact"], "" if tool["ok"] else tool["fix"])
        console.print(tt)

        # Aviso destacado de claves a renovar
        if keys_to_fix:
            lines = "\n".join(f"• [bold]{a['name']}[/]: {a['action']}" for a in keys_to_fix)
            console.print(
                Panel(
                    lines,
                    title="[bold red]🔑 ACCIÓN REQUERIDA: claves a renovar/actualizar[/]",
                    subtitle="[dim]actualiza tu archivo .env y vuelve a ejecutar[/]",
                    border_style="red", box=box.HEAVY,
                )
            )
    else:
        _plain(f"\nAPIs ({diag.get('apis_ok', 0)}/{diag.get('apis_total', 0)} OK):")
        for a in apis:
            _plain(f"  {a['name']}: {a['label']}  {a['action']}")
        _plain("\nHerramientas:")
        for tool in tools:
            _plain(f"  {tool['tool']}: {'OK' if tool['ok'] else 'NO -> ' + tool['fix']}")
        if keys_to_fix:
            _plain("\n!!! CLAVES A RENOVAR:")
            for a in keys_to_fix:
                _plain(f"  - {a['name']}: {a['action']}")


def progress_status(message: str):
    """Devuelve un context manager de estado (spinner) o uno nulo si no hay rich."""
    if _RICH:
        return console.status(f"[cyan]{message}[/]", spinner="dots")

    class _Null:
        def __enter__(self):
            _plain(f"... {message}")
            return self

        def __exit__(self, *a):
            return False

    return _Null()
