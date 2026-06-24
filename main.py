#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Prototipo OSINT - Descubrimiento pasivo de activos + monitorización.

Modos de uso:
  Interactivo (pregunta el dominio y las fases):
      python main.py

  Automático / no interactivo (recomendado para escaneos en lote):
      python main.py -d ejemplo.com -y
      python main.py -d ejemplo.com --fingerprint --darkweb
      python main.py -f dominios.txt -y --no-active -t 60
      python main.py ejemplo.com --all --formats json,md -o resultados

Ejecuta `python main.py -h` para ver todas las opciones.
"""

import argparse
import os
import sys
import time

from dotenv import load_dotenv

from scripts.modules import ui
from scripts.modules.utils import get_logger, is_valid_domain, setup_logging

load_dotenv()
log = get_logger()


# ============================================================
# CLI
# ============================================================
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Prototipo OSINT - reconocimiento pasivo de activos, tecnologías, CVEs y dark web.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain", nargs="?", help="Dominio a analizar (también admite -d).")
    p.add_argument("-d", "--domain", dest="domain_opt", help="Dominio a analizar.")
    p.add_argument("-f", "--file", help="Archivo con una lista de dominios (uno por línea).")

    p.add_argument(
        "--fingerprint", action=argparse.BooleanOptionalAction, default=None,
        help="Activar/desactivar fingerprinting + CVEs (requiere Docker).",
    )
    p.add_argument(
        "--darkweb", action=argparse.BooleanOptionalAction, default=None,
        help="Activar/desactivar monitorización de exposición (brechas, Ahmia, pastes).",
    )
    p.add_argument(
        "--tor", action="store_true",
        help="Capa avanzada: crawling .onion vía Tor (requiere Tor en :9050). Desactivada por defecto.",
    )
    p.add_argument(
        "--socradar", action=argparse.BooleanOptionalAction, default=None,
        help="Inteligencia SOCRadar (ASM/activos, dark web, vulns, incidentes). "
             "Solo endpoints GRATIS por defecto. Requiere SOCRADAR_API_KEY y "
             "SOCRADAR_COMPANY_ID en .env.",
    )
    p.add_argument(
        "--socradar-credits", action="store_true",
        help="Permite que SOCRadar consuma créditos (Identity Intelligence). "
             "Respeta SOCRADAR_MAX_CREDITS (def: 10). Desactivado por defecto.",
    )
    p.add_argument(
        "--browser", action="store_true",
        help="Renderizar páginas con JS usando Firefox/Playwright (respaldo en dark web). "
             "Desactivado por defecto: consume RAM. Requiere 'playwright install firefox'.",
    )
    p.add_argument(
        "--pivot", action="store_true",
        help="Pivoting: tras la dark web, relanza la búsqueda con los IOCs encontrados "
             "(emails, credenciales, dominios/.onion relacionados). Añade tiempo.",
    )
    p.add_argument("--no-active", action="store_true", help="Omitir verificación ICMP/TCP de hosts.")
    p.add_argument("--no-diff", action="store_true", help="No comparar con el escaneo anterior (modo monitorización).")
    p.add_argument("--all", action="store_true", help="Ejecutar todas las fases (fingerprint + darkweb).")
    p.add_argument(
        "-y", "--yes", action="store_true",
        help="Modo no interactivo: no pregunta nada y usa los flags/valores por defecto.",
    )

    p.add_argument("-o", "--output-dir", default="outputs", help="Carpeta de salida (def: outputs).")
    p.add_argument("-t", "--threads", type=int, default=30, help="Hilos de concurrencia (def: 30).")
    p.add_argument("--formats", default="json,csv,md,html", help="Formatos de informe: json,csv,md,html (def: todos).")
    p.add_argument("--max-fp-urls", type=int, default=25, help="Máx. URLs a analizar en fingerprinting (def: 25).")

    g = p.add_mutually_exclusive_group()
    g.add_argument("-q", "--quiet", action="store_true", help="Salida mínima (solo avisos/errores).")
    g.add_argument("-v", "--verbose", action="store_true", help="Salida detallada (debug).")
    return p.parse_args(argv)


def collect_domains(args) -> list:
    """Reúne y valida la lista de dominios desde -d, posicional y/o -f."""
    domains = []
    for d in (args.domain, args.domain_opt):
        if d:
            domains.append(d.strip().lower())
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        domains.append(line)
        except OSError as e:
            log.warning(f"[!] No se pudo leer {args.file}: {e}")

    # Modo interactivo si no se pasó ningún dominio y hay terminal
    if not domains and sys.stdin.isatty() and not args.yes:
        while True:
            d = input("   ▶ Introduce el dominio a analizar (ej: google.com): ").strip().lower()
            if d and is_valid_domain(d):
                domains.append(d)
                break
            print("   ⚠️  Dominio no válido. Inténtalo de nuevo.")

    # Validar y deduplicar conservando el orden
    seen, valid = set(), []
    for d in domains:
        if d in seen:
            continue
        seen.add(d)
        if is_valid_domain(d):
            valid.append(d)
        else:
            log.warning(f"[!] Dominio ignorado (formato inválido): {d}")
    return valid


def decide_phase(flag, interactive, prompt, default=False) -> bool:
    """Resuelve si una fase opcional debe ejecutarse según flags / modo interactivo."""
    if flag is not None:
        return flag
    if interactive:
        return input(prompt).strip().lower() in ("s", "y", "si", "yes")
    return default


# ============================================================
# PIPELINE POR DOMINIO
# ============================================================
def analyze_domain(domain, args, do_fp, do_dw, do_sr=False):
    from scripts.modules.discovery import PassiveDiscovery
    from scripts.modules.threat_intel import ThreatIntel
    from scripts.modules.report import ReportGenerator

    start = time.time()

    # --- Identidad del escaneo: slug del dominio + sellos de tiempo ---
    # Dos formatos a propósito:
    #   · run_ts  → ISO ordenable, para la BD/persistencia (intel.db) y el JSON.
    #   · stamp   → europeo (día-mes-año) para los NOMBRES de archivo y la carpeta,
    #               más legible para una persona. El orden cronológico de los
    #               informes NO depende de este nombre (diffing usa fecha de
    #               modificación), así que usar dd-mm-aaaa aquí es seguro.
    slug = domain.replace(".", "_")
    run_ts = time.strftime("%Y-%m-%d %H:%M:%S")
    stamp = time.strftime("%d-%m-%Y_%Hh%M")
    # Cada escaneo en su propia subcarpeta: outputs/<dominio>_<dd-mm-aaaa_HHhMM>/
    # (intel.db y los logs siguen en la raíz de outputs/, son acumulativos).
    scan_dir = os.path.join(args.output_dir, f"{slug}_{stamp}")
    os.makedirs(scan_dir, exist_ok=True)

    # --- FASE 1: descubrimiento (+ actividad) ---
    ui.phase("FASE 1", "DESCUBRIMIENTO DE ACTIVOS", "Subdominios (9 fuentes en paralelo) · DNS · WHOIS · actividad ICMP/TCP")
    discovery = PassiveDiscovery(domain, threads=args.threads)
    discovery_results = discovery.run_all(verificar_actividad=not args.no_active)

    # --- FASE 2: threat intelligence (APIs en paralelo) ---
    ui.phase("FASE 2", "THREAT INTELLIGENCE", "13 APIs consultadas en paralelo (Shodan, VirusTotal, AbuseIPDB…)")
    threat = ThreatIntel(domain)
    threat_results = threat.run_all()

    # Combinar subdominios de VirusTotal y urlscan
    extra = list(threat_results.get("subdomains_from_virustotal", []))
    for r in threat_results.get("urlscan", {}).get("results", []):
        d = r.get("domain", "")
        if d and d != domain and d.endswith(domain):
            extra.append(d)
    discovery.add_subdomains_from_list(extra, source="threat_intel")
    discovery_results["subdomains"] = sorted(discovery.subdomains)
    discovery_results["total_subdomains"] = len(discovery.subdomains)
    discovery_results["subdomain_sources"] = {k: sorted(v) for k, v in discovery.sources.items()}

    # Render visual de los hallazgos de descubrimiento
    ui.table_subdomains(
        discovery_results["subdomains"],
        discovery_results["subdomain_sources"],
        discovery_results.get("activos", {}),
    )
    ui.table_dns(discovery_results.get("dns_records", {}))

    # --- FASES 2.5 y 4: independientes entre sí → se solapan EN PARALELO ---
    # Fingerprinting (Docker+APIs) y exposición/dark web (red/Tor) no comparten
    # datos de entrada (ambas ya tienen lo que necesitan de FASE 1+2), así que
    # lanzarlas a la vez recorta el tiempo total sin alterar los resultados.
    # No se hace UI dentro de los hilos: cada función DEVUELVE su dict y las
    # tablas se pintan después, en orden, para no entremezclar la salida.

    def _fase_fingerprint() -> dict:
        """FASE 2.5: tecnologías → CVEs → exploits → INCIBE. Devuelve dict parcial."""
        from scripts.modules.fingerprint import Fingerprinter
        from scripts.modules.cve_exploit import CveExploitScanner

        out: dict = {}
        # El apex (p.ej. zunder.com) suele ser el sitio más rico en tecnologías y
        # versiones (WordPress, plugins…), clave para la fase CVE. Va primero y se
        # deduplica por si descovery ya lo incluyó como "subdominio".
        hosts = [domain] + [s for s in discovery_results["subdomains"] if not s.startswith("*.")]
        seen, urls = set(), []
        for h in hosts:
            if h not in seen:
                seen.add(h)
                urls.append(f"https://{h}")
        urls = urls[: args.max_fp_urls]
        try:
            fp = Fingerprinter(threads=max(2, args.threads // 8))
            if not fp.is_ready():
                out["fingerprinting"] = {
                    "status": "error",
                    "message": "Docker/wappalyzer-next no disponible.",
                    "results": [], "total_technologies": 0,
                }
                out["vulnerabilities"] = {"status": "skipped"}
            elif not urls:
                out["fingerprinting"] = {"status": "skipped"}
                out["vulnerabilities"] = {"status": "skipped"}
            else:
                tech_results = fp.scan(urls)
                out["fingerprinting"] = tech_results
                out["vulnerabilities"] = CveExploitScanner().scan(tech_results)
        except Exception as e:  # noqa: BLE001
            out["fingerprinting"] = {"status": "error", "message": str(e)}
            out["vulnerabilities"] = {"status": "skipped"}
        return out

    def _fase_exposicion() -> dict:
        """FASE 4: brechas + dark web + pastes + IOCs. Devuelve dict parcial."""
        from scripts.modules.exposure import ExposureMonitor

        # Correos a vigilar: los que descubre Hunter + la lista manual de .env.
        emails = []
        hunter = threat_results.get("hunter", {})
        if isinstance(hunter, dict):
            emails += [e.get("value", "") for e in hunter.get("emails", []) if e.get("value")]
        emails += [e for e in os.getenv("MONITOR_EMAILS", "").replace(";", ",").split(",") if e.strip()]

        out: dict = {}
        try:
            dw = ExposureMonitor(
                domain, emails=emails, run_tor=args.tor, threads=args.threads,
                use_browser=args.browser, use_pivot=args.pivot
            ).run_all()
            # Exportar IOCs detectados (emails, credenciales, IPs, hashes, cripto…)
            ioc_result = dw.get("iocs", {})
            if ioc_result.get("total"):
                from scripts.modules.ioc_extractor import export_iocs
                dw["ioc_files"] = export_iocs(ioc_result, scan_dir, domain, timestamp=stamp)
            out["darkweb"] = dw
        except Exception as e:  # noqa: BLE001
            out["darkweb"] = {"status": "error", "message": str(e)}
        return out

    def _fase_socradar() -> dict:
        """SOCRadar: ASM/activos + dark web + vulns + incidentes. Devuelve dict parcial."""
        from scripts.modules.socradar import SocRadar

        # Objetivos para Identity Intelligence (solo si se permiten créditos):
        # el dominio + los emails públicos descubiertos por Hunter / .env.
        id_targets = [domain]
        hunter = threat_results.get("hunter", {})
        if isinstance(hunter, dict):
            id_targets += [e.get("value", "") for e in hunter.get("emails", []) if e.get("value")]
        id_targets += [e for e in os.getenv("MONITOR_EMAILS", "").replace(";", ",").split(",") if e.strip()]
        id_targets = [t for t in dict.fromkeys(id_targets) if t]

        try:
            sr = SocRadar(domain, cache_dir=os.path.join(args.output_dir, ".socradar_cache"))
            if not sr.is_configured():
                return {"socradar": {"status": "no_api_key",
                                     "message": "Configura SOCRADAR_API_KEY y SOCRADAR_COMPANY_ID en .env"}}
            max_credits = int(os.getenv("SOCRADAR_MAX_CREDITS", "10") or 10)
            asm_pages = int(os.getenv("SOCRADAR_ASM_MAX_PAGES", "0") or 0)
            return {"socradar": sr.run_all(
                spend_credits=args.socradar_credits,
                asm_max_pages=asm_pages,
                identity_targets=id_targets,
                max_credits=max_credits,
            )}
        except Exception as e:  # noqa: BLE001
            return {"socradar": {"status": "error", "message": str(e)}}

    # Construir solo las fases activas y lanzarlas juntas.
    par_tasks = {}
    if do_fp:
        par_tasks["fingerprint"] = _fase_fingerprint
    if do_dw:
        par_tasks["exposicion"] = _fase_exposicion
    if do_sr:
        par_tasks["socradar"] = _fase_socradar

    if par_tasks:
        partes_fase = []
        if do_fp:
            partes_fase.append("Tecnologías+CVEs+INCIBE")
        if do_dw:
            partes_fase.append("Brechas+Dark web+Pastes" + (" · Tor" if args.tor else ""))
        if do_sr:
            partes_fase.append("SOCRadar (ASM/dark web)")
        ui.phase("FASES 2.5 + 4", "FINGERPRINTING ‖ EXPOSICIÓN ‖ SOCRADAR (en paralelo)",
                 "  ·  ".join(partes_fase))
        from scripts.modules.utils import run_named_parallel as _run_named_parallel
        with ui.progress_status("Ejecutando fingerprinting y exposición en paralelo…"):
            par_out = _run_named_parallel(par_tasks, max_workers=len(par_tasks))
        # Cada función escribe claves distintas (fingerprinting/vulnerabilities vs darkweb).
        for sub in par_out.values():
            if isinstance(sub, dict):
                threat_results.update(sub)

    # Render de tablas (secuencial, tras el join).
    if do_fp:
        if threat_results.get("fingerprinting", {}).get("status") == "error":
            ui.warn(f"Fingerprinting: {threat_results['fingerprinting'].get('message', 'error')}")
        ui.table_technologies(threat_results.get("fingerprinting", {}))
        ui.table_cves(threat_results.get("vulnerabilities", {}))
    else:
        threat_results["fingerprinting"] = {"status": "skipped"}
        threat_results["vulnerabilities"] = {"status": "skipped"}

    if do_dw:
        if threat_results.get("darkweb", {}).get("status") == "error":
            ui.error(f"Monitorización de exposición: {threat_results['darkweb'].get('message', 'error')}")
        else:
            ui.table_exposure(threat_results.get("darkweb", {}))
    else:
        threat_results["darkweb"] = {"status": "skipped"}

    if do_sr:
        sr_res = threat_results.get("socradar", {})
        if sr_res.get("status") == "success":
            # Los activos ASM (dominios/subdominios) descubiertos por SOCRadar
            # se incorporan al descubrimiento para no perderlos en el informe.
            asm_domains = sr_res.get("asm", {}).get("domains", [])
            rel = [d for d in asm_domains if d == domain or d.endswith("." + domain)]
            if rel:
                discovery.add_subdomains_from_list(rel, source="socradar_asm")
                discovery_results["subdomains"] = sorted(discovery.subdomains)
                discovery_results["total_subdomains"] = len(discovery.subdomains)
                discovery_results["subdomain_sources"] = {k: sorted(v) for k, v in discovery.sources.items()}
            ui.table_socradar(sr_res)
        elif sr_res.get("status") in ("error", "no_api_key"):
            ui.warn(f"SOCRadar: {sr_res.get('message', 'no disponible')}")
    else:
        threat_results["socradar"] = {"status": "skipped"}

    # --- DIAGNÓSTICO: claves API y herramientas (no detiene el escaneo) ---
    from scripts.modules import diagnostics as diag_mod

    diag = diag_mod.build(threat_results)
    threat_results["diagnostics"] = diag
    ui.diagnostics(diag)

    # --- MONITORIZACIÓN: comparar con el escaneo anterior (antes de escribir el nuevo) ---
    changes = {"status": "desactivado"}
    if not args.no_diff:
        from scripts.modules import diffing

        current_snapshot = {
            "dominio_analizado": domain,
            "discovery": discovery_results,
            "threat_intel": threat_results,
        }
        changes = diffing.compute(current_snapshot, args.output_dir, slug)
        ui.table_changes(changes)

    # --- CORRELACIÓN: grafo de entidades + confidence scoring ---
    try:
        from scripts.modules.entities import build_entity_graph
        graph = build_entity_graph(domain, discovery_results, threat_results)
        # Persistencia: fusiona con el histórico (intel.db) y anota first_seen/
        # last_seen/is_new/runs. Memoria entre escaneos; degrada con elegancia.
        from scripts.modules.intel_store import persist_and_enrich
        threat_results["entities"] = persist_and_enrich(graph, args.output_dir, run_ts)
    except Exception as e:  # noqa: BLE001
        threat_results["entities"] = {"status": "error", "message": str(e)}

    # --- FASE 3: informes ---
    ui.phase("FASE 3", "GENERACIÓN DE INFORMES", f"Formatos: {args.formats} → {scan_dir}/")
    formats = {f.strip() for f in args.formats.split(",") if f.strip()}
    reporter = ReportGenerator(scan_dir, domain, timestamp=stamp)
    if "json" in formats:
        reporter.to_json(
            {
                "dominio_analizado": domain,
                "discovery": discovery_results,
                "threat_intel": threat_results,
                "diagnostics": diag,
                "changes_since_last_scan": changes,
                "timestamp": run_ts,
            }
        )
    if "csv" in formats:
        reporter.to_csv(discovery_results["subdomains"], sources=discovery_results.get("subdomain_sources"))
    if "md" in formats:
        reporter.to_markdown(discovery_results, threat_results, diagnostics=diag)
    if "html" in formats:
        reporter.to_html(discovery_results, threat_results, diagnostics=diag)

    elapsed = time.time() - start
    ui.summary(domain, discovery_results, threat_results, elapsed)
    return elapsed


# ============================================================
# MAIN
# ============================================================
def main(argv=None):
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    if not args.quiet:
        ui.banner()

    domains = collect_domains(args)
    if not domains:
        ui.warn("No se proporcionó ningún dominio válido. Usa -d, -f o el modo interactivo.")
        return 1

    interactive = sys.stdin.isatty() and not args.yes and not args.all
    do_fp = True if args.all else decide_phase(
        args.fingerprint, interactive, "   ¿Fingerprinting + CVEs + INCIBE-CERT? (s/n): ", default=True
    )
    do_dw = True if args.all else decide_phase(
        args.darkweb, interactive, "   ¿Búsqueda en dark web? (s/n): ", default=False
    )
    # SOCRadar solo si hay credenciales configuradas (si no, ni se ofrece).
    sr_configured = bool(os.getenv("SOCRADAR_API_KEY") and os.getenv("SOCRADAR_COMPANY_ID"))
    do_sr = False
    if sr_configured:
        do_sr = True if args.all else decide_phase(
            args.socradar, interactive,
            "   ¿Inteligencia SOCRadar (ASM/dark web, gratis)? (s/n): ", default=False
        )
    elif args.socradar:
        ui.warn("SOCRadar solicitado pero falta SOCRADAR_API_KEY / SOCRADAR_COMPANY_ID en .env.")

    ui.info(
        f"\n[dim]Objetivos:[/] [bold]{len(domains)}[/]   "
        f"[dim]fingerprint:[/] {'✓' if do_fp else '✗'}   "
        f"[dim]dark web:[/] {'✓' if do_dw else '✗'}   "
        f"[dim]SOCRadar:[/] {'✓' if do_sr else '✗'}   "
        f"[dim]hilos:[/] {args.threads}"
        if ui.enabled()
        else f"\n[*] Dominios: {len(domains)} | fingerprint={do_fp} | darkweb={do_dw} | socradar={do_sr} | hilos={args.threads}"
    )

    total = 0.0
    try:
        for i, domain in enumerate(domains, 1):
            ui.domain_header(domain, i, len(domains))
            try:
                total += analyze_domain(domain, args, do_fp, do_dw, do_sr)
            except KeyboardInterrupt:
                raise
            except Exception as e:  # noqa: BLE001
                ui.error(f"Error analizando {domain}: {e}")
    finally:
        # Cierra el navegador compartido (si se usó --browser) y libera su RAM.
        if args.browser:
            from scripts.modules.browser_fetch import close_fetcher
            close_fetcher()

    if ui.enabled():
        ui.console.rule("[bold green]✅ COMPLETADO")
        ui.info(
            f"[bold green]{len(domains)} dominio(s)[/] analizados en [bold]{total:.1f}s[/]. "
            f"Informes en [cyan]'{args.output_dir}/'[/]"
        )
    else:
        log.info(f"\n✅ COMPLETADO — {len(domains)} dominio(s) en {total:.1f}s. Informes en '{args.output_dir}/'")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[!] Ejecución interrumpida por el usuario")
        sys.exit(130)
