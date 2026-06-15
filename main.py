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
        help="Activar/desactivar monitorización en dark web (requiere Tor).",
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
def analyze_domain(domain, args, do_fp, do_dw):
    from scripts.modules.discovery import PassiveDiscovery
    from scripts.modules.threat_intel import ThreatIntel
    from scripts.modules.report import ReportGenerator

    start = time.time()

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

    # --- FASE 2.5: fingerprinting + CVEs ---
    if do_fp:
        ui.phase("FASE 2.5", "FINGERPRINTING + CVEs + EXPLOITS + INCIBE-CERT",
                 "Tecnologías (Docker/Wappalyzer) → CVEs (NVD) → Exploit-DB → referencias INCIBE-CERT")
        from scripts.modules.fingerprint import Fingerprinter
        from scripts.modules.cve_exploit import CveExploitScanner

        urls = [f"https://{s}" for s in discovery_results["subdomains"] if not s.startswith("*.")]
        urls = urls[: args.max_fp_urls]
        try:
            fp = Fingerprinter(threads=max(2, args.threads // 8))
            if not fp.is_ready():
                threat_results["fingerprinting"] = {
                    "status": "error",
                    "message": "Docker/wappalyzer-next no disponible.",
                    "results": [], "total_technologies": 0,
                }
                threat_results["vulnerabilities"] = {"status": "skipped"}
                ui.warn("Fingerprinting omitido: Docker o wappalyzer-next no disponibles.")
            elif not urls:
                threat_results["fingerprinting"] = {"status": "skipped"}
                threat_results["vulnerabilities"] = {"status": "skipped"}
            else:
                with ui.progress_status("Detectando tecnologías y buscando vulnerabilidades…"):
                    tech_results = fp.scan(urls)
                    threat_results["fingerprinting"] = tech_results
                    threat_results["vulnerabilities"] = CveExploitScanner().scan(tech_results)
                ui.table_technologies(threat_results["fingerprinting"])
                ui.table_cves(threat_results["vulnerabilities"])
        except Exception as e:  # noqa: BLE001
            ui.error(f"Error en la fase de fingerprinting: {e}")
            threat_results["fingerprinting"] = {"status": "error", "message": str(e)}
            threat_results["vulnerabilities"] = {"status": "skipped"}
    else:
        threat_results["fingerprinting"] = {"status": "skipped"}
        threat_results["vulnerabilities"] = {"status": "skipped"}

    # --- FASE 4: dark web ---
    if do_dw:
        ui.phase("FASE 4", "MONITORIZACIÓN EN DARK WEB (Tor)", "Búsqueda multi-motor + crawling de enlaces .onion")
        from scripts.modules.darkweb_monitor import DarkWebMonitor

        try:
            with ui.progress_status("Conectando a Tor y rastreando la dark web…"):
                threat_results["darkweb"] = DarkWebMonitor(domain).run_all()
            ui.table_darkweb(threat_results["darkweb"])
        except Exception as e:  # noqa: BLE001
            threat_results["darkweb"] = {"status": "error", "message": str(e)}
            ui.error(f"Dark web: {e}")
    else:
        threat_results["darkweb"] = {"status": "skipped"}

    # --- DIAGNÓSTICO: claves API y herramientas (no detiene el escaneo) ---
    from scripts.modules import diagnostics as diag_mod

    diag = diag_mod.build(threat_results)
    threat_results["diagnostics"] = diag
    ui.diagnostics(diag)

    # --- MONITORIZACIÓN: comparar con el escaneo anterior (antes de escribir el nuevo) ---
    changes = {"status": "desactivado"}
    if not args.no_diff:
        from scripts.modules import diffing

        slug = domain.replace(".", "_")
        current_snapshot = {
            "dominio_analizado": domain,
            "discovery": discovery_results,
            "threat_intel": threat_results,
        }
        changes = diffing.compute(current_snapshot, args.output_dir, slug)
        ui.table_changes(changes)

    # --- FASE 3: informes ---
    ui.phase("FASE 3", "GENERACIÓN DE INFORMES", f"Formatos: {args.formats} → {args.output_dir}/")
    formats = {f.strip() for f in args.formats.split(",") if f.strip()}
    reporter = ReportGenerator(args.output_dir, domain)
    if "json" in formats:
        reporter.to_json(
            {
                "dominio_analizado": domain,
                "discovery": discovery_results,
                "threat_intel": threat_results,
                "diagnostics": diag,
                "changes_since_last_scan": changes,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
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
        args.fingerprint, interactive, "   ¿Fingerprinting + CVEs + INCIBE-CERT? (s/n): ", default=False
    )
    do_dw = True if args.all else decide_phase(
        args.darkweb, interactive, "   ¿Búsqueda en dark web? (s/n): ", default=False
    )

    ui.info(
        f"\n[dim]Objetivos:[/] [bold]{len(domains)}[/]   "
        f"[dim]fingerprint:[/] {'✓' if do_fp else '✗'}   "
        f"[dim]dark web:[/] {'✓' if do_dw else '✗'}   "
        f"[dim]hilos:[/] {args.threads}"
        if ui.enabled()
        else f"\n[*] Dominios: {len(domains)} | fingerprint={do_fp} | darkweb={do_dw} | hilos={args.threads}"
    )

    total = 0.0
    for i, domain in enumerate(domains, 1):
        ui.domain_header(domain, i, len(domains))
        try:
            total += analyze_domain(domain, args, do_fp, do_dw)
        except KeyboardInterrupt:
            raise
        except Exception as e:  # noqa: BLE001
            ui.error(f"Error analizando {domain}: {e}")

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
