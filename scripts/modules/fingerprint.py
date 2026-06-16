#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de fingerprinting tecnológico usando wappalyzer-next dentro de Docker.

Mejoras:
- Detecta automáticamente el directorio wappalyzer-next.
- Comprueba que Docker esté disponible antes de intentar nada.
- Ejecuta los escaneos de varias URLs EN PARALELO (con un límite prudente,
  ya que cada uno levanta un contenedor).
"""

import json
import os
import shutil
import subprocess
from typing import Dict, List

from .utils import get_logger, run_parallel

log = get_logger()

# ---------------------------------------------------------------------------
# Estrategia de rendimiento (medido sobre zunder.com en la VM, 2 CPU / 3.8GB):
#
#   · Un host vivo tarda 31-39s en wappalyzer "balanced" (lanza navegador interno).
#     El antiguo timeout de 25s era MENOR que eso → abortaba TODOS los hosts vivos
#     → 0 tecnologías. Era una regresión silenciosa.
#   · Se lanzaba 1 contenedor por URL (~3s de arranque cada uno) con 3 workers.
#     22 URLs ⇒ ~200s.
#
# Solución (ambas medidas, ~200s → ~76s CON resultados):
#   1. Pre-filtro HTTP barato (≈1-2s en paralelo): descarta hosts que no responden
#      (mail, mx, staging caído) para no gastar el navegador en ellos.
#   2. UN solo contenedor con fichero de URLs + workers internos de wappalyzer
#      (-i fichero -w N). Elimina N-1 arranques de contenedor y deja que wappalyzer
#      paralelice. El compose monta .:/app, así que el fichero va dentro del dir.
#
# Todo ajustable por env sin tocar código.
# ---------------------------------------------------------------------------
def _int_env(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (ValueError, TypeError):
        return default

# Presupuesto global del batch: arranque + margen por URL. 20 URLs balanced ≈ 76s,
# así que 30 + 8/URL (≈190s para 20) deja holgura sin colgar el escaneo eterno.
FP_BATCH_BASE_S = _int_env("FP_BATCH_BASE_S", 30, 10)
FP_BATCH_PER_URL_S = _int_env("FP_BATCH_PER_URL_S", 8, 2)
FP_BATCH_MAX_S = _int_env("FP_BATCH_MAX_S", 600, 60)
# Workers internos de wappalyzer (cada uno abre un navegador, ~0.5GB). 4 es seguro
# con 0 swap; subir solo si hay RAM de sobra. FP_WORKERS.
FP_WORKERS = _int_env("FP_WORKERS", 4, 1)
# fast | balanced | full. balanced (navegador) detecta versiones para la fase CVE;
# fast (solo requests) es ~3x más rápido pero pierde versiones. FP_SCAN_TYPE.
FP_SCAN_TYPE = os.getenv("FP_SCAN_TYPE", "balanced").strip().lower()
if FP_SCAN_TYPE not in ("fast", "balanced", "full"):
    FP_SCAN_TYPE = "balanced"
# Timeout del sondeo HTTP de liveness por host (segundos).
FP_PROBE_TIMEOUT_S = _int_env("FP_PROBE_TIMEOUT_S", 4, 1)
# Compatibilidad: si alguien fija FP_URL_TIMEOUT_S en el .env, lo respetamos como
# suelo del presupuesto del batch (ya no hay timeout "por URL" porque es 1 contenedor).
FP_URL_TIMEOUT_S = _int_env("FP_URL_TIMEOUT_S", 25, 5)

# Patrones de subdominios poco interesantes para fingerprinting (CDNs, assets, etc.)
DEFAULT_EXCLUDE = [
    "cdn.", "static.", "assets.", "img.", "media.", "maptiles.", "tileserver",
    "k8s", "flutter",
]


class Fingerprinter:
    def __init__(self, wappalyzer_dir: str = None, threads: int = 4):
        self.threads = threads
        # Workers internos de wappalyzer (cuántos navegadores en el único contenedor).
        # No confundir con args.threads (concurrencia del resto del pipeline).
        self.workers = FP_WORKERS
        self.docker_ok = self._docker_available()

        if wappalyzer_dir is None:
            base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            posibles = [
                os.path.join(base, "scripts", "wappalyzer-next"),
                os.path.join(base, "wappalyzer-next"),
            ]
            self.wappalyzer_dir = next((p for p in posibles if os.path.isdir(p)), None)
        else:
            self.wappalyzer_dir = wappalyzer_dir if os.path.isdir(wappalyzer_dir) else None

    @staticmethod
    def _docker_available() -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            r = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def is_ready(self) -> bool:
        return self.docker_ok and self.wappalyzer_dir is not None

    @staticmethod
    def _http_alive(urls: List[str]) -> List[str]:
        """Pre-filtro barato: deja solo hosts que devuelven ALGUNA respuesta HTTP.

        Sondeo en paralelo con timeout corto. Descarta hosts muertos/mudos
        (mail, mx, staging caído → ConnectionError/timeout) para no malgastar
        el navegador de wappalyzer en ellos. Conserva 403/503 (el servidor existe).
        Si requests no está disponible, no filtra (devuelve todo).
        """
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
        except Exception:  # noqa: BLE001
            return urls

        def _probe(u: str):
            try:
                requests.get(
                    u, timeout=FP_PROBE_TIMEOUT_S, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}, verify=False,
                )
                return u  # cualquier respuesta = host vivo
            except Exception:  # noqa: BLE001
                return None

        alive: List[str] = []
        for _, res in run_parallel(_probe, urls, max_workers=min(25, max(4, len(urls))), label="http-probe"):
            if res:
                alive.append(res)
        return alive

    def _scan_batch(self, urls: List[str]) -> List[Dict]:
        """Escanea TODAS las URLs en un único contenedor wappalyzer (workers internos)."""
        results: List[Dict] = []
        # El compose monta .:/app → escribimos el fichero dentro del dir del módulo.
        fname = ".fp_targets.txt"
        fpath = os.path.join(self.wappalyzer_dir, fname)
        budget = min(FP_BATCH_MAX_S, max(FP_URL_TIMEOUT_S, FP_BATCH_BASE_S + len(urls) * FP_BATCH_PER_URL_S))
        try:
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write("\n".join(urls) + "\n")
            cmd = [
                "docker", "compose", "run", "--rm", "wappalyzer",
                "-i", f"/app/{fname}", "--scan-type", FP_SCAN_TYPE,
                "-w", str(self.workers), "-oJ",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=budget, cwd=self.wappalyzer_dir
            )
            # El progreso ("Processed X/Y") va a stderr; el JSON, a stdout (última línea {...}).
            json_line = next(
                (ln.strip() for ln in reversed(result.stdout.splitlines()) if ln.strip().startswith("{")),
                None,
            )
            if not json_line:
                log.debug(f"    [!] Fingerprint batch sin JSON (rc={result.returncode}): "
                          f"{result.stderr.strip()[-200:]}")
                return results
            data = json.loads(json_line)
            for url, tech_dict in data.items():
                if not isinstance(tech_dict, dict):
                    continue
                for tech_name, tech_info in tech_dict.items():
                    version = tech_info.get("version", "N/A")
                    if isinstance(version, list):
                        version = version[0] if version else "N/A"
                    results.append({
                        "url": url,
                        "technology": tech_name,
                        "version": version,
                        "confidence": tech_info.get("confidence", 100),
                    })
        except subprocess.TimeoutExpired:
            log.warning(f"   [!] Fingerprint: presupuesto agotado ({budget}s) con {len(urls)} URLs.")
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error de fingerprint batch: {e}")
        finally:
            try:
                os.remove(fpath)
            except OSError:
                pass
        return results

    def scan(self, urls: List[str], exclude=None) -> Dict:
        if not self.docker_ok:
            return {
                "status": "error",
                "message": "Docker no disponible o no en ejecución. El fingerprinting requiere Docker.",
                "results": [],
                "total_technologies": 0,
            }
        if not self.wappalyzer_dir:
            return {
                "status": "error",
                "message": (
                    "No se encontró 'wappalyzer-next'. Clónalo en scripts/wappalyzer-next y ejecuta "
                    "'docker compose build'."
                ),
                "results": [],
                "total_technologies": 0,
            }

        exclude = exclude if exclude is not None else DEFAULT_EXCLUDE
        urls_filtradas = [u for u in urls if not any(p in u for p in exclude)]

        # 1) Pre-filtro HTTP: descarta hosts muertos antes de gastar el navegador.
        vivas = self._http_alive(urls_filtradas)
        descartadas = len(urls_filtradas) - len(vivas)
        if not vivas:
            log.info(f"   [*] Fingerprinting: 0 hosts vivos de {len(urls_filtradas)} (nada que escanear).")
            return {"status": "success", "results": [], "total_technologies": 0, "urls_scanned": 0}

        log.info(
            f"   [*] Fingerprinting de {len(vivas)} hosts vivos "
            f"(descartados {descartadas} sin HTTP, modo={FP_SCAN_TYPE}, w={self.workers}) en 1 contenedor..."
        )

        # 2) Batch: un único contenedor con todas las URLs vivas + workers internos.
        results = self._scan_batch(vivas)

        return {
            "status": "success",
            "results": results,
            "total_technologies": len(results),
            "urls_scanned": len(vivas),
        }
