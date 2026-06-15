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

# Patrones de subdominios poco interesantes para fingerprinting (CDNs, assets, etc.)
DEFAULT_EXCLUDE = [
    "cdn.", "static.", "assets.", "img.", "media.", "maptiles.", "tileserver",
    "k8s", "flutter",
]


class Fingerprinter:
    def __init__(self, wappalyzer_dir: str = None, threads: int = 4):
        self.threads = threads
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

    def _scan_one(self, url: str) -> List[Dict]:
        techs: List[Dict] = []
        try:
            cmd = ["docker", "compose", "run", "--rm", "wappalyzer", "-i", url, "-oJ"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=90, cwd=self.wappalyzer_dir
            )
            if result.returncode != 0:
                return techs
            json_line = next(
                (ln.strip() for ln in result.stdout.splitlines() if ln.strip().startswith("{")), None
            )
            if not json_line:
                return techs
            data = json.loads(json_line)
            tech_dict = list(data.values())[0] if isinstance(data, dict) and len(data) == 1 else data
            for tech_name, tech_info in tech_dict.items():
                version = tech_info.get("version", "N/A")
                if isinstance(version, list):
                    version = version[0] if version else "N/A"
                techs.append(
                    {
                        "url": url,
                        "technology": tech_name,
                        "version": version,
                        "confidence": tech_info.get("confidence", 100),
                    }
                )
        except subprocess.TimeoutExpired:
            log.debug(f"    [!] Fingerprint timeout en {url}")
        except Exception as e:  # noqa: BLE001
            log.debug(f"    [!] Error de fingerprint en {url}: {e}")
        return techs

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
        log.info(f"   [*] Fingerprinting de {len(urls_filtradas)} URLs (de {len(urls)}) en paralelo...")

        results: List[Dict] = []
        for _, techs in run_parallel(
            self._scan_one, urls_filtradas, max_workers=self.threads, label="fingerprint"
        ):
            if isinstance(techs, list):
                results.extend(techs)

        return {
            "status": "success",
            "results": results,
            "total_technologies": len(results),
        }
