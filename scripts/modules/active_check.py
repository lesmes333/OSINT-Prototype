#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de verificación de actividad de hosts.

Métodos:
  1. ICMP (ping del sistema operativo).
  2. TCP (conexión a uno o varios puertos, p.ej. 80 y 443).

La verificación de múltiples hosts se ejecuta de forma CONCURRENTE mediante un
ThreadPoolExecutor, lo que reduce drásticamente el tiempo cuando hay decenas o
cientos de subdominios.
"""

import platform
import socket
import subprocess
from typing import Dict, List, Sequence, Tuple

from .utils import get_logger, run_parallel

log = get_logger()


class ActiveChecker:
    """Verifica si un host está activo combinando ICMP y TCP, en paralelo."""

    def __init__(self, threads: int = 50):
        self.sistema = platform.system().lower()  # 'windows', 'linux', 'darwin'
        self.threads = threads

    # ------------------------------------------------------------
    # ICMP (ping)
    # ------------------------------------------------------------
    def check_icmp(self, host: str) -> Tuple[bool, str]:
        try:
            if self.sistema == "windows":
                param = ["ping", "-n", "1", "-w", "2000", host]
            else:
                param = ["ping", "-c", "1", "-W", "2", host]
            result = subprocess.run(param, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return True, f"ICMP: {host} responde (Echo Reply)"
            return False, f"ICMP: {host} no responde"
        except subprocess.TimeoutExpired:
            return False, f"ICMP: timeout en {host}"
        except Exception as e:  # noqa: BLE001
            return False, f"ICMP: error - {e}"

    # ------------------------------------------------------------
    # TCP (conexión a un puerto)
    # ------------------------------------------------------------
    def check_tcp(self, host: str, port: int = 80, timeout: int = 3) -> Tuple[bool, str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    return True, f"TCP/{port}: {host} abierto (SYN+ACK)"
            return False, f"TCP/{port}: {host} sin respuesta"
        except ConnectionRefusedError:
            # RST: el host está vivo aunque el puerto esté cerrado
            return True, f"TCP/{port}: {host} vivo (RST, puerto cerrado)"
        except socket.timeout:
            return False, f"TCP/{port}: timeout en {host}"
        except Exception as e:  # noqa: BLE001
            return False, f"TCP/{port}: error - {e}"

    # ------------------------------------------------------------
    # Verificación combinada de un host
    # ------------------------------------------------------------
    def check_host(self, host: str, ports: Sequence[int] = (80, 443)) -> Dict:
        host = host.strip()
        icmp_ok, icmp_msg = self.check_icmp(host)
        if icmp_ok:
            return {
                "host": host,
                "estado": "ACTIVA",
                "metodo_deteccion": "ICMP",
                "puertos_abiertos": [],
                "detalle": icmp_msg,
            }

        # ICMP falló: probar puertos TCP
        abiertos = []
        for port in ports:
            tcp_ok, _ = self.check_tcp(host, port)
            if tcp_ok:
                abiertos.append(port)
        if abiertos:
            return {
                "host": host,
                "estado": "ACTIVA",
                "metodo_deteccion": "TCP",
                "puertos_abiertos": abiertos,
                "detalle": f"TCP abierto en {abiertos}",
            }

        return {
            "host": host,
            "estado": "NO ACTIVA",
            "metodo_deteccion": "ICMP+TCP",
            "puertos_abiertos": [],
            "detalle": "Sin respuesta a ICMP ni TCP",
        }

    # ------------------------------------------------------------
    # Verificación concurrente de múltiples hosts
    # ------------------------------------------------------------
    def check_multiple_hosts(self, hosts: List[str], ports: Sequence[int] = (80, 443)) -> List[Dict]:
        hosts = [h.strip() for h in hosts if h and h.strip()]
        log.info(f"    [*] Verificando {len(hosts)} hosts (concurrencia: {self.threads})...")
        resultados = [
            res
            for _, res in run_parallel(
                lambda h: self.check_host(h, ports), hosts, max_workers=self.threads, label="active_check"
            )
            if isinstance(res, dict)
        ]
        # Ordenar: activos primero, luego alfabético
        resultados.sort(key=lambda r: (r["estado"] != "ACTIVA", r["host"]))
        return resultados

    # ------------------------------------------------------------
    # Resumen estadístico
    # ------------------------------------------------------------
    def generar_resumen(self, resultados: List[Dict]) -> Dict:
        total = len(resultados)
        activos = sum(1 for r in resultados if r.get("estado") == "ACTIVA")
        return {
            "total_hosts": total,
            "activos": activos,
            "no_activos": total - activos,
            "detectados_por_icmp": sum(
                1 for r in resultados if r.get("estado") == "ACTIVA" and r.get("metodo_deteccion") == "ICMP"
            ),
            "detectados_por_tcp": sum(
                1 for r in resultados if r.get("estado") == "ACTIVA" and r.get("metodo_deteccion") == "TCP"
            ),
            "porcentaje_actividad": round((activos / total) * 100, 2) if total else 0,
        }
