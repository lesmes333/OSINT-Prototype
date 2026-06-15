#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilidades compartidas por todos los módulos OSINT.

Incluye:
- Un logger central configurable (verbosidad ajustable, sin ruido de "DEBUG" suelto).
- Una sesión HTTP reutilizable con reintentos automáticos y User-Agent realista.
- Helpers de concurrencia (run_parallel) para acelerar fases que hacen muchas
  llamadas independientes (descubrimiento, threat intel, verificación de hosts...).
- Validación de dominios y normalización de subdominios.
"""

import logging
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
    _RETRY_AVAILABLE = True
except Exception:  # pragma: no cover
    _RETRY_AVAILABLE = False


# ============================================================
# LOGGING
# ============================================================
_LOGGER_NAME = "osint"
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def get_logger() -> logging.Logger:
    """Devuelve el logger central del proyecto (configúralo con setup_logging)."""
    return logging.getLogger(_LOGGER_NAME)


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """
    Configura el logger global.
    :param verbose: muestra mensajes DEBUG (detalle interno).
    :param quiet: solo muestra WARNING y errores.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.handlers.clear()

    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


# ============================================================
# SESIÓN HTTP CON REINTENTOS
# ============================================================
def make_session(
    retries: int = 2,
    backoff: float = 0.5,
    user_agent: str = _DEFAULT_UA,
    pool_size: int = 32,
) -> requests.Session:
    """
    Crea una sesión requests con reintentos automáticos ante errores transitorios
    (timeouts, 429, 5xx) y un pool de conexiones amplio para uso concurrente.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})

    if _RETRY_AVAILABLE:
        retry = Retry(
            total=retries,
            connect=retries,
            read=retries,
            backoff_factor=backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size
        )
    else:  # pragma: no cover
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)

    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ============================================================
# CONCURRENCIA
# ============================================================
def run_parallel(
    func: Callable,
    items: Iterable,
    max_workers: int = 10,
    label: Optional[str] = None,
) -> List[Tuple[Any, Any]]:
    """
    Ejecuta `func(item)` en paralelo sobre cada elemento de `items`.

    Devuelve una lista de tuplas (item, resultado). Si una tarea lanza una
    excepción, el resultado será la propia excepción (no detiene al resto).

    :param max_workers: número de hilos concurrentes.
    :param label: texto opcional para depuración.
    """
    items = list(items)
    if not items:
        return []

    logger = get_logger()
    workers = max(1, min(max_workers, len(items)))
    results: List[Tuple[Any, Any]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_item = {executor.submit(func, item): item for item in items}
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                results.append((item, future.result()))
            except Exception as exc:  # noqa: BLE001
                if label:
                    logger.debug(f"    [!] Error en {label} para {item}: {exc}")
                results.append((item, exc))
    return results


def run_named_parallel(tasks: dict, max_workers: int = 13) -> dict:
    """
    Ejecuta un diccionario {nombre: callable_sin_argumentos} en paralelo.
    Devuelve {nombre: resultado}. Las excepciones se capturan por tarea.
    Ideal para lanzar varias APIs a la vez.
    """
    if not tasks:
        return {}

    logger = get_logger()
    results: dict = {}
    workers = max(1, min(max_workers, len(tasks)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_name = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"    [!] Tarea '{name}' falló: {exc}")
                results[name] = {"status": "error", "message": str(exc)}
    return results


# ============================================================
# VALIDACIÓN / NORMALIZACIÓN DE DOMINIOS
# ============================================================
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def is_valid_domain(domain: str) -> bool:
    """Valida que el string tenga forma de dominio (FQDN)."""
    if not domain or len(domain) > 253:
        return False
    return _DOMAIN_RE.match(domain) is not None


def clean_subdomain(sub: str, base_domain: str) -> Optional[str]:
    """
    Normaliza un subdominio: quita esquemas, puertos, wildcards y espacios.
    Devuelve None si no pertenece al dominio base o no es válido.
    """
    if not sub or not isinstance(sub, str):
        return None
    sub = sub.strip().lower()
    # Quitar esquema y ruta
    sub = re.sub(r"^[a-z]+://", "", sub)
    sub = sub.split("/")[0]
    # Quitar puerto y credenciales
    sub = sub.split(":")[0]
    sub = sub.split("@")[-1]
    # Quitar wildcard y punto inicial
    sub = sub.lstrip("*.").strip(".")
    if not sub:
        return None
    if sub == base_domain or sub.endswith("." + base_domain):
        return sub
    return None


# Bloqueo para impresiones thread-safe si fuera necesario
print_lock = threading.Lock()
