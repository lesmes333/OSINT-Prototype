#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilidades de OPSEC y resiliencia para acceso a la dark web vía Tor.

Centraliza todo lo relativo a "tocar" servicios .onion / clearnet de forma
sigilosa y robusta, para no repetir lógica en cada módulo:

  · Rotación de User-Agents realistas (no destacar como bot/scraper).
  · Aislamiento de circuito Tor por sesión (stream isolation vía SOCKS auth):
    cada sesión obtiene un circuito distinto, de modo que un .onion caído o
    lento no contamina al resto y se distribuye la carga entre nodos de salida.
  · Reintentos con backoff exponencial + jitter para onions inestables
    (los hidden services fallan/timeout con frecuencia; un único intento
    pierde demasiados hits reales).
  · Pausas con jitter entre peticiones para parecer tráfico humano.
  · Renovación de identidad Tor (NEWNYM) opcional vía puerto de control.

Todo es pasivo: solo se realizan peticiones GET de lectura sobre contenido
público indexado. No se interactúa con formularios, logins ni se envían datos.
"""

import random
import string
import time
from typing import Dict, Optional

import requests

from .utils import get_logger

log = get_logger()

# ── Configuración Tor ─────────────────────────────────────────────────────────
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051

# ── Pool de User-Agents realistas ─────────────────────────────────────────────
# Mezcla de Tor Browser (Firefox ESR sobre Windows/Linux/Mac) y navegadores
# comunes. El Tor Browser real anuncia siempre una UA de Firefox ESR uniforme;
# para clearnet conviene variar más. Se rota por sesión para difuminar el patrón.
USER_AGENTS = [
    # Tor Browser (Firefox ESR) — lo esperado en .onion
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:115.0) Gecko/20100101 Firefox/115.0",
    # Navegadores clearnet comunes — para fuentes no-onion
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def pick_user_agent(tor_only: bool = False) -> str:
    """
    Devuelve un User-Agent al azar del pool.

    :param tor_only: si True, restringe a UAs de Tor Browser (Firefox ESR),
                     lo correcto para peticiones a servicios .onion donde una
                     UA de Chrome resultaría sospechosa.
    """
    pool = [ua for ua in USER_AGENTS if "Firefox/115" in ua] if tor_only else USER_AGENTS
    return random.choice(pool)


def _random_isolation_tag(length: int = 12) -> str:
    """Genera una credencial SOCKS aleatoria para forzar un circuito Tor nuevo."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def tor_proxies(isolate: bool = True) -> Dict[str, str]:
    """
    Construye el dict de proxies SOCKS5h para Tor.

    Con `isolate=True` se añade un par usuario:contraseña aleatorio. Tor trata
    cada combinación SOCKS distinta como un *stream* aislado (IsolateSOCKSAuth,
    activo por defecto), lo que fuerza un circuito independiente por sesión.
    Esto reparte las peticiones entre nodos de salida y evita que un único
    circuito lento/bloqueado tumbe todo el escaneo.

    Se usa socks5h:// (la 'h') para que la resolución DNS la haga Tor — requisito
    para resolver direcciones .onion y evitar fugas DNS al resolver clearnet.
    """
    if isolate:
        user = _random_isolation_tag()
        pwd = _random_isolation_tag()
        auth = f"{user}:{pwd}@"
    else:
        auth = ""
    proxy = f"socks5h://{auth}{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    return {"http": proxy, "https": proxy}


def tor_session(timeout: int = 20, isolate: bool = True,
                tor_only_ua: bool = True) -> requests.Session:
    """
    Crea una sesión requests enrutada por Tor con UA rotativa y circuito aislado.

    :param isolate:     circuito Tor independiente para esta sesión (recomendado).
    :param tor_only_ua: usar exclusivamente UAs de Tor Browser (para .onion).
    El timeout se aplica por petición (ver request_with_retry), no se guarda aquí.
    """
    s = requests.Session()
    s.proxies.update(tor_proxies(isolate=isolate))
    s.headers.update({
        "User-Agent": pick_user_agent(tor_only=tor_only_ua),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    })
    return s


def clearnet_session(timeout: int = 20) -> requests.Session:
    """Sesión clearnet (sin Tor) con UA rotativa, para fuentes no-onion."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": pick_user_agent(tor_only=False),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
    })
    return s


def jitter_sleep(base: float = 1.0, spread: float = 1.5) -> None:
    """
    Pausa `base` segundos + un jitter aleatorio en [0, spread).

    Evita un patrón de peticiones perfectamente regular (delator de bot) y
    reduce la presión sobre servicios .onion frágiles. Llamar entre peticiones
    secuenciales al mismo host; en paralelo el propio reparto ya introduce
    variación.
    """
    time.sleep(base + random.uniform(0, spread))


def request_with_retry(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    timeout: int = 20,
    retries: int = 2,
    backoff: float = 1.5,
    rotate_circuit_on_fail: bool = True,
    accept_status=(200, 206),
    **kwargs,
) -> Optional[requests.Response]:
    """
    Realiza una petición tolerante a fallos de servicios .onion inestables.

    Reintenta ante timeouts / errores de conexión / códigos no aceptados, con
    backoff exponencial + jitter. Si `rotate_circuit_on_fail` y la sesión usa
    Tor, renueva el circuito (nuevas credenciales SOCKS) entre reintentos para
    esquivar un nodo de salida lento o un circuito roto.

    Devuelve la Response si el status está en `accept_status`, o None si se
    agotan los reintentos. Nunca lanza excepción (registra en debug).

    :param accept_status: tupla de códigos HTTP considerados "éxito".
    """
    last_err = ""
    uses_tor = any("socks5" in str(p) for p in session.proxies.values())

    for attempt in range(retries + 1):
        try:
            resp = session.request(method, url, timeout=timeout,
                                   allow_redirects=True, **kwargs)
            if resp.status_code in accept_status:
                return resp
            last_err = f"HTTP {resp.status_code}"
            # 4xx persistentes (403/404) rara vez se arreglan reintentando
            if resp.status_code in (400, 401, 403, 404, 410):
                log.debug("request_with_retry %s: %s (no se reintenta)", url[:60], last_err)
                return None
        except requests.exceptions.RequestException as e:
            last_err = str(e)[:80]

        if attempt < retries:
            if rotate_circuit_on_fail and uses_tor:
                session.proxies.update(tor_proxies(isolate=True))
                session.headers["User-Agent"] = pick_user_agent(tor_only=True)
            sleep_for = backoff * (2 ** attempt) + random.uniform(0, 1.0)
            log.debug("request_with_retry %s: intento %d falló (%s) → espera %.1fs",
                      url[:60], attempt + 1, last_err, sleep_for)
            time.sleep(sleep_for)

    log.debug("request_with_retry %s: agotados %d reintentos (%s)",
              url[:60], retries, last_err)
    return None


def renew_tor_identity(control_port: int = TOR_CONTROL_PORT,
                       password: str = "") -> bool:
    """
    Solicita un nuevo circuito global a Tor vía señal NEWNYM (puerto de control).

    Best-effort: requiere que el ControlPort esté habilitado en torrc. Devuelve
    True si la señal se envió correctamente. Para escaneos normales basta con el
    aislamiento por sesión (tor_proxies(isolate=True)); esto es para forzar una
    rotación completa de identidad de forma puntual.

    Nota: tras NEWNYM conviene esperar unos segundos a que Tor construya circuitos.
    """
    try:
        import socket as _socket
        with _socket.create_connection((TOR_SOCKS_HOST, control_port), timeout=5) as sock:
            if password:
                sock.sendall(f'AUTHENTICATE "{password}"\r\n'.encode())
            else:
                sock.sendall(b"AUTHENTICATE\r\n")
            if b"250" not in sock.recv(1024):
                log.debug("renew_tor_identity: autenticación rechazada")
                return False
            sock.sendall(b"SIGNAL NEWNYM\r\n")
            ok = b"250" in sock.recv(1024)
            if ok:
                log.info("   [*] Tor: nueva identidad solicitada (NEWNYM)")
            return ok
    except Exception as e:  # noqa: BLE001
        log.debug("renew_tor_identity: %s", str(e)[:80])
        return False
