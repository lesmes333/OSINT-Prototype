#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Motor de renderizado con navegador real (Playwright + Firefox), OPCIONAL.

¿Para qué sirve?
  Muchas páginas de filtraciones, paneles de leaks y motores .onion modernos
  cargan su contenido con JavaScript. Una petición `requests` normal solo ve el
  HTML "vacío" inicial y se pierde lo importante. Un navegador de verdad ejecuta
  ese JavaScript y nos deja leer el contenido ya renderizado.

¿Por qué con tanto cuidado?
  Esta VM tiene poca RAM y NO tiene swap. Lanzar Firefox a lo bruto (o varias
  instancias a la vez) puede agotar la memoria y hacer que el kernel mate
  procesos (OOM) — incluso tumbar la máquina. Por eso este módulo es muy
  disciplinado con los recursos:

    1) Importación perezosa: Playwright solo se carga si de verdad se usa.
    2) UN solo navegador headless, reutilizado para todas las páginas.
    3) Concurrencia 1: un hilo trabajador dedicado es el ÚNICO dueño de los
       objetos de Playwright (que NO son seguros entre hilos) y procesa las
       páginas de una en una. Nunca hay dos Firefox a la vez.
    4) Se bloquean imágenes, vídeo, fuentes y CSS: menos RAM y menos ancho de
       banda, que es justo lo que no nos sobra.
    5) Timeout duro por página y cierre garantizado de cada pestaña.
    6) Chequeo de RAM ANTES de arrancar: si hay poca memoria disponible, NO se
       lanza el navegador y se devuelve None para que quien llama use el método
       normal (requests). Es la red de seguridad que faltaba cuando crasheó.
    7) Proxy Tor opcional (socks5://127.0.0.1:9050) para .onion.

Uso típico (con respaldo a requests):

    from .browser_fetch import get_fetcher

    fetcher = get_fetcher(use_tor=True)        # no lanza nada todavía
    html = fetcher.fetch("https://ejemplo/leaks")  # arranca Firefox al 1er uso
    if html is None:
        html = requests.get(url).text          # respaldo si el navegador no va

Acceso 100% pasivo y defensivo: solo se LEE contenido público. No se rellenan
formularios ni se interactúa con sistemas objetivo.
"""

import os
import threading
from queue import Queue
from typing import Optional

from .utils import get_logger

log = get_logger()

# Proxy Tor por defecto (mismo endpoint que el resto de la herramienta).
TOR_SOCKS = os.getenv("TOR_SOCKS", "socks5://127.0.0.1:9050")

# Umbral de RAM disponible (MB) por debajo del cual NO se lanza el navegador.
# Firefox headless ronda 300-500 MB; dejamos margen porque no hay swap.
MIN_RAM_MB = int(os.getenv("BROWSER_MIN_RAM_MB", "700"))

# Tiempo máximo por página (segundos). Configurable por entorno.
DEFAULT_PAGE_TIMEOUT = float(os.getenv("BROWSER_PAGE_TIMEOUT", "30"))

# Recursos que se descartan para ahorrar RAM y ancho de banda.
_BLOCKED_RESOURCES = {"image", "media", "font", "stylesheet"}

# User-Agent realista (mismo perfil que usamos vía Tor en el resto del código).
_UA = ("Mozilla/5.0 (Windows NT 10.0; rv:115.0) "
       "Gecko/20100101 Firefox/115.0")


def _mem_available_mb() -> int:
    """Lee MemAvailable de /proc/meminfo en MB. Si no se puede, no bloquea."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:  # noqa: BLE001
        return 1_000_000  # desconocido → no bloquear
    return 1_000_000


class BrowserFetcher:
    """
    Renderizador de páginas con Firefox headless, seguro en memoria.

    Toda la interacción con Playwright ocurre en UN hilo trabajador dedicado
    (self._worker). Los demás hilos solo encolan trabajos y esperan el
    resultado, así que nunca se tocan objetos de Playwright desde dos hilos.
    """

    def __init__(self,
                 use_tor: bool = False,
                 page_timeout: float = DEFAULT_PAGE_TIMEOUT,
                 min_ram_mb: int = MIN_RAM_MB):
        self.use_tor = use_tor
        self.page_timeout = page_timeout
        self.min_ram_mb = min_ram_mb

        self._queue: "Queue" = Queue()
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()         # protege el arranque perezoso
        self._ready = threading.Event()        # el worker avisa cuando está listo
        self._started = False                  # ya se intentó arrancar
        self._ok = False                       # el navegador arrancó bien
        self._fatal: Optional[str] = None      # motivo si no se pudo usar

    # ── API pública ────────────────────────────────────────────────────────
    def is_available(self) -> bool:
        """¿Hay navegador utilizable? Arranca perezosamente la primera vez."""
        return self._ensure_started()

    def fetch(self, url: str, timeout: Optional[float] = None) -> Optional[str]:
        """
        Devuelve el HTML renderizado de `url`, o None si el navegador no está
        disponible o la página falla. Quien llama debe tener un respaldo
        (p. ej. requests) cuando recibe None.
        """
        if not self._ensure_started():
            return None

        budget = timeout or self.page_timeout
        box = {"event": threading.Event(), "html": None, "error": None}
        self._queue.put((url, budget, box))
        # Esperamos un poco más que el timeout de página para dar margen al worker.
        if not box["event"].wait(timeout=budget + 15):
            log.debug(f"    [!] browser_fetch: sin respuesta para {url} (timeout)")
            return None
        if box["error"]:
            log.debug(f"    [!] browser_fetch: {url} → {box['error']}")
            return None
        return box["html"]

    def close(self) -> None:
        """Apaga el navegador y libera RAM. Idempotente."""
        with self._lock:
            if self._worker and self._worker.is_alive():
                self._queue.put(None)  # señal de parada
                self._worker.join(timeout=15)
            self._worker = None
            self._started = False
            self._ok = False

    # ── Interno ──────────────────────────────────────────────────────────────
    def _ensure_started(self) -> bool:
        with self._lock:
            if self._started:
                return self._ok
            self._started = True

            avail = _mem_available_mb()
            if avail < self.min_ram_mb:
                self._fatal = (f"RAM disponible {avail}MB < {self.min_ram_mb}MB; "
                               f"no se lanza Firefox (sin swap, riesgo OOM)")
                log.warning(f"    [!] browser_fetch: {self._fatal}")
                self._ok = False
                return False

            self._worker = threading.Thread(
                target=self._run, name="browser-fetcher", daemon=True)
            self._worker.start()

        # Esperamos (fuera del lock) a que el worker confirme arranque.
        self._ready.wait(timeout=90)
        if not self._ok and self._fatal:
            log.warning(f"    [!] browser_fetch: {self._fatal}")
        return self._ok

    def _route(self, route) -> None:
        """Aborta recursos pesados (imágenes, fuentes, CSS, vídeo)."""
        try:
            if route.request.resource_type in _BLOCKED_RESOURCES:
                route.abort()
            else:
                route.continue_()
        except Exception:  # noqa: BLE001
            try:
                route.continue_()
            except Exception:  # noqa: BLE001
                pass

    def _run(self) -> None:
        """Bucle del hilo trabajador: arranca Firefox y sirve páginas de una en una."""
        pw = browser = context = None
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:  # noqa: BLE001
            self._fatal = f"Playwright no instalado: {e}"
            self._ok = False
            self._ready.set()
            return

        try:
            pw = sync_playwright().start()
            launch_kwargs = {
                "headless": True,
                # Flags de bajo consumo de memoria.
                "firefox_user_prefs": {
                    "browser.cache.disk.enable": False,
                    "browser.cache.memory.enable": False,
                    "permissions.default.image": 2,   # no cargar imágenes
                    "media.autoplay.default": 5,
                },
            }
            if self.use_tor:
                launch_kwargs["proxy"] = {"server": TOR_SOCKS}

            browser = pw.firefox.launch(**launch_kwargs)
            context = browser.new_context(
                user_agent=_UA,
                java_script_enabled=True,
                viewport={"width": 1280, "height": 800},
            )
            context.route("**/*", self._route)
            self._ok = True
            log.info("   [*] browser_fetch: Firefox headless listo"
                     + (" (vía Tor)" if self.use_tor else ""))
        except Exception as e:  # noqa: BLE001
            self._fatal = f"no se pudo lanzar Firefox: {e}"
            self._ok = False
            self._ready.set()
            # Limpieza parcial si quedó algo a medias.
            try:
                if browser:
                    browser.close()
                if pw:
                    pw.stop()
            except Exception:  # noqa: BLE001
                pass
            return

        self._ready.set()  # ya se puede atender

        # Bucle de servicio: una página a la vez.
        while True:
            job = self._queue.get()
            if job is None:  # señal de parada
                break
            url, budget, box = job
            try:
                page = context.new_page()
                try:
                    page.goto(url, timeout=int(budget * 1000),
                              wait_until="domcontentloaded")
                    box["html"] = page.content()
                finally:
                    page.close()
            except Exception as e:  # noqa: BLE001
                box["error"] = str(e)
            finally:
                box["event"].set()

        # Apagado ordenado.
        try:
            context.close()
            browser.close()
            pw.stop()
        except Exception:  # noqa: BLE001
            pass
        log.debug("   [*] browser_fetch: Firefox apagado")


# ── Singleton de proceso ───────────────────────────────────────────────────────
# Un único navegador para todo el escaneo: arrancarlo es caro y consume RAM,
# así que se comparte. get_fetcher() NO lanza nada hasta el primer fetch().
_INSTANCE: Optional[BrowserFetcher] = None
_INSTANCE_LOCK = threading.Lock()


def get_fetcher(use_tor: bool = False) -> BrowserFetcher:
    """Devuelve el navegador compartido del proceso (lo crea si no existe)."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = BrowserFetcher(use_tor=use_tor)
        return _INSTANCE


def close_fetcher() -> None:
    """Apaga el navegador compartido al final del escaneo (libera RAM)."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is not None:
            _INSTANCE.close()
            _INSTANCE = None
