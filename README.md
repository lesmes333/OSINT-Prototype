<div align="center">

# 🔍 OSINT Recon Suite

**Reconocimiento pasivo de activos · Threat Intel · Fingerprinting · CVEs · INCIBE-CERT · Dark Web**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Rich UI](https://img.shields.io/badge/UI-rich-ff69b4.svg)](https://github.com/Textualize/rich)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-opcional-blue.svg)](https://www.docker.com/)

*Created by **Cristian & Luisber***

</div>

---

## 📌 ¿Qué hace?

Herramienta OSINT (Open Source Intelligence) para **descubrir los activos expuestos** de un dominio en Internet, **identificar las tecnologías** que usan, **correlacionar vulnerabilidades (CVEs)** y exploits públicos, **referenciar INCIBE-CERT** 🇪🇸 y **vigilar la dark web** (Tor).

> ✅ Solo consulta **fuentes públicas indexadas**. No interactúa de forma intrusiva con los sistemas objetivo. Uso **exclusivamente para auditorías defensivas autorizadas y fines educativos**.

---

## 🎯 Funcionalidades

| Fase | Qué hace | Fuentes |
|------|----------|---------|
| **1. Descubrimiento** | Subdominios + DNS + WHOIS + actividad de hosts | crt.sh, certspotter, HackerTarget, RapidDNS, Anubis, OTX, Wayback, DNSdumpster, Subfinder |
| **2. Threat Intel** | Reputación, puertos, geolocalización, emails, menciones | 13 APIs (Shodan, VirusTotal, Censys, AbuseIPDB, Hunter…) |
| **2.5. Tecnologías + CVEs** | Fingerprinting → CVEs → exploits → **INCIBE-CERT** | Wappalyzer, NVD, Exploit-DB, **INCIBE-CERT** |
| **4. Exposición y filtraciones** | Brechas de datos + leaks en fuentes abiertas + dark web + Pastebin (+ Tor opcional) | XposedOrNot, URLScan, GitHub, Pastebin Pro, IntelX, Tor |
| **3. Informes** | JSON · CSV · Markdown · **HTML visual** | — |

### ⚡ Rápido por diseño
Todas las fases con llamadas independientes se ejecutan **en paralelo** (subdominios, las 13 APIs, verificación de hosts, fingerprinting, exploits). Las peticiones HTTP llevan **reintentos automáticos** ante errores transitorios (429/5xx).

### 🛡️ Monitorización de exposición y filtraciones (Fase 4)

Detecta exposición del dominio en fuentes públicas, deep web y dark web **legalmente accesibles**, por cinco capas (todo defensivo y no intrusivo):

| Capa | Qué busca | Fuentes | Requiere |
|------|-----------|---------|----------|
| **1. Brechas de datos** | Correos y credenciales del dominio en filtraciones conocidas | XposedOrNot (gratis) · HIBP · **LeakCheck** (gratis 5/día) · **Dehashed** | — / `HIBP_API_KEY` / `LEAKCHECK_API_KEY` / `DEHASHED_*` |
| **2. Índice dark web** | Menciones del dominio en motores .onion | **Ahmia .onion · OnionLand · DarkSearch · Haystak** (todos vía Tor) · IntelX (pago) | `--tor` + Tor en `:9050` / `INTELX_API_KEY` |
| **3. Leaks en fuentes abiertas** | Historial público + repos + Pastebin | URLScan · GitHub · **Pastebin/archive vía Tor** (gratis) · Pastebin Pro · IntelX | `URLSCAN_API_KEY`, `GITHUB_TOKEN`, `PASTEBIN_API_KEY`* |
| **4. Ransomware & Ciberataques** | Si el dominio aparece en leak sites de grupos de ransomware activos + reputación de dominio | **ransomware.live · RansomLook · Maltiverse** (todos gratis, sin clave) | — |
| **5. Crawling .onion** | Análisis profundo de páginas `.onion` con contenido amenazante | Tor + Ahmia .onion + Haystak + Torch + 15 motores adicionales | `--tor` + Tor en `:9050` |
| **6. Foros / Leak sites / Infostealers** | Búsqueda activa en fuentes dark web conocidas: foros de credenciales, acceso directo a 80+ leak sites de ransomware, inteligencia de infostealers, Telegram público | **80+ leak sites .onion** directos · **BreachForums** (.onion+clearnet) · **XSS.is, Nulled.to, Cracked.io, exploit.in** · **Ahmia+OnionLand+Haystak+Torch+DarkSearch** (motores .onion) · **Hudson Rock** (infostealers gratis) · **Pulsedive** (domain intel) · **14 canales Telegram** públicos · DeepPaste + Ghostbin + paste.ee + Justpaste.it | `--tor` (recomendado para máxima cobertura) |

> \* **Pastebin Pro** (`PASTEBIN_API_KEY`): opcional, para monitorizar el feed de Pastebin en tiempo real. Requiere cuenta Pro en [pastebin.com/pro](https://pastebin.com/pro) ($8.95/mes). Sin ella, la Capa 3 usa el **archivo público de Pastebin vía Tor** como alternativa gratuita.

> 💡 **Capa 6 (Dark web real) sin coste:** la herramienta accede directamente a **80+ leak sites `.onion`** de grupos de ransomware activos, busca en BreachForums, XSS.is, foros rusos de credenciales, consulta **Hudson Rock** (infostealer intelligence) y busca en **14 canales Telegram públicos** de filtraciones — todo gratis, sin claves de pago. Esto cubre lo que herramientas comerciales de *dark web monitoring* (DarkOwl, Flare.io, Recorded Future) cobran a $500–$5.000/mes.

> ⚠️ **Sobre Ahmia en clearnet:** Ahmia.fi clearnet redirige a su homepage sin devolver resultados (requiere Tor Browser). La herramienta accede directamente al `.onion` de Ahmia vía Tor, evitando el problema. Usa `--tor` para activar las búsquedas en motores .onion.

**Correos:** se descubren **automáticamente** desde Hunter.io durante el escaneo. No es necesario configurar `MONITOR_EMAILS`.

**Sin ninguna clave de pago**, la Fase 4 funciona con: XposedOrNot + XposedOrNot domain-level + URLScan + GitHub + Pastebin/Tor + **todos los motores .onion** (con Tor) + ransomware.live + RansomLook + Maltiverse + **Capa 6 completa** (80 leak sites + foros + infostealers + Telegram).

> ✅ Solo se consultan índices y APIs públicas. No se accede a sistemas ajenos ni se descarga contenido ilegal. Acorde con un marco defensivo y autorizado.

### 🔎 Extracción y exportación de IOCs

Todo el texto recolectado en la dark web (foros, leak sites, paste sites, canales Telegram, motores `.onion`) pasa por un **extractor de IOCs** (`ioc_extractor.py`) que detecta y deduplica indicadores accionables:

| Tipo | Detecta |
|------|---------|
| **Emails** | Correos sueltos y, resaltados, los del dominio objetivo |
| **Credenciales** | Pares `email:contraseña` y `usuario:contraseña` (formato combolist) |
| **Dominios / subdominios** | Dominios mencionados y subdominios del objetivo |
| **IPs** | IPv4 e IPv6 **públicas** (descarta privadas/reservadas) |
| **Hashes** | MD5 · SHA1 · SHA256 · SHA512 |
| **Wallets** | Bitcoin (BTC) · Ethereum (ETH) · Monero (XMR) |
| **Otros** | CVEs · servicios `.onion` |

Los IOCs se incluyen en el informe JSON y, además, se exportan a archivos propios listos para ingerir en un **SIEM/TIP**:

- `iocs_<dominio>_<fecha>.json` — estructurado, con conteo por tipo.
- `iocs_<dominio>_<fecha>.csv` — una fila por IOC (`tipo,valor`).

> Los regex están validados (p. ej. las IPv6 se confirman con `ipaddress`, no por regex puro) y filtran falsos positivos comunes (fragmentos de email, nombres de fichero `.txt`/`.sql`, etc.).

### 🌐 Búsqueda agresiva y multilingüe

La búsqueda de fugas combina el dominio con vocabulario real de brecha en **inglés, español y ruso** (`generate_breach_queries()`): `leak`, `dump`, `database`, `combolist`, `filtracion`, `contraseñas`, `слив`, `база`, `дамп`… además de variantes con año, `www`, `@dominio` y patrones de fichero de dump. Esto saca a la luz dumps que no aparecen buscando solo el dominio.

### 🥷 OPSEC y resiliencia (Tor)

El acceso a `.onion` es sigiloso y tolerante a fallos (`tor_utils.py`):

- **Rotación de User-Agents** (Tor Browser para `.onion`).
- **Aislamiento de circuito** por sesión (stream isolation vía SOCKS auth): reparte la carga y aísla servicios `.onion` caídos.
- **Reintentos con backoff + jitter** y rotación de circuito ante timeouts (los hidden services fallan a menudo; un solo intento pierde hits reales).

### 🇪🇸 Integración con INCIBE-CERT
Cada CVE detectado se **enlaza con su ficha en español** de la *Alerta Temprana* de INCIBE-CERT (verificando que existe). Las que están en alerta temprana reciente se marcan con ⚠️, y además se cruzan las tecnologías detectadas con el feed reciente.

### 🩺 Diagnóstico automático
Al terminar, la herramienta indica qué **API keys están caducadas/inválidas o sin cuota** (con el enlace para renovarlas y actualizar tu `.env`) y qué **herramientas externas** faltan (con el comando para instalarlas). **El escaneo nunca se detiene por estos fallos**: continúa y los documenta.

---

## 🖥️ Interfaz visual en terminal

```
╔═════════════════════════════ OSINT RECON SUITE ══════════════════════════════╗
║                     ███████ ███████ ██ ███    ██ ████████                     ║
║                     ...     ★ Created by Cristian & Luisber ★                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
Paneles por fase, tablas con colores, **severidades coloreadas** (🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW), avisos de claves a renovar y un panel de resumen final. Si `rich` no está instalado, degrada a texto plano automáticamente.

El **informe HTML** es autocontenido (tema oscuro, tarjetas de resumen, badges de severidad) y se abre directamente en el navegador.

---

## 🚀 Instalación

La instalación tiene **dos niveles**:

1. **Núcleo (obligatorio)** → Python + las dependencias de `requirements.txt`. Con esto ya funciona el descubrimiento de subdominios, DNS, WHOIS, Threat Intel y los informes.
2. **Herramientas externas (opcionales)** → Docker, Tor, subfinder y searchsploit. Solo hacen falta si quieres las fases de fingerprinting, dark web o exploits.

> 💡 Sigue los pasos **en orden**. Cada herramienta externa es independiente: instala solo las que vayas a usar.

---

### 🧱 Paso 0 — Requisitos previos del sistema

Antes de nada, asegúrate de tener instalado en la máquina:

| Requisito | Versión | Comprobar | Instalar si falta |
|-----------|---------|-----------|-------------------|
| **Python** | 3.9 o superior | `python3 --version` | macOS: `brew install python` · Ubuntu/Debian: `sudo apt install python3 python3-venv python3-pip` · Windows: [python.org](https://www.python.org/downloads/) (marca *“Add to PATH”*) |
| **pip** | reciente | `python3 -m pip --version` | Viene con Python; actualiza con `python3 -m pip install --upgrade pip` |
| **git** | cualquiera | `git --version` | macOS: `brew install git` · Ubuntu/Debian: `sudo apt install git` · Windows: [git-scm.com](https://git-scm.com/) |

---

### ⚙️ Paso 1 — Instalar el núcleo (obligatorio)

#### Opción A — Script automático (macOS / Linux)
```bash
git clone https://github.com/lesmes333/OSINT-Prototype.git
cd OSINT-Prototype
bash install.sh
```
El script crea el entorno virtual, instala las dependencias y prepara el `.env`.

> ⚠️ **Importante:** `install.sh` instala todo dentro del entorno virtual (`venv/`), pero **NO deja el venv activado en tu terminal**. Antes de ejecutar la herramienta tienes que activarlo tú (ver el paso siguiente). Si lanzas `python3 main.py` sin activar el venv, usará el Python del sistema y verás errores como `ModuleNotFoundError: No module named 'dotenv'`.

#### Opción B — Manual (macOS / Linux / Windows)
```bash
# 1) Clonar el repositorio
git clone https://github.com/lesmes333/OSINT-Prototype.git
cd OSINT-Prototype

# 2) Crear y activar el entorno virtual
python3 -m venv venv
source venv/bin/activate          # Windows (PowerShell): venv\Scripts\Activate.ps1
                                  # Windows (CMD):        venv\Scripts\activate.bat

# 3) Actualizar pip e instalar las dependencias de Python
python3 -m pip install --upgrade pip
pip install -r requirements.txt

# 4) (Opcional pero recomendado) Configurar las API keys
cp .env.example .env              # Windows: copy .env.example .env
nano .env                         # añade tus claves: Shodan, VirusTotal, Hunter…
```

> ✅ La herramienta **funciona sin API keys**: el descubrimiento de subdominios usa 9 fuentes públicas gratuitas. Las claves solo **amplían** la información de Threat Intel (ver [tabla de claves](#-configurar-api-keys-env)).

#### ▶️ Activar el venv y comprobar que funciona

**Cada vez** que abras una terminal nueva para usar la herramienta, primero activa el entorno virtual:

```bash
cd OSINT-Prototype
source venv/bin/activate          # Windows (PowerShell): venv\Scripts\Activate.ps1
```
Verás que el prompt cambia a `(venv)`. A partir de ahí ya puedes usar `python` (sin el `3`). Para salir del venv: `deactivate`.

```bash
# Con el venv activado:
python main.py -d ejemplo.com -y --no-darkweb --no-fingerprint
```

> 💡 **¿`python: command not found`?** En Ubuntu/Debian el binario del sistema es `python3` (no `python`). Tienes dos soluciones:
> - **Recomendado:** activa el venv (`source venv/bin/activate`) — dentro del venv sí existe `python`.
> - **Sin activar:** llama directamente al Python del venv: `venv/bin/python main.py -d ejemplo.com -y`
>
> Usar el `python3` del sistema (sin venv) **no** funcionará porque las dependencias están instaladas dentro del venv.

---

### 🧰 Paso 2 — Herramientas externas (opcionales, según la fase que quieras)

Cada una habilita **una fase concreta**. Instala solo las que necesites. La herramienta detecta automáticamente cuáles están disponibles y, al terminar el escaneo, te dice en el diagnóstico cuáles faltan y cómo instalarlas.

| Herramienta | Habilita | macOS (Homebrew) | Linux (Debian/Ubuntu) | Windows |
|-------------|----------|------------------|------------------------|---------|
| **subfinder** | Más subdominios | `brew install subfinder` | `sudo apt install subfinder` *(o vía Go, abajo)* | `go install` (abajo) o [release](https://github.com/projectdiscovery/subfinder/releases) |
| **Docker** | Fingerprinting (Wappalyzer) | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | `sudo apt install docker.io` + `sudo usermod -aG docker $USER` | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| **searchsploit** | Exploits (Exploit-DB) | `brew install exploitdb` | clonar desde GitLab (abajo) | [exploitdb en WSL](https://gitlab.com/exploit-database/exploitdb) |
| **Tor** | Dark web | `brew install tor` + `brew services start tor` | `sudo apt install tor` + `sudo systemctl start tor` | [Tor Expert Bundle](https://www.torproject.org/download/tor/) |

> **subfinder vía Go** (si no está en tu gestor de paquetes):
> ```bash
> go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
> ```
> Asegúrate de que `~/go/bin` está en tu `PATH`.

> **searchsploit en Ubuntu/Debian:** el paquete `exploitdb` de `apt` **no existe** en Ubuntu (solo en Kali), y el repo de GitHub está vacío. Clónalo desde **GitLab** (su ubicación oficial) y enlázalo al PATH:
> ```bash
> sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
> sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
> searchsploit apache        # comprobar que funciona
> ```

#### 🔍 Configurar el fingerprinting (Docker + wappalyzer-next)

El fingerprinting necesita **Docker en marcha** y el contenedor de **wappalyzer-next** construido:

```bash
# 1) Arranca Docker (Docker Desktop en macOS/Windows, o el servicio en Linux)
docker info                       # debe responder sin error

# 2) Clona wappalyzer-next dentro del proyecto y construye la imagen
git clone https://github.com/s0md3v/wappalyzer-next.git scripts/wappalyzer-next
cd scripts/wappalyzer-next
docker compose build
cd ../..
```

#### 🧅 Verificar que Tor está corriendo

La fase de dark web requiere Tor escuchando en `127.0.0.1:9050`:

```bash
# macOS:  brew services start tor
# Linux:  sudo systemctl start tor
# Comprueba el puerto:
nc -z 127.0.0.1 9050 && echo "Tor OK" || echo "Tor NO está corriendo"
```

---

### ✅ Resumen rápido de lo que hay que tener instalado

| Para esto… | Necesitas |
|------------|-----------|
| Lo básico (subdominios, DNS, WHOIS, Threat Intel, informes) | **Python 3.9+** + `pip install -r requirements.txt` |
| Más subdominios | **subfinder** |
| Tecnologías + CVEs + INCIBE-CERT | **Docker** + **wappalyzer-next** *(y `nvdlib`, ya en requirements)* |
| Exploits públicos | **searchsploit** (exploitdb) |
| Dark web | **Tor** corriendo en `:9050` *(y `osint-darkweb-pkg`, ya en requirements)* |

---

## ▶️ Uso

### Interactivo (te pregunta el dominio y las fases)
```bash
python main.py
```

### Automático / no interactivo (ideal para recon y lotes)
```bash
# Descubrimiento + Threat Intel, sin preguntas
python main.py -d ejemplo.com -y

# Todas las fases (fingerprint + CVEs + INCIBE + dark web)
python main.py -d ejemplo.com --all

# Activar fases concretas
python main.py -d ejemplo.com --fingerprint --no-darkweb

# Lote de dominios (uno por línea), 60 hilos, sin verificación ICMP/TCP
python main.py -f dominios.txt -y --no-active -t 60

# Elegir formatos y carpeta de salida
python main.py ejemplo.com --all --formats json,html -o resultados
```

### Opciones (`python main.py -h`)

| Opción | Descripción |
|--------|-------------|
| `-d, --domain` | Dominio a analizar (también admite posicional). |
| `-f, --file` | Archivo con lista de dominios (uno por línea). |
| `-y, --yes` | No interactivo: no pregunta nada. |
| `--all` | Ejecuta todas las fases. |
| `--fingerprint / --no-fingerprint` | Activa/desactiva fingerprinting + CVEs + INCIBE. |
| `--darkweb / --no-darkweb` | Activa/desactiva la monitorización de exposición (brechas, Ahmia, pastes). |
| `--tor` | Capa avanzada: crawling `.onion` vía Tor (requiere Tor en `:9050`). Desactivada por defecto. |
| `--no-active` | Omite la verificación ICMP/TCP. |
| `--no-diff` | No compara con el escaneo anterior (desactiva la monitorización). |
| `-t, --threads` | Hilos concurrentes (def: 30). |
| `--formats` | `json,csv,md,html` (def: todos). |
| `-o, --output-dir` | Carpeta de salida (def: `outputs`). |
| `--max-fp-urls` | Máx. URLs para fingerprinting (def: 25). |
| `-q / -v` | Salida mínima / detallada. |

### 🔁 Modo monitorización (diff entre escaneos)

Cada vez que analizas un dominio, la herramienta **compara automáticamente** con el escaneo anterior del mismo dominio (busca el `activos_<dominio>_*.json` previo en la carpeta de salida) y resalta:

- 🆕 **Subdominios nuevos** y ➖ **desaparecidos**
- 🔴 **CVEs nuevos**
- 🔌 **Puertos abiertos nuevos**

El resumen sale en pantalla y se guarda dentro del JSON (`changes_since_last_scan`). Desactívalo con `--no-diff`.

Ideal para vigilancia periódica con **cron**. Ejemplo: escaneo diario a las 8:00 guardando histórico en `outputs/`:
```bash
0 8 * * *  cd /ruta/OSINT-Prototype && venv/bin/python main.py -d ejemplo.com -y --all >> outputs/cron.log 2>&1
```
Como conserva todos los JSON con fecha, cada ejecución se compara con la anterior y verás aparecer lo nuevo.

---

## 📄 Informes generados

Por cada dominio, en `outputs/` (o la carpeta indicada con `-o`):

| Archivo | Contenido |
|---------|-----------|
| `informe_<dominio>_<fecha>.html` | **Informe visual** (abrir en navegador): resumen, diagnóstico, subdominios, DNS, WHOIS, tecnologías, CVEs con severidad y enlaces INCIBE-CERT, dark web. |
| `informe_<dominio>_<fecha>.md` | Mismo contenido en Markdown (para GitHub/lectura rápida). |
| `activos_<dominio>_<fecha>.json` | Datos completos y estructurados (para automatización). |
| `subdominios_<dominio>_<fecha>.csv` | Lista de subdominios con su(s) fuente(s). |
| `iocs_<dominio>_<fecha>.json` | **IOCs** extraídos de la dark web (emails, credenciales, IPs, hashes, wallets, onions) con conteo por tipo. Solo si se detecta alguno. |
| `iocs_<dominio>_<fecha>.csv` | Mismos IOCs, una fila por indicador (`tipo,valor`) — listo para SIEM/TIP. |

---

## 🔑 Configurar API keys (`.env`)

Copia `.env.example` a `.env` y rellena las que tengas. Si una clave caduca o agota su cuota, la herramienta **te avisa al final del escaneo** con el enlace exacto para renovarla:

**Claves gratuitas** (sin coste):

| Servicio | Variable | Obtener clave |
|----------|----------|---------------|
| Shodan | `SHODAN_API_KEY` | https://account.shodan.io |
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| Censys | `CENSYS_PAT` | https://platform.censys.io — ver nota abajo |
| AlienVault OTX | `ALIENVAULT_API_KEY` | https://otx.alienvault.com/settings |
| Hunter.io | `HUNTER_API_KEY` | https://hunter.io/api-keys (25 búsquedas/mes gratis) |
| IPinfo | `IPINFO_API_KEY` | https://ipinfo.io/account/token (50k/mes gratis) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |
| urlscan.io | `URLSCAN_API_KEY` | https://urlscan.io/user/profile/ |
| NVD | `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key |
| GitHub | `GITHUB_TOKEN` | https://github.com/settings/tokens (scope: `public_repo`) |
| GitLab | `GITLAB_TOKEN` | https://gitlab.com/-/profile/personal_access_tokens |
| **LeakCheck** | `LEAKCHECK_API_KEY` | https://leakcheck.io → Registro gratuito → perfil → API (5 búsquedas/día gratis) |

**Claves opcionales de pago** (amplían la Fase 4 — monitorización de exposición):

| Servicio | Variable | Coste | Qué aporta |
|----------|----------|-------|------------|
| **Pastebin Pro** | `PASTEBIN_API_KEY` | $8.95/mes | Monitorización del feed de Pastebin en tiempo real. Obtener en: https://pastebin.com/pro |
| **Intelligence X** | `INTELX_API_KEY` | desde ~1800 USD/año | Búsqueda en dark web, paste sites históricos, buckets S3 expuestos, foros de hacking. El plan gratuito Open Source **no incluye** acceso API. Obtener en: https://intelx.io/product |
| **Have I Been Pwned** | `HIBP_API_KEY` | desde ~3.50 USD/mes | Brechas de datos por email (enriquece XposedOrNot, que es gratis). Obtener en: https://haveibeenpwned.com/API/Key |
| **Dehashed** | `DEHASHED_EMAIL` + `DEHASHED_API_KEY` | $5.49/mes | La BD de credenciales filtradas más grande (~15B registros). Búsqueda por dominio devuelve emails, usuarios, contraseñas, IPs y nombres reales. Obtener en: https://dehashed.com/profile |

> ℹ️ **Nota sobre Censys (nuevo Platform API):** la herramienta usa el **Censys Platform** (https://platform.censys.io):
> - `CENSYS_PAT` → tu **Personal Access Token** (icono de usuario → *API Access* → *Create New Token*; la cadena larga se muestra **solo al crearlo**).
> - `CENSYS_ORG_ID` → **opcional**. El *Organization ID* solo existe en cuentas **de pago** (Starter/Enterprise), en *My Account → Personal Access Tokens → "Current Organization"*. En el **Free Tier no existe**: déjalo vacío.
>
> ⚠️ **Limitación del Free Tier:** las cuentas gratuitas de Censys **solo permiten endpoints de lookup, no de búsqueda**, que es el que usa esta herramienta. Con cuenta gratuita Censys devolverá normalmente 403. La API antigua (`CENSYS_API_ID`/`CENSYS_API_SECRET`) está retirada. Censys es **opcional**: si falla, el escaneo continúa con el resto de fuentes.

---

## 🧩 Solución de problemas

| Síntoma | Causa / solución |
|---------|------------------|
| `Fingerprinting omitido: Docker no disponible` | Arranca Docker Desktop y construye wappalyzer-next (ver instalación). |
| `Tor no está corriendo` | `brew services start tor` o `systemctl start tor`. Comprueba el puerto 9050. |
| Pocas API OK en el diagnóstico | Normal sin claves; añádelas en `.env`. El descubrimiento funciona igual. |
| `searchsploit` no encontrado (Ubuntu) | `apt install exploitdb` no existe en Ubuntu. Clónalo desde GitLab: `sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit`. En macOS: `brew install exploitdb`. |
| Censys da 401/403 | Revisa que `CENSYS_PAT` y `CENSYS_ORG_ID` sean correctos (Platform API en platform.censys.io). El Organization ID es obligatorio además del token. |
| Shodan no devuelve puertos | El plan **gratuito (OSS)** de Shodan no permite el host lookup por API; la herramienta usa **InternetDB** (gratis, sin clave) como alternativa. Si igual sale vacío, es que **Shodan no tiene datos de esa IP** (no es un error). Con clave de pago se usa el endpoint completo automáticamente. |
| Registros DNS vacíos | Tu red/resolver bloquea el puerto 53 saliente; prueba en otra red. |
| Búsqueda de CVEs lenta | Sin `NVD_API_KEY` el límite es estricto (pausas de 6s). Añade la clave para acelerar. |
| Ahmia no devuelve resultados | Ahmia.fi en clearnet redirige a su homepage **sin resultados** (requiere Tor Browser). La herramienta accede al **Ahmia .onion** vía Tor directamente — usa `--tor` para activarlo. |
| IntelX devuelve 403 | El plan "Open Source Intelligence" gratuito **no incluye acceso API** (`/intelligent/search` devuelve 403). Se necesita un plan de pago. |
| Pastebin sin resultados con Pro key | Verifica que la IP está en la whitelist de tu cuenta Pro. Sin key, se usa el archivo público vía Tor (alternativa gratuita). |
| Censys devuelve 403 | El Free Tier de Censys **no permite el endpoint de búsqueda vía API** (solo UI web). El escaneo continúa con las demás fuentes. |
| LeakCheck 403 | Límite diario alcanzado (5 búsquedas/día en plan gratuito). Se resetea cada 24h. |
| `playwright install chromium` falla | En VMs con red restringida, el CDN de Chromium puede estar bloqueado. Usa `playwright install firefox` en su lugar. |

---

## 🗂️ Estructura del proyecto

```
OSINT-Prototype/
├── main.py                      # CLI + orquestación de fases (interfaz rich)
├── requirements.txt
├── .env.example
├── install.sh
└── scripts/modules/
    ├── utils.py                 # Concurrencia, sesión HTTP con reintentos, logging
    ├── ui.py                    # Interfaz visual de terminal (rich)
    ├── discovery.py             # Subdominios (9 fuentes en paralelo) + DNS + WHOIS
    ├── active_check.py          # Actividad de hosts (ICMP/TCP concurrente)
    ├── threat_intel.py          # 13 APIs de threat intelligence en paralelo
    ├── fingerprint.py           # Wappalyzer (Docker) en paralelo
    ├── cve_exploit.py           # CVEs (NVD) + exploits (Exploit-DB) + INCIBE
    ├── incibe.py                # Integración con INCIBE-CERT (alerta temprana)
    ├── diffing.py               # Modo monitorización: compara con el escaneo anterior
    ├── diagnostics.py           # Estado de API keys y herramientas
    ├── exposure.py              # Fase 4: brechas · dark web (6 capas) · ransomware · LeakCheck · IOCs
    ├── darkweb_monitor.py       # Crawling .onion via Tor (Ahmia/Haystak/Torch + multi-motor)
    ├── darkweb_sources.py       # Capa 6: leak sites de ransomware · foros · infostealers · Telegram
    ├── tor_utils.py             # OPSEC/resiliencia Tor: rotación UA · aislamiento de circuito · reintentos
    ├── ioc_extractor.py         # Extracción y export de IOCs (emails, credenciales, IPs, hashes, wallets…)
    └── report.py                # Informes JSON / CSV / Markdown / HTML
```

---

<div align="center">

**OSINT Recon Suite** · Created by **Cristian & Luisber** · Uso responsable y autorizado únicamente.

</div>
