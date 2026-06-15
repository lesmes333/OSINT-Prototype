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
| **4. Dark Web** | Búsqueda multi-motor + crawling de `.onion` | Ahmia + Tor |
| **3. Informes** | JSON · CSV · Markdown · **HTML visual** | — |

### ⚡ Rápido por diseño
Todas las fases con llamadas independientes se ejecutan **en paralelo** (subdominios, las 13 APIs, verificación de hosts, fingerprinting, exploits). Las peticiones HTTP llevan **reintentos automáticos** ante errores transitorios (429/5xx).

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

**Comprobar que el núcleo funciona:**
```bash
python main.py -d ejemplo.com -y --no-darkweb --no-fingerprint
```

---

### 🧰 Paso 2 — Herramientas externas (opcionales, según la fase que quieras)

Cada una habilita **una fase concreta**. Instala solo las que necesites. La herramienta detecta automáticamente cuáles están disponibles y, al terminar el escaneo, te dice en el diagnóstico cuáles faltan y cómo instalarlas.

| Herramienta | Habilita | macOS (Homebrew) | Linux (Debian/Ubuntu) | Windows |
|-------------|----------|------------------|------------------------|---------|
| **subfinder** | Más subdominios | `brew install subfinder` | `sudo apt install subfinder` *(o vía Go, abajo)* | `go install` (abajo) o [release](https://github.com/projectdiscovery/subfinder/releases) |
| **Docker** | Fingerprinting (Wappalyzer) | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | `sudo apt install docker.io` + `sudo usermod -aG docker $USER` | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| **searchsploit** | Exploits (Exploit-DB) | `brew install exploitdb` | `sudo apt install exploitdb` | [exploitdb en WSL](https://gitlab.com/exploit-database/exploitdb) |
| **Tor** | Dark web | `brew install tor` + `brew services start tor` | `sudo apt install tor` + `sudo systemctl start tor` | [Tor Expert Bundle](https://www.torproject.org/download/tor/) |

> **subfinder vía Go** (si no está en tu gestor de paquetes):
> ```bash
> go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
> ```
> Asegúrate de que `~/go/bin` está en tu `PATH`.

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
| `--darkweb / --no-darkweb` | Activa/desactiva la dark web. |
| `--no-active` | Omite la verificación ICMP/TCP. |
| `-t, --threads` | Hilos concurrentes (def: 30). |
| `--formats` | `json,csv,md,html` (def: todos). |
| `-o, --output-dir` | Carpeta de salida (def: `outputs`). |
| `--max-fp-urls` | Máx. URLs para fingerprinting (def: 25). |
| `-q / -v` | Salida mínima / detallada. |

---

## 📄 Informes generados

Por cada dominio, en `outputs/` (o la carpeta indicada con `-o`):

| Archivo | Contenido |
|---------|-----------|
| `informe_<dominio>_<fecha>.html` | **Informe visual** (abrir en navegador): resumen, diagnóstico, subdominios, DNS, WHOIS, tecnologías, CVEs con severidad y enlaces INCIBE-CERT, dark web. |
| `informe_<dominio>_<fecha>.md` | Mismo contenido en Markdown (para GitHub/lectura rápida). |
| `activos_<dominio>_<fecha>.json` | Datos completos y estructurados (para automatización). |
| `subdominios_<dominio>_<fecha>.csv` | Lista de subdominios con su(s) fuente(s). |

---

## 🔑 Configurar API keys (`.env`)

Copia `.env.example` a `.env` y rellena las que tengas. Si una clave caduca o agota su cuota, la herramienta **te avisa al final del escaneo** con el enlace exacto para renovarla:

| Servicio | Variable | Obtener clave |
|----------|----------|---------------|
| Shodan | `SHODAN_API_KEY` | https://account.shodan.io |
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| Censys | `CENSYS_API_ID` / `CENSYS_API_SECRET` | https://search.censys.io/account/api |
| AlienVault OTX | `ALIENVAULT_API_KEY` | https://otx.alienvault.com/settings |
| Hunter.io | `HUNTER_API_KEY` | https://hunter.io/api-keys |
| IPinfo | `IPINFO_API_KEY` | https://ipinfo.io/account/token |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |
| urlscan.io | `URLSCAN_API_KEY` | https://urlscan.io/user/profile/ |
| NVD | `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key |
| GitHub | `GITHUB_TOKEN` | https://github.com/settings/tokens |
| GitLab | `GITLAB_TOKEN` | https://gitlab.com/-/profile/personal_access_tokens |

---

## 🧩 Solución de problemas

| Síntoma | Causa / solución |
|---------|------------------|
| `Fingerprinting omitido: Docker no disponible` | Arranca Docker Desktop y construye wappalyzer-next (ver instalación). |
| `Tor no está corriendo` | `brew services start tor` o `systemctl start tor`. Comprueba el puerto 9050. |
| Pocas API OK en el diagnóstico | Normal sin claves; añádelas en `.env`. El descubrimiento funciona igual. |
| `searchsploit` no encontrado | `brew install exploitdb` / `apt install exploitdb` (opcional). |
| Registros DNS vacíos | Tu red/resolver bloquea el puerto 53 saliente; prueba en otra red. |
| Búsqueda de CVEs lenta | Sin `NVD_API_KEY` el límite es estricto (pausas de 6s). Añade la clave para acelerar. |

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
    ├── exploit_db.py            # Integración opcional con la API local de Exploit-DB
    ├── incibe.py                # Integración con INCIBE-CERT (alerta temprana)
    ├── diagnostics.py           # Estado de API keys y herramientas
    ├── darkweb_monitor.py       # Dark web (Tor) + crawling
    └── report.py                # Informes JSON / CSV / Markdown / HTML
```

---

<div align="center">

**OSINT Recon Suite** · Created by **Cristian & Luisber** · Uso responsable y autorizado únicamente.

</div>
