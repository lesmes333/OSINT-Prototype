#!/bin/bash
# Script de instalación automática para macOS/Linux
set -e

echo "🔍 Instalando OSINT Prototype..."

# 1) Entorno virtual
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

# 2) Dependencias Python
pip install --upgrade pip
pip install -r requirements.txt

# 3) Archivo .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Archivo .env creado. Añade tus API keys (opcional) con: nano .env"
fi

# 4) Comprobaciones de herramientas externas (todas opcionales)
command -v subfinder >/dev/null 2>&1 || \
    echo "ℹ️  Subfinder no instalado (opcional). Mejora el descubrimiento: brew/apt install subfinder"

command -v searchsploit >/dev/null 2>&1 || \
    echo "ℹ️  searchsploit no instalado (opcional, exploits). brew install exploitdb / apt install exploitdb"

command -v tor >/dev/null 2>&1 || \
    echo "ℹ️  Tor no instalado (opcional, dark web). brew install tor / apt install tor"

command -v docker >/dev/null 2>&1 || \
    echo "ℹ️  Docker no instalado (opcional, fingerprinting). https://www.docker.com/"

# 5) wappalyzer-next (opcional, para fingerprinting)
if command -v docker >/dev/null 2>&1 && [ ! -d scripts/wappalyzer-next ]; then
    echo "ℹ️  Para fingerprinting, clona wappalyzer-next:"
    echo "    git clone https://github.com/s0md3v/wappalyzer-next.git scripts/wappalyzer-next"
    echo "    (cd scripts/wappalyzer-next && docker compose build)"
fi

echo ""
echo "✅ Instalación completada."
echo ""
echo "⚠️  IMPORTANTE: las dependencias se instalaron dentro del venv."
echo "    Antes de ejecutar la herramienta DEBES activar el entorno virtual:"
echo ""
echo "        source venv/bin/activate      # (el prompt cambiará a '(venv)')"
echo ""
echo "    Si ejecutas 'python3 main.py' sin activar el venv verás"
echo "    'ModuleNotFoundError: No module named dotenv'."
echo ""
echo "📌 Uso interactivo:    source venv/bin/activate && python main.py"
echo "📌 Uso automático:     source venv/bin/activate && python main.py -d ejemplo.com -y"
echo "📌 Lote de dominios:   source venv/bin/activate && python main.py -f dominios.txt -y -t 60"
echo "📌 Sin activar (alt.):  venv/bin/python main.py -d ejemplo.com -y"
