#!/bin/bash
set -e

echo "🔧 Instalando ambiente…"

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

mkdir -p local_data
mkdir -p reports_executive
mkdir -p templates

if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo "✔ .env criado a partir de .env.example (STORAGE_BACKEND=local por padrão)"
fi

echo "✔ Instalação concluída!"
echo "Para executar (100% local, sem AWS):"
echo "source venv/bin/activate && uvicorn api_with_mfa:app --reload"
