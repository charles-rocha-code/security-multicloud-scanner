#!/bin/bash

echo "🔧 Instalando ambiente…"

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install requests

mkdir -p reports/history
mkdir -p templates

echo "✔ Instalação concluída!"
echo "Para executar:"
echo "source venv/bin/activate && python3 auditor.py"
