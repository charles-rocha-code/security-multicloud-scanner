#!/bin/bash
set -e

echo "🔧 Instalando ambiente…"

# Mesma versão do CI (test.yml / security-scan.yml): sem fixar, "python3" no
# macOS com Homebrew pode ser 3.14 e o venv local diverge do que é testado.
# Sobrescreva com PYTHON=python3.x ./install.sh se precisar.
PYTHON="${PYTHON:-python3.12}"
command -v "$PYTHON" >/dev/null || { echo "❌ $PYTHON não encontrado (macOS: brew install python@3.12)"; exit 1; }

"$PYTHON" -m venv venv
source venv/bin/activate

pip install --upgrade pip
# Lock = mesmas versões do deploy e do CI; requirements.txt só define as faixas.
pip install -r requirements.lock.txt

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
