#!/bin/bash

# Script de auditoria automática de múltiplos buckets S3
# Lê a lista de buckets do arquivo buckets.txt

echo "🔐 S3 Security Auditor - Modo Automático"
echo "============================================================"

# Verifica se o arquivo buckets.txt existe
if [ ! -f "buckets.txt" ]; then
    echo "❌ Erro: arquivo buckets.txt não encontrado!"
    echo "Crie o arquivo com a lista de buckets (um por linha)"
    exit 1
fi

# Lê buckets do arquivo e junta com vírgula
BUCKETS=$(cat buckets.txt | grep -v '^#' | grep -v '^$' | tr '\n' ',' | sed 's/,$//')

if [ -z "$BUCKETS" ]; then
    echo "❌ Erro: nenhum bucket encontrado em buckets.txt"
    exit 1
fi

TOTAL=$(grep -v '^#' buckets.txt | grep -v '^$' | wc -l | tr -d ' ')
echo "📋 Total de buckets: $TOTAL"
echo "📝 Buckets: $BUCKETS"
echo ""

# Ativa virtual environment se existir
if [ -d "venv" ]; then
    echo "🐍 Ativando ambiente virtual..."
    source venv/bin/activate
fi

# Executa o auditor
echo "$BUCKETS" | python3 auditor.py

echo ""
echo "============================================================"
echo "✅ Auditoria concluída!"
echo "📊 Relatórios disponíveis em: reports/"
echo ""
echo "🌐 Para visualizar os dashboards:"
echo "   cd reports && python3 -m http.server 8080"
echo "   Depois acesse: http://localhost:8080/cdn44.html"
echo "============================================================"
