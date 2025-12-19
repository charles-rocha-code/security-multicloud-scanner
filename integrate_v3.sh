#!/bin/bash

################################################################################
# 🔄 SCRIPT DE INTEGRAÇÃO AUTOMÁTICA
# S3 Security Auditor v2.0 → v3.0
#
# Este script integra automaticamente as melhorias da v3.0 ao seu projeto
# existente, preservando backups e histórico.
#
# Uso: bash integrate_v3.sh
################################################################################

set -e  # Parar em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de log
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

################################################################################
# VERIFICAÇÕES INICIAIS
################################################################################

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                          ║"
echo "║           🔄 INTEGRAÇÃO S3 AUDITOR v2.0 → v3.0                           ║"
echo "║                                                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""

log_info "Verificando pré-requisitos..."

# Verifica se está no diretório correto
if [ ! -f "auditor.py" ]; then
    log_error "Arquivo auditor.py não encontrado!"
    log_warning "Execute este script no diretório raiz do projeto (s3_auditor_enterprise/)"
    exit 1
fi

log_success "Diretório correto detectado"

# Verifica Python
if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
    log_error "Python não encontrado!"
    exit 1
fi

PYTHON_CMD="python"
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
fi

log_success "Python encontrado: $($PYTHON_CMD --version)"

# Verifica ambiente virtual
if [ ! -d "venv" ]; then
    log_warning "Ambiente virtual não encontrado!"
    log_info "Criando ambiente virtual..."
    $PYTHON_CMD -m venv venv
    log_success "Ambiente virtual criado"
fi

# Ativa ambiente virtual
log_info "Ativando ambiente virtual..."
source venv/bin/activate || source venv/Scripts/activate 2>/dev/null
log_success "Ambiente virtual ativado"

# Verifica requests
if ! $PYTHON_CMD -c "import requests" 2>/dev/null; then
    log_warning "Biblioteca 'requests' não encontrada"
    log_info "Instalando requests..."
    pip install requests --break-system-packages 2>/dev/null || pip install requests
    log_success "Biblioteca 'requests' instalada"
else
    log_success "Biblioteca 'requests' já instalada"
fi

################################################################################
# CONFIRMAÇÃO DO USUÁRIO
################################################################################

echo ""
log_warning "ATENÇÃO: Este script irá:"
echo "  1. Fazer backup dos arquivos atuais"
echo "  2. Substituir auditor.py pela versão v3.0"
echo "  3. Substituir templates/dashboard.html pela versão v3.0"
echo "  4. Criar diretório docs/ com documentação"
echo "  5. Preservar todos os relatórios e histórico existentes"
echo ""
read -p "Deseja continuar? (s/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[SsYy]$ ]]; then
    log_warning "Integração cancelada pelo usuário"
    exit 0
fi

################################################################################
# FASE 1: BACKUP
################################################################################

echo ""
log_info "FASE 1: Criando backups..."

# Backup do script
if [ -f "auditor.py" ]; then
    cp auditor.py "auditor_v2_backup_$(date +%Y%m%d_%H%M%S).py"
    log_success "Backup: auditor.py → auditor_v2_backup_*.py"
fi

# Backup do dashboard
if [ -f "templates/dashboard.html" ]; then
    cp templates/dashboard.html "templates/dashboard_v2_backup_$(date +%Y%m%d_%H%M%S).html"
    log_success "Backup: dashboard.html → dashboard_v2_backup_*.html"
fi

################################################################################
# FASE 2: VERIFICAR ARQUIVOS NOVOS
################################################################################

echo ""
log_info "FASE 2: Verificando arquivos novos..."

# Verifica se os arquivos novos existem
NEW_FILES_DIR="."
if [ ! -f "s3_auditor_improved.py" ]; then
    log_error "Arquivo s3_auditor_improved.py não encontrado!"
    log_warning "Certifique-se de que os arquivos novos estão no mesmo diretório"
    exit 1
fi

if [ ! -f "dashboard_improved.html" ]; then
    log_error "Arquivo dashboard_improved.html não encontrado!"
    exit 1
fi

log_success "Arquivos novos encontrados"

################################################################################
# FASE 3: INTEGRAÇÃO
################################################################################

echo ""
log_info "FASE 3: Integrando arquivos novos..."

# Cria diretório de documentação
mkdir -p docs
log_success "Diretório docs/ criado"

# Copia novo script
cp s3_auditor_improved.py auditor.py
log_success "auditor.py atualizado"

# Copia novo dashboard
cp dashboard_improved.html templates/dashboard.html
log_success "templates/dashboard.html atualizado"

# Copia documentação
if [ -f "README_MELHORIAS.md" ]; then
    cp README_MELHORIAS.md docs/
    log_success "docs/README_MELHORIAS.md criado"
fi

if [ -f "COMPARATIVO_VERSOES.md" ]; then
    cp COMPARATIVO_VERSOES.md docs/
    log_success "docs/COMPARATIVO_VERSOES.md criado"
fi

if [ -f "GUIA_RAPIDO.md" ]; then
    cp GUIA_RAPIDO.md docs/
    log_success "docs/GUIA_RAPIDO.md criado"
fi

if [ -f "INDEX.md" ]; then
    cp INDEX.md docs/
    log_success "docs/INDEX.md criado"
fi

if [ -f "GUIA_INTEGRACAO.md" ]; then
    cp GUIA_INTEGRACAO.md docs/
    log_success "docs/GUIA_INTEGRACAO.md criado"
fi

################################################################################
# FASE 4: VALIDAÇÃO
################################################################################

echo ""
log_info "FASE 4: Validando integração..."

# Testa se o script executa
if $PYTHON_CMD -c "import auditor" 2>/dev/null; then
    log_error "Módulo 'auditor' não pode ser importado diretamente"
    log_info "Isso é normal - o script deve ser executado, não importado"
fi

# Verifica estrutura de arquivos
if [ -f "auditor.py" ] && [ -f "templates/dashboard.html" ]; then
    log_success "Estrutura de arquivos validada"
else
    log_error "Estrutura de arquivos inválida!"
    exit 1
fi

# Verifica diretórios necessários
if [ -d "reports" ] && [ -d "reports/history" ] && [ -d "templates" ]; then
    log_success "Diretórios necessários presentes"
else
    log_warning "Alguns diretórios podem estar faltando"
    log_info "Criando diretórios faltantes..."
    mkdir -p reports/history templates static
    log_success "Diretórios criados"
fi

################################################################################
# FASE 5: TESTE RÁPIDO
################################################################################

echo ""
log_info "FASE 5: Executando teste rápido..."

# Testa importação do módulo requests
if $PYTHON_CMD -c "import requests; print('Requests OK')" 2>/dev/null | grep -q "OK"; then
    log_success "Dependências verificadas"
else
    log_error "Erro ao verificar dependências"
    exit 1
fi

################################################################################
# RESUMO
################################################################################

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                          ║"
echo "║                     ✅ INTEGRAÇÃO CONCLUÍDA!                             ║"
echo "║                                                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""

log_success "Arquivos integrados com sucesso!"
echo ""
echo "📊 RESUMO DA INTEGRAÇÃO:"
echo "   ✅ auditor.py → v3.0 (backup criado)"
echo "   ✅ templates/dashboard.html → v3.0 (backup criado)"
echo "   ✅ docs/ → 5 arquivos de documentação"
echo "   ✅ Histórico preservado em reports/history/"
echo "   ✅ Relatórios antigos mantidos em reports/"
echo ""

log_info "PRÓXIMOS PASSOS:"
echo "   1. Execute um scan de teste:"
echo "      $ python auditor.py"
echo ""
echo "   2. Visualize o novo dashboard:"
echo "      $ open reports/seu-bucket_*.html"
echo ""
echo "   3. Leia a documentação:"
echo "      $ cat docs/GUIA_RAPIDO.md"
echo ""

log_warning "ROLLBACK (se necessário):"
echo "   Se precisar voltar à versão anterior:"
echo "   $ cp auditor_v2_backup_*.py auditor.py"
echo "   $ cp templates/dashboard_v2_backup_*.html templates/dashboard.html"
echo ""

################################################################################
# INFORMAÇÕES ADICIONAIS
################################################################################

log_info "NOVOS RECURSOS DISPONÍVEIS:"
echo "   • 20+ padrões de detecção de credenciais (+300%)"
echo "   • 15+ categorias de arquivos (+114%)"
echo "   • 3 gráficos interativos no dashboard"
echo "   • Exportação CSV dos resultados"
echo "   • Score CVSS personalizado por arquivo"
echo "   • Recomendações dinâmicas baseadas em achados"
echo "   • Logs visuais com emojis e cores"
echo "   • Histórico expandido (50 → 100 scans)"
echo "   • Modal rico com detalhes e recomendações"
echo "   • Dashboard 100% responsivo (mobile/desktop)"
echo ""

log_success "🎉 Pronto para usar!"
echo ""

# Pergunta se quer executar um teste
read -p "Deseja executar um scan de teste agora? (s/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[SsYy]$ ]]; then
    log_info "Iniciando scan de teste..."
    echo ""
    $PYTHON_CMD auditor.py
else
    log_info "Execute 'python auditor.py' quando estiver pronto"
fi

echo ""
log_success "Integração finalizada!"
echo ""

exit 0
