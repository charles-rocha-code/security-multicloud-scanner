# 🚀 GUIA RÁPIDO - S3 Security Auditor v3.0

## ⚡ Início Rápido (5 minutos)

### 1️⃣ Preparação

```bash
# Instalar dependência
pip install requests --break-system-packages

# Criar estrutura
mkdir -p templates reports/history

# Copiar dashboard
cp dashboard_improved.html templates/dashboard.html
```

### 2️⃣ Executar

```bash
python s3_auditor_improved.py
```

**Entrada:**
```
🪣 Digite buckets: meu-bucket-publico
🔢 Limite de arquivos: [Enter para sem limite]
```

### 3️⃣ Visualizar

```bash
# Abrir HTML no navegador
open reports/meu-bucket-publico_*.html

# Ou no Windows:
start reports\meu-bucket-publico_*.html
```

---

## 📊 O Que Esperar

### Console Output:
```
🔐 AUDITORIA DE SEGURANÇA S3 v3.0
==================================
✅ Região: us-east-1
🚨 3 arquivos críticos encontrados!
📊 1,500 arquivos processados
⏱️ Duração: 45.2s
```

### Dashboard HTML:
- 📊 **6 cards de métricas** (total, críticas, altas, médias, baixas, score)
- 📈 **3 gráficos interativos** (severidade, categoria, histórico)
- 📋 **Tabela completa** com ordenação e filtros
- 🎯 **Recomendações personalizadas** baseadas nos achados
- 💾 **Exportação** JSON e CSV

---

## 🚨 Principais Descobertas

### Críticas (Ação Imediata)
- 🔴 `.env` → Variáveis de ambiente expostas
- 🔴 `id_rsa` → Chave SSH privada
- 🔴 `.git/` → Repositório exposto
- 🔴 `credentials.json` → Credenciais AWS/GCP

### Altas (Priorize Revisão)
- ⚠️ `config.yaml` → Configurações sensíveis
- ⚠️ `backup.sql` → Dump de banco de dados
- ⚠️ `app.py` → Código-fonte exposto
- ⚠️ `bundle.js.map` → Source map exposto

---

## 🛡️ Top 5 Ações Imediatas

### 1. Remover Arquivos Críticos
```bash
# Liste os críticos
grep "CRÍTICO" reports/*.json

# Remova do bucket (AWS CLI)
aws s3 rm s3://meu-bucket/.env
aws s3 rm s3://meu-bucket/id_rsa
```

### 2. Rotacionar Credenciais
```bash
# AWS
aws iam create-access-key --user-name seu-usuario
aws iam delete-access-key --access-key-id AKIA...

# Atualize suas aplicações!
```

### 3. Bloquear Acesso Público
```bash
aws s3api put-public-access-block \
  --bucket meu-bucket \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 4. Habilitar Logging
```bash
aws s3api put-bucket-logging \
  --bucket meu-bucket \
  --bucket-logging-status file://logging.json
```

### 5. Habilitar Versionamento
```bash
aws s3api put-bucket-versioning \
  --bucket meu-bucket \
  --versioning-configuration Status=Enabled
```

---

## 📋 Checklist Pós-Auditoria

### ⚡ Urgente (24h)
- [ ] Remover arquivos críticos
- [ ] Rotacionar credenciais expostas
- [ ] Auditar CloudTrail logs
- [ ] Ativar Block Public Access

### 📅 Esta Semana
- [ ] Habilitar logging (S3 + CloudTrail)
- [ ] Configurar criptografia SSE-KMS
- [ ] Implementar políticas IAM mínimas
- [ ] Habilitar versionamento

### 🔄 Contínuo
- [ ] Auditoria mensal
- [ ] Monitoramento CloudWatch
- [ ] Treinamento de equipe
- [ ] Revisão de acessos

---

## 🆘 Troubleshooting

### ❌ Erro: "Nome de bucket inválido"
```
Bucket deve:
- Ter 3-63 caracteres
- Usar apenas minúsculas, números, hífen, ponto
- Não começar/terminar com hífen
- Não conter .. ou .- ou -.
```

### ❌ Erro: "Timeout ao acessar"
```
Causas:
- Bucket não existe
- Região incorreta
- Problemas de rede
- Rate limiting AWS

Solução:
- Verifique o nome do bucket
- Tente com --region
- Aguarde alguns minutos
```

### ❌ Erro: "Não foi possível verificar acesso público"
```
Causa: Bucket é privado ou não existe

OK! Isso significa que:
✅ Bucket está protegido, OU
❌ Nome está incorreto
```

### ❌ Dashboard não carrega
```
Verifique:
1. Arquivo JSON existe no mesmo diretório?
2. Nome do JSON está correto no HTML?
3. Abriu via http:// (não file://)?

Solução:
# Servir via HTTP simples
python -m http.server 8000
# Abra: http://localhost:8000/reports/bucket.html
```

---

## 💡 Dicas Profissionais

### 🎯 Para Múltiplos Buckets
```python
buckets = ["bucket1", "bucket2", "bucket3"]
# Digite separado por vírgula
```

### 📊 Para Buckets Grandes
```python
# Limite a 10,000 arquivos para teste rápido
max_files = 10000
```

### 🔍 Foco em Críticos
```python
# No dashboard, clique no card vermelho "Críticas"
# Verá apenas arquivos críticos com recomendações
```

### 💾 Exportar para Análise
```python
# Dashboard → Botão "CSV"
# Abre no Excel/Google Sheets
# Filtre por CVSS > 7.0
```

### 📈 Acompanhar Evolução
```python
# Execute semanalmente
# Veja gráfico de histórico
# Score deve diminuir ao longo do tempo!
```

---

## 🎓 Entendendo os Scores

### CVSS (0-10)
```
10.0 = .env com AWS_SECRET_KEY
9.5  = id_rsa (chave SSH)
9.0  = .git/ exposto
8.0  = config.yaml com DB_PASSWORD
7.0  = código-fonte sensível
5.0  = documentos (pode ter PII)
2.0  = imagens/CSS/JS
```

### Risk Score Geral
```
Média ponderada de todos os arquivos

9-10 = 🔴 CRÍTICO - Ação imediata
7-8  = 🟠 ALTO - Priorize
5-6  = 🟡 MÉDIO - Revise
0-4  = 🟢 BAIXO - Monitore
```

---

## 📞 Suporte

### Problemas Técnicos
1. Verifique versão Python (3.7+)
2. Reinstale requests: `pip install requests --force-reinstall`
3. Teste com bucket público conhecido
4. Verifique conectividade: `ping s3.amazonaws.com`

### Falsos Positivos
- Ajuste `classify_file()` no código
- Modifique scores CVSS por tipo
- Adicione exceções por nome de arquivo

### Melhorias
- Fork o projeto
- Adicione novos padrões em `SENSITIVE_PATTERNS`
- Customize categorias
- Melhore dashboard HTML

---

## ⚖️ Uso Responsável

### ✅ Permitido
- Auditar seus próprios buckets
- Auditar buckets da empresa (com autorização)
- Fins educacionais em ambiente controlado
- Testes de segurança autorizados

### ❌ Proibido
- Auditar buckets de terceiros sem autorização
- Uso para fins maliciosos
- Compartilhar relatórios com dados sensíveis
- Ignorar leis de privacidade (LGPD/GDPR)

---

## 🎯 Objetivos de Segurança

### Curto Prazo (1 mês)
- Score < 5.0
- Zero arquivos críticos
- Block Public Access ativo
- Logging habilitado

### Médio Prazo (3 meses)
- Score < 3.0
- Criptografia em 100% dos buckets
- IAM policies auditadas
- Macie configurado

### Longo Prazo (6+ meses)
- Score < 2.0
- Conformidade automática (AWS Config)
- Zero violações de políticas
- Cultura de segurança estabelecida

---

## 📚 Recursos Adicionais

### Documentação
- [README_MELHORIAS.md](README_MELHORIAS.md) - Detalhes técnicos
- [COMPARATIVO_VERSOES.md](COMPARATIVO_VERSOES.md) - v2.0 vs v3.0

### AWS Docs
- [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)

### Ferramentas Complementares
- **AWS CLI** - Gerenciamento de buckets
- **AWS CloudTrail** - Auditoria de API calls
- **Amazon Macie** - Descoberta de dados sensíveis
- **AWS Config** - Conformidade contínua
- **git-secrets** - Prevenir commits de secrets

---

## 🏆 Próximos Passos

1. ✅ Execute sua primeira auditoria
2. 📊 Analise o dashboard HTML
3. 🚨 Remedie descobertas críticas
4. 🔄 Configure auditoria recorrente (semanal)
5. 📈 Monitore evolução do score
6. 🎓 Treine sua equipe
7. 🛡️ Implemente controles preventivos
8. ✨ Mantenha score < 3.0

---

**🔐 S3 Security Auditor v3.0 - Protegendo sua infraestrutura AWS**

*Desenvolvido para auditorias profissionais de segurança*

---

## 🎉 Começe Agora!

```bash
# 1. Instale
pip install requests --break-system-packages

# 2. Prepare
mkdir -p templates reports/history
cp dashboard_improved.html templates/dashboard.html

# 3. Execute
python s3_auditor_improved.py

# 4. Visualize
open reports/*.html

# 5. Remedie
# Siga as recomendações personalizadas!
```

**Boa auditoria! 🚀**
