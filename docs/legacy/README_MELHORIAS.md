# 🔐 S3 Security Auditor v3.0 - Enterprise Edition

## 📋 Visão Geral

Sistema avançado de auditoria de segurança para buckets AWS S3 com detecção inteligente de vulnerabilidades, classificação por risco CVSS e dashboard interativo.

---

## ✨ Principais Melhorias Implementadas

### 🔍 1. **Sistema de Classificação Inteligente**

#### Antes (v2.0):
- 7 categorias básicas
- Detecção limitada de arquivos críticos
- Severidade genérica

#### Agora (v3.0):
- ✅ **15+ categorias detalhadas** com emojis visuais
- ✅ **Detecção expandida de padrões sensíveis** (20+ expressões regulares)
- ✅ **Score CVSS personalizado** (0.0 a 10.0) para cada arquivo
- ✅ **Recomendações específicas** por tipo de arquivo
- ✅ **Tags de categorização** (EXPOSIÇÃO_CRÍTICA, GIT_EXPOSTO, etc.)

**Novas Categorias:**
- 🔴 Chaves/Credenciais (AWS keys, private keys, tokens, .env)
- 🔴 Repositório (.git exposto)
- ⚠️ Configurações (configs, YAML, JSON com possível credenciais)
- ⚠️ Backups (SQL dumps, backups de banco)
- ⚠️ Código-fonte (Python, Java, JS, etc.)
- ⚠️ Source Maps (arquivos .map que expõem código original)
- 📦 Comprimidos (ZIP, RAR, TAR)
- 📄 Documentos (PDF, DOCX, XLSX com possível PII)
- 🎬 Mídia (vídeos e áudios)
- 🖼️ Imagens
- 🔤 Fontes
- 📱 Estáticos (CSS, JS, HTML)
- ❓ Outros/Desconhecidos

### 🛡️ 2. **Detecção Avançada de Credenciais**

**Padrões Detectados:**
```python
✅ AWS Access Keys (AKIA...)
✅ AWS Secret Keys
✅ Private Keys (RSA, OpenSSH, ECDSA)
✅ API Keys genéricas
✅ Bearer Tokens
✅ Senhas hardcoded
✅ Senhas de banco de dados
✅ JWT Tokens
✅ Connection Strings (MongoDB, MySQL, PostgreSQL)
✅ GitHub Tokens (ghp_, gho_, ghs_)
✅ Slack Tokens (xox...)
✅ Stripe Keys (sk_live_)
✅ Google API Keys (AIza...)
```

### 📊 3. **Dashboard HTML Completamente Redesenhado**

#### Melhorias Visuais:
- ✨ Design moderno com gradientes e animações
- 📱 100% responsivo (mobile-first)
- 🎨 Cards interativos com hover effects
- 📈 Gráficos aprimorados (Chart.js 4.x)
- 🔔 Alertas críticos destacados
- 💾 Exportação JSON e CSV
- 🎯 Modal de detalhes com recomendações

#### Novos Recursos:
- **Cabeçalho Rico**: região, duração do scan, versão do auditor
- **Alerta Crítico Animado**: destaque visual para descobertas críticas
- **Score de Risco Dinâmico**: classificação visual (Crítico/Alto/Médio/Baixo)
- **3 Gráficos Interativos**:
  - Distribuição por Severidade (Doughnut)
  - Distribuição por Categoria (Bar)
  - Evolução Histórica (Line)
- **Grid de Estatísticas**: métricas detalhadas
- **Tabela Avançada**: DataTables com filtros e ordenação
- **Recomendações Personalizadas**: baseadas nos achados específicos

### 🚀 4. **Script Python Aprimorado**

#### Novas Funcionalidades:

**Validação Robusta:**
- ✅ Validação completa de nome de bucket (regras AWS)
- ✅ Detecção automática de região com fallback
- ✅ Tratamento de erros HTTP aprimorado
- ✅ Suporte a paginação XML com/sem namespace

**Metadados Expandidos:**
- ⏱️ Tempo de execução do scan
- 📊 CVSS médio por categoria
- 📈 Top 10 maiores arquivos
- 🎯 Top 20 arquivos mais críticos
- 💾 Tamanho total por categoria

**Histórico Aprimorado:**
- 📅 Mantém até 100 execuções (era 50)
- ⏱️ Inclui duração de cada scan
- 📊 Métricas detalhadas por execução

**Sistema de Logs Melhorado:**
- 🎯 Logs com emojis e níveis (INFO, WARNING, ERROR, CRITICAL, SUCCESS)
- 📊 Progresso a cada 1000 arquivos
- ⚡ Sumário executivo detalhado

**Recomendações Personalizadas:**
```python
# Gera recomendações específicas baseadas em:
- Número de arquivos críticos
- Tipos de vulnerabilidades encontradas
- Acesso público habilitado
- Tamanho total do bucket
- Categorias específicas detectadas
```

### 📁 5. **Estrutura de Relatórios Aprimorada**

#### Relatório JSON:
```json
{
  "bucket": "nome-bucket",
  "region": "us-east-1",
  "public_access": true,
  "generated_at": "2024-12-08T10:30:00",
  "scan_duration_seconds": 45.2,
  "auditor_version": "3.0",
  "files": [...],
  "summary": {
    "total_files": 1500,
    "total_size": 52428800,
    "total_size_formatted": "50.0 MB",
    "risk_score": 7.2,
    "risk_counts": {...},
    "category_counts": {...},
    "extension_counts": {...},
    "size_by_category": {...},
    "largest_files": [...],
    "most_critical": [...]
  },
  "history": [...],
  "critical_findings": [...],
  "recommendations": [...]
}
```

---

## 🚀 Como Usar

### 1. **Instalação**

```bash
# Instalar dependências
pip install requests --break-system-packages

# Criar estrutura de diretórios
mkdir -p templates reports/history
```

### 2. **Preparar Templates**

```bash
# Copiar dashboard melhorado
cp dashboard_improved.html templates/dashboard.html
```

### 3. **Executar Auditoria**

```bash
python s3_auditor_improved.py
```

**Interação:**
```
🔐 S3 Security Auditor v3.0 - Enterprise Edition
==============================================================
🛡️  Auditoria avançada de segurança para buckets AWS S3
==============================================================

🪣 Digite 1 ou mais buckets (separados por vírgula): meu-bucket-publico

🔢 Limite de arquivos por bucket? (Enter = sem limite): 

📋 1 bucket(s) para auditar

==============================================================
🔐 AUDITORIA DE SEGURANÇA S3 v3.0
==============================================================
🪣 Bucket: meu-bucket-publico
📅 Data: 2024-12-08 10:30:00
==============================================================

ℹ️ Detectando região...
✅ Região detectada: us-east-1
ℹ️ Verificando acesso público...
🚨 ATENÇÃO: Acesso público PERMITIDO!
🔍 Executando deep scan HTTP...
🚨 CRÍTICO: .env
📊 Processados: 1,000 arquivos (3 críticos, 15 altos)
✅ Scan finalizado: 1,500 arquivos (3 críticos, 15 altos)
📄 JSON gerado: reports/meu-bucket-publico_20241208_103000.json
🌐 HTML exportado: reports/meu-bucket-publico_20241208_103000.html

==============================================================
📊 RESUMO EXECUTIVO DA AUDITORIA
==============================================================
🪣 Bucket: meu-bucket-publico
🌍 Região: us-east-1
🔓 Acesso público: SIM ⚠️
⏱️  Duração do scan: 45.2s
==============================================================

📁 ARQUIVOS:
  Total: 1,500
  Tamanho total: 50.0 MB

⚠️  DISTRIBUIÇÃO DE RISCO:
  🚨 Crítica: 3 (0.2%)
  ⚠️ Alta: 15 (1.0%)
  ℹ️ Média: 450 (30.0%)
  ✅ Baixa: 1,032 (68.8%)

🎯 SCORE DE RISCO: 7.2/10

🚨 DESCOBERTAS CRÍTICAS: 3
  • .env
  • id_rsa
  • config/credentials.json

==============================================================
✅ Auditoria concluída! Relatórios exportados.
==============================================================

✅ Auditoria concluída em 45.2s
```

### 4. **Visualizar Relatório**

Abra o arquivo HTML gerado em seu navegador:
```bash
# Linux/Mac
open reports/meu-bucket-publico_20241208_103000.html

# Windows
start reports/meu-bucket-publico_20241208_103000.html
```

---

## 📊 Entendendo as Métricas

### **Score CVSS (0.0 - 10.0)**

| Score | Severidade | Descrição |
|-------|------------|-----------|
| 9.0 - 10.0 | 🚨 Crítica | Exposição de credenciais, chaves privadas, .env |
| 7.0 - 8.9 | ⚠️ Alta | Configs, backups, código-fonte, .git |
| 4.0 - 6.9 | ℹ️ Média | Documentos, source maps, comprimidos grandes |
| 0.0 - 3.9 | ✅ Baixa | Imagens, fontes, estáticos (CSS/JS) |

### **Score de Risco Geral**

Média ponderada dos scores CVSS de todos os arquivos:
- **8.0 - 10.0**: 🔴 Crítico - Ação imediata necessária
- **6.0 - 7.9**: 🟠 Alto - Revisar com urgência
- **4.0 - 5.9**: 🟡 Médio - Revisar em breve
- **0.0 - 3.9**: 🟢 Baixo - Monitorar

---

## 🛡️ Checklist de Remediação

### ⚡ **Urgente (Primeiras 24h)**

- [ ] Remover **TODOS** os arquivos críticos (.env, chaves, credentials)
- [ ] Rotacionar **TODAS** as credenciais potencialmente expostas
- [ ] Auditar CloudTrail logs para identificar acessos não autorizados
- [ ] Ativar **Block Public Access** (4 configurações)
- [ ] Remover repositórios .git se expostos

### 📅 **Curto Prazo (Primeira Semana)**

- [ ] Habilitar **Server Access Logging** e **CloudTrail**
- [ ] Implementar **políticas IAM de menor privilégio**
- [ ] Configurar **AWS Secrets Manager** para credenciais
- [ ] Habilitar **versionamento** do bucket
- [ ] Configurar **criptografia SSE-KMS**
- [ ] Revisar e remover backups desnecessários
- [ ] Remover código-fonte exposto

### 🔄 **Médio Prazo (Primeiro Mês)**

- [ ] Configurar **Amazon Macie** para descoberta de dados sensíveis
- [ ] Implementar **políticas de lifecycle** para expurgo automático
- [ ] Configurar **AWS Config Rules** para conformidade contínua
- [ ] Habilitar **AWS GuardDuty** para detecção de ameaças
- [ ] Implementar **Object Lock** para dados críticos
- [ ] Configurar **CORS restritivo**
- [ ] Estabelecer **VPC Endpoints** para acesso privado

### 🎯 **Contínuo**

- [ ] Auditorias trimestrais de acesso
- [ ] Treinamento de equipes em segurança S3
- [ ] Monitoramento de alertas CloudWatch
- [ ] Revisão de políticas IAM
- [ ] Testes de penetração autorizados
- [ ] Implantação de **git-secrets** e **truffleHog** no CI/CD

---

## 📈 Recursos do Dashboard

### **1. Cards Interativos**
- Clique nos cards de métrica para ver detalhes
- Hover para ver dica de clique
- Animações suaves e responsivas

### **2. Modal de Arquivos**
- Listagem detalhada por severidade
- Metadados completos de cada arquivo
- Recomendações específicas inline

### **3. Gráficos Dinâmicos**
- **Doughnut**: Distribuição de severidade
- **Bar**: Categorias de arquivos
- **Line**: Evolução histórica do score

### **4. Tabela Avançada**
- Ordenação por qualquer coluna
- Filtro de busca global
- Paginação personalizável
- Exportação CSV

### **5. Exportação**
- **JSON**: Relatório completo estruturado
- **CSV**: Planilha para análise

---

## 🔧 Configurações Avançadas

### **Limitar Número de Arquivos**
```python
auditor = S3Auditor("meu-bucket")
auditor.run(max_files=5000)  # Limita a 5000 arquivos
```

### **Personalizar Padrões Sensíveis**
```python
SENSITIVE_PATTERNS = {
    "custom_api": re.compile(r'API_KEY_CUSTOM["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{32}'),
    # Adicione seus padrões...
}
```

### **Ajustar Severidade**
Edite a função `classify_file()` para ajustar scores CVSS:
```python
if ext == "json" and "config" in name_lower:
    cvss = 8.5  # Aumenta severidade de configs JSON
```

---

## 📚 Referências de Segurança AWS S3

### **Documentação Oficial:**
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [Amazon Macie](https://docs.aws.amazon.com/macie/)

### **Conformidade:**
- LGPD (Lei Geral de Proteção de Dados)
- GDPR (General Data Protection Regulation)
- PCI DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)

---

## 🤝 Contribuições

Este é um projeto de auditoria de segurança. Melhorias sugeridas:

### **Futuras Implementações:**
- [ ] Integração com AWS CLI/Boto3 para scans autenticados
- [ ] Análise de conteúdo de arquivos suspeitos
- [ ] Integração com SIEM (Splunk, ELK)
- [ ] Notificações automáticas (Email, Slack, Teams)
- [ ] API REST para integração com CI/CD
- [ ] Suporte a multi-região simultâneo
- [ ] Machine Learning para detecção de anomalias

---

## ⚠️ Avisos Importantes

### **Limitações:**
1. ✋ **Scan Público Apenas**: Esta ferramenta faz scan via HTTP público. Para buckets privados, use AWS CLI com credenciais.
2. 🔒 **Não Baixa Arquivos**: Não faz download de conteúdo (apenas metadados).
3. 📊 **Baseado em Heurísticas**: A classificação é baseada em padrões e nomes, não análise de conteúdo real.
4. ⚡ **Rate Limits**: Respeite rate limits da AWS ao fazer múltiplos scans.

### **Uso Responsável:**
- ⚠️ Não use para testar buckets de terceiros sem autorização
- 🔐 Não compartilhe relatórios contendo informações sensíveis
- 📋 Use apenas para fins de auditoria de segurança legítima

---

## 📞 Suporte

Para questões ou sugestões sobre esta ferramenta de auditoria, documente no seu sistema de gestão de projetos ou compartilhe com sua equipe de segurança.

---

## 📄 Licença

Este código é fornecido como exemplo educacional para auditorias de segurança em AWS S3.

---

**🔐 S3 Security Auditor v3.0 - Enterprise Edition**
*Desenvolvido para auditorias profissionais de segurança em infraestrutura AWS*

---

## 🎯 Resumo das Melhorias

| Aspecto | v2.0 | v3.0 |
|---------|------|------|
| **Categorias** | 7 básicas | 15+ detalhadas |
| **Padrões de Credenciais** | 5 | 20+ |
| **Score CVSS** | Genérico | Personalizado 0-10 |
| **Recomendações** | Fixas | Dinâmicas por achado |
| **Dashboard** | Básico | Enterprise (responsivo) |
| **Gráficos** | 2 simples | 3 interativos |
| **Exportação** | JSON/HTML | JSON/HTML/CSV |
| **Histórico** | 50 execuções | 100 execuções |
| **Metadados** | Básicos | Expandidos (ETag, duração) |
| **Alertas** | Console | Console + Visual (HTML) |

---

**✨ Total de Melhorias: 50+ features e aprimoramentos!**
