# 🛡️ Security Multicloud Storage Scanner

Auditoria avançada de segurança para **AWS S3**, **Google Cloud Storage** e **Azure Blob Storage** com autenticação MFA, dashboard web interativo e geração de relatórios executivos.

---

## 🚀 Features

- ☁️ **Multicloud:** AWS S3, GCS, Azure Blob Storage
- 🔐 **Dual Mode:** Scan público (sem credenciais) + autenticado (com credenciais)
- 🔑 **Autenticação MFA:** Login com OTP via TOTP (Google Authenticator)
- 📊 **Risk Scoring:** 0–100 com níveis CRITICAL / HIGH / MEDIUM / LOW
- ⚖️ **Compliance:** CIS, PCI-DSS, HIPAA, NIST, ISO 27001
- 📄 **Relatórios Executivos:** Geração automática em PDF e DOCX
- 🎨 **Dashboard Web:** Interface moderna com histórico de scans

---

## 📦 Instalação

```bash
# Clone o repositório
git clone https://github.com/charles-rocha-code/security-multicloud-scanner.git
cd security-multicloud-scanner

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar dependências
pip install -r requirements.txt
```

---

## 🔧 Iniciando o Servidor

O servidor principal é o `api_with_mfa.py`, que inclui autenticação MFA.

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Iniciar servidor com MFA
python3 api_with_mfa.py

# Acessar dashboard
# http://localhost:8000/dashboard
```

> ⚠️ O arquivo `api.py` é o servidor base sem MFA. Para uso em produção use sempre `api_with_mfa.py`.

---

## 👤 Gerenciamento de Usuários

### Resetar banco de usuários

```bash
./reset_users.sh
```

Este script para a API, faz backup do banco atual, zera os usuários e reinicia o servidor.

### Primeiro acesso

1. Acesse `http://localhost:8000/dashboard`
2. Clique em **Login**
3. Cadastre seu usuário e configure o MFA via QR Code
4. Use o Google Authenticator ou similar para gerar o OTP

---

## 📊 API Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/health` | Health check |
| `GET` | `/dashboard` | Dashboard web |
| `GET` | `/scan/{bucket}` | Scan público (200 objetos) |
| `POST` | `/scan/authenticated` | Scan autenticado (1000 objetos) |
| `POST` | `/generate-report` | Gera relatório PDF + DOCX |
| `GET` | `/download-report/{filename}` | Download do relatório |
| `GET` | `/reports/list` | Lista relatórios gerados |

---

## 🔐 Scan Autenticado

O campo `provider` é **obrigatório** para identificar o provedor corretamente, especialmente quando o nome do bucket não contém a URL completa.

### AWS S3

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "meu-bucket",
    "provider": "AWS_S3",
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "xxxxx",
    "region": "us-east-1",
    "max_objects": 1000
  }'
```

### Google Cloud Storage

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "meu-bucket-gcs",
    "provider": "GCS",
    "service_account_key": {
      "type": "service_account",
      "project_id": "meu-projeto",
      "private_key_id": "...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...",
      "client_email": "sa@projeto.iam.gserviceaccount.com",
      ...
    },
    "max_objects": 1000
  }'
```

> 💡 O JSON da `service_account_key` é gerado no **GCP Console → IAM & Admin → Service Accounts → Criar chave → JSON**.

### Azure Blob Storage

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "myaccount.blob.core.windows.net",
    "provider": "AZURE_BLOB",
    "azure_connection_string": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net",
    "max_objects": 1000
  }'
```

---

## 🌐 Scan Público (sem credenciais)

Detecta o provider automaticamente pela URL.

```bash
# AWS S3
curl http://localhost:8000/scan/meu-bucket

# GCS (URL completa)
curl http://localhost:8000/scan/meu-bucket.storage.googleapis.com

# Azure
curl http://localhost:8000/scan/myaccount.blob.core.windows.net
```

---

## 🎯 Arquitetura

```
FastAPI Server (api_with_mfa.py)
│
├── Autenticação MFA
│   ├── auth_mfa.py          — TOTP + JWT
│   └── templates/login.html — Tela de login
│
├── Scan Público (200 objetos)
│   ├── auditor.py                — AWS S3
│   ├── auditor_gcs.py            — GCS
│   └── auditor_azure.py          — Azure Blob
│
├── Scan Autenticado (1000 objetos)
│   ├── auditor_s3_authenticated.py
│   ├── auditor_gcs_authenticated.py
│   └── auditor_azure_authenticated.py
│
├── Risk Engine
│   └── engine_risk.py     — Scoring + Compliance
│
├── Relatórios
│   └── generate_report.py — PDF + DOCX
│
└── Dashboard
    └── templates/dashboard.html
```

---

## 🗂️ Estrutura de Arquivos

```
security-multicloud-scanner/
├── api.py                          # Servidor base (sem MFA)
├── api_with_mfa.py                 # Servidor principal (com MFA) ← usar este
├── auth_mfa.py                     # Módulo de autenticação MFA
├── auditor.py                      # Auditor AWS S3 público
├── auditor_gcs.py                  # Auditor GCS público
├── auditor_azure.py                # Auditor Azure público
├── auditor_s3_authenticated.py     # Auditor AWS S3 autenticado
├── auditor_gcs_authenticated.py    # Auditor GCS autenticado
├── auditor_azure_authenticated.py  # Auditor Azure autenticado
├── auditor_universal.py            # Auditor universal (CDN/outros)
├── engine_risk.py                  # Motor de risco e compliance
├── generate_report.py              # Gerador de relatórios PDF/DOCX
├── requirements.txt                # Dependências Python
├── reset_users.sh                  # Script para resetar usuários
├── install.sh                      # Script de instalação
└── templates/
    ├── dashboard.html              # Dashboard principal
    ├── login.html                  # Tela de login MFA
    └── mfa_setup.html              # Configuração do MFA
```

---

## ⚙️ Variáveis e Configuração

O sistema usa arquivos JSON locais para persistência:

| Arquivo | Descrição |
|---------|-----------|
| `users_db.json` | Banco de usuários (não subir no git) |
| `sessions_db.json` | Sessões ativas (não subir no git) |
| `reports_executive/` | Relatórios gerados (não subir no git) |

---

## 🔒 Segurança

- Credenciais **nunca são armazenadas** — usadas apenas durante o scan
- Tokens JWT com expiração configurável
- MFA obrigatório para scans autenticados
- `.gitignore` configurado para excluir dados sensíveis

---

## 📝 License

MIT License

---

## 👤 Autor

Desenvolvido por **Charles Rocha** para auditoria de segurança em ambientes multicloud.
