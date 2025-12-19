# 🛡️ Security Multicloud Storage Scanner

Auditoria avançada de segurança para AWS S3, Google Cloud Storage e Azure Blob Storage.

## 🚀 Features

- ☁️ **Multicloud:** AWS S3, GCS, Azure Blob Storage
- 🔐 **Dual Mode:** Scan público + autenticado
- 📊 **Risk Scoring:** 0-100 com níveis (CRITICAL/HIGH/MEDIUM/LOW)
- ⚖️ **Compliance:** CIS, PCI-DSS, HIPAA, NIST, ISO 27001
- 🎨 **Dashboard:** Interface web moderna com suporte Azure

## 📦 Instalação
```bash
# Clone o repositório
git clone https://github.com/seu-usuario/security-multicloud-scanner.git
cd security-multicloud-scanner

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

## 🔧 Uso
```bash
# Ativar ambiente virtual (se não estiver ativo)
source venv/bin/activate

# Iniciar servidor
python api.py

# Acessar dashboard
# Abrir navegador: http://localhost:8000/dashboard
```

## 📊 API Endpoints

- `GET /scan/{bucket}` - Scan público (200 objetos)
- `POST /scan/authenticated` - Scan autenticado (1000 objetos)
- `GET /dashboard` - Dashboard web
- `GET /health` - Health check

## 🔐 Scan Autenticado

### AWS S3
```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "my-bucket.s3.amazonaws.com",
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "xxxxx",
    "max_objects": 1000
  }'
```

### Google Cloud Storage
```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "my-bucket.storage.googleapis.com",
    "service_account_key": {...},
    "max_objects": 1000
  }'
```

### Azure Blob Storage
```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "myaccount.blob.core.windows.net",
    "azure_connection_string": "DefaultEndpointsProtocol=https;...",
    "max_objects": 1000
  }'
```

## 🎯 Arquitetura
```
FastAPI Server
├── Public Scans (200 objetos)
│   ├── auditor.py (AWS S3)
│   ├── auditor_gcs.py (GCS)
│   └── auditor_azure.py (Azure)
│
├── Authenticated Scans (1000 objetos)
│   ├── auditor_s3_authenticated.py
│   ├── auditor_gcs_authenticated.py
│   └── auditor_azure_authenticated.py
│
├── Risk Engine
│   └── engine_risk.py (scoring + compliance)
│
└── Dashboard
    └── templates/dashboard.html
```

## 📝 License

MIT License

## 👤 Autor

Desenvolvido para auditoria de segurança em ambientes multicloud.
