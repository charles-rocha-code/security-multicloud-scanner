# 🔐 Guia de Integração MFA - Security Multicloud Scanner

## 📋 Visão Geral

Este guia mostra como integrar o sistema de autenticação MFA (Multi-Factor Authentication) com o Security Multicloud Storage Scanner existente.

---

## 📦 Arquivos Criados

| Arquivo | Descrição |
|---------|-----------|
| **auth_mfa.py** | Módulo completo de autenticação MFA |
| **login.html** | Página de login/registro com estilo da dashboard |
| **api_integrado.py** | API com MFA integrado (substitui api.py) |
| **requirements_mfa.txt** | Dependências atualizadas com MFA |

---

## 🚀 Instalação (3 Passos)

### **Passo 1: Instalar Dependências MFA**

```bash
pip install pyotp==2.9.0 qrcode[pil]==7.4.2 Pillow==10.1.0 python-dotenv==1.0.0
```

Ou instale tudo de uma vez:

```bash
pip install -r requirements_mfa.txt
```

### **Passo 2: Organizar Arquivos**

```
seu-projeto/
│
├── api_integrado.py         ← Nova API com MFA
├── auth_mfa.py              ← Módulo de autenticação
├── login.html               ← Página de login
│
├── templates/
│   └── dashboard.html       ← Dashboard existente
│
├── auditor.py               ← Seus auditores existentes
├── auditor_gcs.py
├── auditor_azure.py
├── engine_risk.py
│
└── requirements_mfa.txt     ← Dependências atualizadas
```

### **Passo 3: Executar**

```bash
python api_integrado.py
```

**Saída esperada:**
```
======================================================================
🚀 Security Multicloud Storage Scanner + MFA - INICIADO
======================================================================
📡 API: http://localhost:8000
📄 Docs: http://localhost:8000/docs
🔐 Login: http://localhost:8000/login
🛡️  Dashboard: http://localhost:8000/dashboard
======================================================================
🔑 MFA: ✅ ATIVO
📊 Providers: AWS S3, GCS, Azure Blob
======================================================================
```

---

## 🎯 Como Usar

### 1️⃣ **Primeira Vez: Criar Conta**

Acesse: http://localhost:8000/login

1. Clique em **"Criar conta"**
2. Preencha:
   - Nome: João Silva
   - Email: joao@empresa.com
   - Senha: senha123
3. Clique em **"Criar Conta"**

### 2️⃣ **Login Inicial (Sem MFA)**

1. Digite email e senha
2. Clique em **"Entrar"**
3. Você será levado ao **Painel de Segurança**

### 3️⃣ **Configurar MFA (Primeira vez)**

1. No Painel, clique em **"Configurar MFA"**
2. Digite sua senha para confirmar
3. Clique em **"Gerar QR Code"**

4. **Escanear QR Code:**
   - Abra o **Google Authenticator** no celular
   - Toque em **"+"** → **"Escanear QR code"**
   - Aponte para o QR Code na tela

5. **Salvar Backup Codes:**
   - Anote os 10 códigos em local seguro
   - Você pode usá-los se perder o celular

6. **Ativar MFA:**
   - Digite o código de 6 dígitos do app
   - Clique em **"Ativar MFA"**

✅ **MFA está ativado!**

### 4️⃣ **Login com MFA (Após ativação)**

1. Digite email e senha
2. Campo de **"Código MFA"** aparecerá
3. Abra Google Authenticator
4. Digite o código de 6 dígitos
5. Clique em **"Entrar"**

### 5️⃣ **Acessar Dashboard**

Após login com sucesso:

1. Clique em **"Ir para Dashboard"**
2. Você será redirecionado para a dashboard do Security Scanner
3. Agora você pode fazer scans protegidos por MFA! 🎉

---

## 📡 Endpoints da API

### **Autenticação**

| Endpoint | Método | Descrição | Autenticação |
|----------|--------|-----------|--------------|
| `/auth/register` | POST | Registrar usuário | ❌ Não |
| `/auth/login` | POST | Login (com/sem MFA) | ❌ Não |
| `/auth/mfa/setup` | POST | Configurar MFA | ❌ Não* |
| `/auth/mfa/verify` | POST | Ativar MFA | ❌ Não* |
| `/auth/mfa/status` | GET | Status MFA | ❌ Não* |
| `/auth/mfa/disable` | POST | Desativar MFA | ❌ Não* |
| `/auth/mfa/regenerate-backup-codes` | POST | Novos códigos | ❌ Não* |
| `/auth/logout` | POST | Logout | ✅ Sim |

*Requer email e senha, mas não token JWT

### **Scans**

| Endpoint | Método | Descrição | Autenticação | MFA |
|----------|--------|-----------|--------------|-----|
| `/scan/{bucket}` | GET | Scan público | ✅ Token | ❌ Não |
| `/scan/authenticated` | POST | Scan autenticado | ✅ Token | ✅ **Sim** |

### **Relatórios**

| Endpoint | Método | Descrição | Autenticação |
|----------|--------|-----------|--------------|
| `/generate-report` | POST | Gerar relatório | ✅ Sim |
| `/download-report/{filename}` | GET | Download | ✅ Sim |
| `/reports/list` | GET | Listar | ✅ Sim |

### **Páginas**

| URL | Descrição | Autenticação |
|-----|-----------|--------------|
| `/` | Redireciona para /login | ❌ Não |
| `/login` | Página de login | ❌ Não |
| `/dashboard` | Dashboard scanner | ✅ Sim |

---

## 🔐 Segurança Implementada

### ✅ O que está implementado:

1. **TOTP (Time-based One-Time Password)**
   - Códigos de 6 dígitos
   - Expiram a cada 30 segundos
   - Window de tolerância: ±30 segundos

2. **Backup Codes**
   - 10 códigos únicos
   - Uso único (invalidados após uso)

3. **Sessões com Token**
   - Tokens únicos por sessão
   - Armazenados em memória

4. **Validação de Senha**
   - Hash SHA-256 (básico)

5. **Middleware de Autenticação**
   - `get_current_user()` - Requer autenticação
   - `require_mfa()` - Requer MFA ativado

### ⚠️ Para Produção (IMPORTANTE!):

#### **1. Use Banco de Dados Real**

Substitua `USERS_DB = {}` em `auth_mfa.py`:

```python
# PostgreSQL
from sqlalchemy import create_engine, Column, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://user:password@localhost/scanner_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    email = Column(String, primary_key=True)
    password = Column(String)
    mfa_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
```

#### **2. Use Bcrypt para Senhas**

```bash
pip install passlib bcrypt
```

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
```

#### **3. Implemente JWT Real**

```bash
pip install python-jose[cryptography]
```

```python
from jose import JWTError, jwt
from datetime import datetime, timedelta

SECRET_KEY = "sua-chave-secreta-muito-forte-aqui"
ALGORITHM = "HS256"

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
```

#### **4. Configure HTTPS**

```bash
# Gere certificados SSL
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Execute com SSL
uvicorn api_integrado:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem --port 443
```

#### **5. Adicione Rate Limiting**

```bash
pip install slowapi
```

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/auth/login")
@limiter.limit("5/minute")  # 5 tentativas por minuto
async def login(request: Request, ...):
    ...
```

#### **6. Variáveis de Ambiente**

Crie arquivo `.env`:

```bash
# .env
DATABASE_URL=postgresql://user:pass@localhost/scanner_db
SECRET_KEY=sua-chave-super-secreta-aqui
MFA_ISSUER=Security Scanner
ENVIRONMENT=production
```

```python
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
```

---

## 🧪 Testes

### **Teste Manual**

1. **Registro:**
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"senha123","full_name":"Test User"}'
```

2. **Login:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"senha123"}'
```

3. **Setup MFA:**
```bash
curl -X POST http://localhost:8000/auth/mfa/setup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"senha123"}'
```

4. **Scan (com token):**
```bash
curl -X GET http://localhost:8000/scan/my-bucket.s3.amazonaws.com \
  -H "Authorization: Bearer {seu-token-aqui}"
```

### **Teste Automatizado**

Use o script de testes incluído:

```bash
python test_mfa.py
```

---

## 🔄 Migração da API Antiga

Se você já tem a `api.py` em produção:

### **Opção 1: Substituição Gradual (Recomendado)**

1. **Rode ambas as APIs em paralelo:**

```bash
# API antiga (porta 8000)
python api.py

# API nova com MFA (porta 8001)
python api_integrado.py --port 8001
```

2. **Configure proxy reverso (Nginx):**

```nginx
# Novas requisições vão para API com MFA
location /auth/ {
    proxy_pass http://localhost:8001;
}

# Requisições antigas continuam na API antiga
location / {
    proxy_pass http://localhost:8000;
}
```

3. **Migre usuários gradualmente**

### **Opção 2: Substituição Direta**

1. **Backup da API antiga:**
```bash
cp api.py api_backup.py
```

2. **Substitua:**
```bash
mv api_integrado.py api.py
```

3. **Teste:**
```bash
python api.py
```

---

## 📊 Fluxo de Autenticação

```
┌─────────────────────────────────────────────────────────────────┐
│                    FLUXO DE AUTENTICAÇÃO MFA                     │
└─────────────────────────────────────────────────────────────────┘

1. REGISTRO
   ├─ Usuario acessa /login
   ├─ Clica em "Criar conta"
   ├─ POST /auth/register
   └─ Conta criada (MFA desativado)

2. PRIMEIRO LOGIN (SEM MFA)
   ├─ POST /auth/login
   │   └─ {email, password}
   ├─ Recebe token
   └─ Redirecionado para Painel

3. CONFIGURAR MFA
   ├─ POST /auth/mfa/setup
   │   └─ {email, password}
   ├─ Recebe:
   │   ├─ QR Code (base64)
   │   ├─ Secret (TOTP)
   │   └─ 10 Backup Codes
   ├─ Escaneia QR Code no Google Authenticator
   └─ POST /auth/mfa/verify
       └─ {email, code: "123456"}
       └─ MFA ATIVADO ✅

4. LOGIN COM MFA
   ├─ POST /auth/login
   │   └─ {email, password}
   ├─ Resposta: {"mfa_required": true}
   ├─ Frontend mostra campo de código
   ├─ POST /auth/login
   │   └─ {email, password, mfa_code: "123456"}
   └─ Recebe token + acesso ao Dashboard

5. USAR DASHBOARD
   ├─ Todas as requisições incluem:
   │   └─ Header: Authorization: Bearer {token}
   ├─ GET /scan/{bucket}
   │   └─ Requer: autenticação (token válido)
   └─ POST /scan/authenticated
       └─ Requer: autenticação + MFA ativado
```

---

## ❓ FAQ

### **P: Posso usar sem MFA?**
R: Sim! Os scans públicos funcionam apenas com autenticação básica. MFA é obrigatório apenas para scans autenticados (com credenciais cloud).

### **P: E se eu perder o celular?**
R: Use um dos 10 backup codes que você salvou. Cada código funciona apenas uma vez.

### **P: Posso desativar MFA depois?**
R: Sim! No Painel de Segurança → "Desativar MFA" (precisa do código MFA atual).

### **P: Os dados ficam seguros?**
R: No código atual, os dados ficam em memória (perdidos ao reiniciar). Para produção, use um banco de dados real (PostgreSQL, MongoDB).

### **P: Preciso mudar minha dashboard existente?**
R: Não! A dashboard continua igual. Apenas adicione o token nas requisições:
```javascript
fetch('/scan/my-bucket', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('scanner_token')}`
  }
})
```

### **P: Como adiciono mais usuários?**
R: Cada usuário cria sua própria conta via `/login` → "Criar conta".

### **P: Posso ter usuários admin e normais?**
R: Sim! Adicione um campo `role` em `USERS_DB` e crie um middleware `require_admin()`.

---

## 📞 Suporte

### **Problemas Comuns**

1. **"Código MFA inválido"**
   - Sincronize o relógio do celular
   - Códigos TOTP expiram a cada 30 segundos
   - Aguarde o próximo código

2. **"Token inválido ou expirado"**
   - Faça login novamente
   - Verifique se o token está sendo enviado no header

3. **"ModuleNotFoundError: pyotp"**
   ```bash
   pip install pyotp qrcode[pil] Pillow
   ```

4. **QR Code não aparece**
   - Verifique console do navegador (F12)
   - Backend deve estar rodando
   - URL da API deve estar correta

---

## ✅ Checklist de Deploy

- [ ] Banco de dados configurado (PostgreSQL/MongoDB)
- [ ] Bcrypt para senhas implementado
- [ ] JWT com SECRET_KEY forte configurado
- [ ] HTTPS configurado (SSL/TLS)
- [ ] Rate limiting ativado
- [ ] Variáveis de ambiente (.env) configuradas
- [ ] CORS configurado para domínios específicos
- [ ] Backup codes instruídos aos usuários
- [ ] Logs de auditoria implementados
- [ ] Monitoramento configurado (Prometheus/Datadog)
- [ ] Testes automatizados passando

---

## 🎉 Conclusão

Você agora tem um sistema completo de MFA integrado ao Security Multicloud Scanner!

**Próximos passos:**
1. Teste localmente
2. Configure para produção (banco de dados, bcrypt, JWT)
3. Deploy em servidor
4. Monitore e ajuste conforme necessário

**Dúvidas?** Consulte esta documentação ou os comentários no código.

---

**Desenvolvido com ❤️  para Security Multicloud Scanner**
