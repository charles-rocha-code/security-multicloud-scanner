"""
auth_mfa.py - Autenticação MFA com persistência em DynamoDB (STORAGE_BACKEND=aws)
ou em arquivos JSON locais (STORAGE_BACKEND=local, padrão para dev sem AWS).

Sessões: DynamoDB (security-scanner-sessions) — sem race condition entre instâncias.
Usuários: DynamoDB (security-scanner-users) com cache em memória — consistência forte.
Migration: na primeira inicialização, se DynamoDB vazio, migra de users_db.json no S3.
Em STORAGE_BACKEND=local, envio de email de reset é substituído por log do link
(sem depender de SES) e sessões/usuários/resets vivem em local_data/*.json.
"""

from fastapi import HTTPException, Depends, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import secrets
import hashlib
import bcrypt
import json
import os
import time
import boto3
from botocore.exceptions import ClientError

from logging_setup import get_logger
from local_store import DATA_DIR, read_json, update_json

logger = get_logger("auth_mfa")

# ==================== CONFIGURAÇÃO ====================

# "local" (padrão) roda sem nenhuma credencial AWS -- sessões/usuários/resets
# em local_data/*.json, email de reset vira log. "aws" usa DynamoDB/S3/SES,
# igual à produção. Ver docs/env vars em .env.example.
STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "local")

S3_BUCKET = os.environ.get("DB_S3_BUCKET", "security-scanner-db-442042548551")
DYNAMO_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")
SESSIONS_TABLE = os.environ.get("SESSIONS_DYNAMO_TABLE", "security-scanner-sessions")
USERS_TABLE = os.environ.get("USERS_DYNAMO_TABLE", "security-scanner-users")
PASSWORD_RESETS_TABLE = os.environ.get("PASSWORD_RESETS_DYNAMO_TABLE", "security-scanner-password-resets")

# Identidade SES já verificada (mesma do Watchdog Lambda) — conta ainda em
# sandbox, então só entrega para destinatários individualmente verificados
SES_REGION = "us-east-1"
SES_SENDER = os.environ.get("SES_SENDER_EMAIL", "no-reply@oisolucoes.app.br")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://scanner.oisolucoes.app.br")

SESSION_TTL_SECONDS = 86400  # 24 h
PASSWORD_RESET_TTL_SECONDS = 1800  # 30 min

SESSIONS_FILE = DATA_DIR / "sessions.json"
USERS_FILE = DATA_DIR / "users.json"
PASSWORD_RESETS_FILE = DATA_DIR / "password_resets.json"


def _backend() -> str:
    # Lida com o valor a cada chamada (não em constante de módulo) para que
    # testes com monkeypatch.setenv("STORAGE_BACKEND", ...) surtam efeito
    # mesmo depois deste módulo já ter sido importado.
    return os.environ.get("STORAGE_BACKEND", STORAGE_BACKEND)


def _tbl_sessions():
    return boto3.resource("dynamodb", region_name=DYNAMO_REGION).Table(SESSIONS_TABLE)


def _tbl_users():
    return boto3.resource("dynamodb", region_name=DYNAMO_REGION).Table(USERS_TABLE)


def _tbl_password_resets():
    return boto3.resource("dynamodb", region_name=DYNAMO_REGION).Table(PASSWORD_RESETS_TABLE)

# ==================== SESSÕES ====================

def _session_put(token: str, email: str) -> None:
    item = {
        "token": token,
        "email": email,
        "created_at": datetime.now().isoformat(),
        "authenticated": True,
        "mfa_verified": True,
        "expires_at_unix": int(time.time()) + SESSION_TTL_SECONDS,
    }
    if _backend() != "aws":
        def _mutate(sessions):
            sessions[token] = item
            return sessions, None
        update_json(SESSIONS_FILE, _mutate)
        return
    _tbl_sessions().put_item(Item=item)


def _session_get(token: str) -> Optional[Dict[str, Any]]:
    if _backend() != "aws":
        def _mutate(sessions):
            found = sessions.get(token)
            if not found:
                return sessions, None
            if int(found.get("expires_at_unix", 0)) < int(time.time()):
                del sessions[token]
                return sessions, None
            return sessions, found
        return update_json(SESSIONS_FILE, _mutate)
    try:
        resp = _tbl_sessions().get_item(Key={"token": token})
        item = resp.get("Item")
        if not item:
            return None
        # Verificação manual de expiração (TTL do DynamoDB não é instantâneo)
        if int(item.get("expires_at_unix", 0)) < int(time.time()):
            _tbl_sessions().delete_item(Key={"token": token})
            return None
        return dict(item)
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB get_session error: {e}")
        return None


def _session_delete(token: str) -> None:
    if _backend() != "aws":
        def _mutate(sessions):
            sessions.pop(token, None)
            return sessions, None
        update_json(SESSIONS_FILE, _mutate)
        return
    try:
        _tbl_sessions().delete_item(Key={"token": token})
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB delete_session error: {e}")


def _sessions_for_email(email: str):
    """Retorna todos os tokens ativos de um email (GSI em modo aws)."""
    if _backend() != "aws":
        sessions = read_json(SESSIONS_FILE, {})
        return [token for token, item in sessions.items() if item.get("email") == email]
    try:
        resp = _tbl_sessions().query(
            IndexName="email-index",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("email").eq(email),
        )
        return [item["token"] for item in resp.get("Items", [])]
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB query sessions by email error: {e}")
        return []

# ==================== TOKENS DE RESET DE SENHA ====================

def _reset_token_put(token: str, email: str) -> None:
    item = {
        "token": token,
        "email": email,
        "created_at": datetime.now().isoformat(),
        "used": False,
        "expires_at_unix": int(time.time()) + PASSWORD_RESET_TTL_SECONDS,
    }
    if _backend() != "aws":
        def _mutate(resets):
            resets[token] = item
            return resets, None
        update_json(PASSWORD_RESETS_FILE, _mutate)
        return
    _tbl_password_resets().put_item(Item=item)


def _reset_token_get(token: str) -> Optional[Dict[str, Any]]:
    if _backend() != "aws":
        def _mutate(resets):
            found = resets.get(token)
            if not found:
                return resets, None
            if int(found.get("expires_at_unix", 0)) < int(time.time()):
                del resets[token]
                return resets, None
            return resets, found
        return update_json(PASSWORD_RESETS_FILE, _mutate)
    try:
        resp = _tbl_password_resets().get_item(Key={"token": token})
        item = resp.get("Item")
        if not item:
            return None
        if int(item.get("expires_at_unix", 0)) < int(time.time()):
            _tbl_password_resets().delete_item(Key={"token": token})
            return None
        return dict(item)
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB get_reset_token error: {e}")
        return None


def _reset_token_delete(token: str) -> None:
    if _backend() != "aws":
        def _mutate(resets):
            resets.pop(token, None)
            return resets, None
        update_json(PASSWORD_RESETS_FILE, _mutate)
        return
    try:
        _tbl_password_resets().delete_item(Key={"token": token})
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB delete_reset_token error: {e}")


def _send_password_reset_email(to_email: str, reset_link: str) -> bool:
    if _backend() != "aws":
        # Sem SES em modo local -- loga o link pra quem estiver testando o
        # fluxo poder seguir manualmente, sem precisar de infra de email.
        logger.info(f"✉️ [STORAGE_BACKEND=local] Link de redefinição de senha para {to_email}: {reset_link}")
        return True
    try:
        ses = boto3.client("ses", region_name=SES_REGION)
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": "Redefinição de senha — Security Scanner", "Charset": "UTF-8"},
                "Body": {
                    "Text": {
                        "Charset": "UTF-8",
                        "Data": (
                            "Recebemos uma solicitação para redefinir a senha da sua conta.\n\n"
                            f"Clique no link abaixo para criar uma nova senha (válido por 30 minutos):\n{reset_link}\n\n"
                            "Se você não solicitou isso, ignore este email — nenhuma alteração será feita."
                        ),
                    }
                },
            },
        )
        return True
    except Exception as e:
        logger.warning(f"⚠️ SES send_password_reset_email error: {e}")
        return False

# ==================== USUÁRIOS ====================

# Cache em memória; DynamoDB (ou local_data/users.json) é a fonte de verdade
USERS_DB: Dict[str, Dict[str, Any]] = {}
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}  # mantido para compatibilidade de importação


def _user_put(email: str, data: Dict[str, Any]) -> None:
    if _backend() != "aws":
        def _mutate(users):
            users[email] = data
            return users, None
        update_json(USERS_FILE, _mutate)
        USERS_DB[email] = data
        return
    try:
        _tbl_users().put_item(Item={"email": email, **data})
        USERS_DB[email] = data
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB put_user error: {e}")
        raise HTTPException(status_code=500, detail="Erro ao salvar usuário")


def _user_get(email: str) -> Optional[Dict[str, Any]]:
    if email in USERS_DB:
        return USERS_DB[email]
    if _backend() != "aws":
        users = read_json(USERS_FILE, {})
        item = users.get(email)
        if item:
            USERS_DB[email] = item
            return item
        return None
    try:
        resp = _tbl_users().get_item(Key={"email": email})
        item = resp.get("Item")
        if item:
            USERS_DB[email] = dict(item)
            return dict(item)
        return None
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB get_user error: {e}")
        return None


def _users_load_all() -> Dict[str, Dict[str, Any]]:
    if _backend() != "aws":
        return read_json(USERS_FILE, {})
    try:
        resp = _tbl_users().scan()
        return {item["email"]: dict(item) for item in resp.get("Items", [])}
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB scan_users error: {e}")
        return {}


def _migrate_from_s3() -> None:
    """Migração única: copia users_db.json do S3 para DynamoDB. Só faz
    sentido em STORAGE_BACKEND=aws -- em local não há S3 nem DynamoDB."""
    if _backend() != "aws" or not S3_BUCKET:
        return
    try:
        s3 = boto3.client("s3", region_name=DYNAMO_REGION)
        resp = s3.get_object(Bucket=S3_BUCKET, Key="db/users_db.json")
        users = json.loads(resp["Body"].read().decode("utf-8"))
        if not users:
            return
        logger.info(f"🔄 Migrando {len(users)} usuário(s) do S3 para DynamoDB...")
        for email, data in users.items():
            _tbl_users().put_item(Item={"email": email, **data})
        logger.info(f"✅ Migração completa: {len(users)} usuário(s)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return
        logger.warning(f"⚠️ S3 migration error: {e}")
    except Exception as e:
        logger.warning(f"⚠️ Migration error: {e}")


# Cache começa vazio e é populado sob demanda por _user_get() (GetItem por
# chave). Pré-aquecer via _users_load_all() foi removido em 2026-07-28: a
# role da aplicação não tem mais dynamodb:Scan (commit 040761b, reduz raio
# de exposição de uma credencial vazada) desde 2026-07-25, então a chamada
# só gerava AccessDeniedException em todo boot -- sem esse fallback, o
# "if not USERS_DB" também nunca era realmente False, disparando
# _migrate_from_s3() (sobrescrita via snapshot do S3) a cada boot também.
logger.info("✅ Cache de usuários iniciado vazio — populado sob demanda via GetItem")

# ==================== COMPATIBILIDADE DE API ====================

def sync_from_s3() -> None:
    """No-op: mantido para compatibilidade. DynamoDB garante consistência."""
    pass


def sync_if_stale() -> None:
    """No-op: mantido para compatibilidade. DynamoDB garante consistência."""
    pass


security = HTTPBearer(auto_error=False)

COOKIE_NAME = "scanner_session"
COOKIE_MAX_AGE = SESSION_TTL_SECONDS

# ==================== MODELOS ====================

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None

class MFASetup(BaseModel):
    email: EmailStr
    password: str

class MFAVerify(BaseModel):
    email: EmailStr
    code: str

class MFAToggle(BaseModel):
    email: EmailStr
    password: str
    code: Optional[str] = None

class MFARegenerateBackup(BaseModel):
    email: EmailStr
    password: str
    code: str

# ==================== FUNÇÕES AUXILIARES ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password.startswith("$2"):
        # Hash legado SHA256 — aceita auth mas marca para upgrade
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

# NIST 800-63B: comprimento importa mais que complexidade forçada (maiúscula+
# número+símbolo obrigatórios só incentiva padrões previsíveis tipo "Senha123!").
# Usado tanto no cadastro quanto na troca de senha — fonte única da política.
WEAK_PASSWORDS = {
    "password1234", "password123456", "12345678901234", "123456789012",
    "1234567890123", "qwertyuiop1234", "qwertyuiop12345", "administrador123",
    "senha12345678", "senha123456789", "changeme123456", "letmein123456",
    "iloveyou123456", "welcome1234567", "trustno1234567", "abc123456789012",
}


def is_weak_password(password: str) -> bool:
    lowered = password.lower()
    if lowered in WEAK_PASSWORDS:
        return True
    if len(set(lowered)) <= 3:
        return True
    if lowered.isdigit():
        ascending = "".join(str(i % 10) for i in range(len(lowered)))
        if lowered == ascending or lowered == ascending[::-1]:
            return True
    return False


def validate_new_password(password: str, email: Optional[str] = None) -> str:
    """Levanta ValueError se a senha não atende a política. Não valida
    comprimento mínimo — isso fica a cargo do schema Pydantic de cada rota."""
    if is_weak_password(password):
        raise ValueError("Senha muito fraca ou comum. Escolha uma senha menos previsível.")
    if email and str(email).split("@")[0].lower() in password.lower():
        raise ValueError("A senha não pode conter parte do seu email.")
    return password

def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def generate_backup_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(4).upper() for _ in range(count)]


def hash_backup_codes(codes: list[str]) -> list[str]:
    """Backup codes são exibidos em texto puro uma única vez (na geração),
    mas persistidos como hash bcrypt -- igual senha. Sem isso, um vazamento
    do banco de usuários exporia os backup codes em texto puro, anulando o
    MFA (eles funcionam como uma segunda senha)."""
    return [hash_password(c) for c in codes]

def generate_qr_code(email: str, secret: str, issuer: str = "Security Scanner") -> str:
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name=issuer)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"

def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=window)

def verify_backup_code(user_backup_codes_hashed: list[str], code: str):
    code_upper = code.upper().replace("-", "").replace(" ", "")
    for stored in user_backup_codes_hashed:
        # Compatibilidade com códigos gerados antes desta migração (texto
        # puro, sem prefixo bcrypt "$2"). Continuam válidos até serem usados
        # ou regenerados -- não há como hashear retroativamente sem invalidar
        # códigos que o usuário já anotou/guardou.
        matched = verify_password(code_upper, stored) if stored.startswith("$2") else stored == code_upper
        if matched:
            remaining = [h for h in user_backup_codes_hashed if h != stored]
            return True, remaining
    return False, user_backup_codes_hashed

def create_session_token(email: str) -> str:
    token = f"scanner_session_{secrets.token_hex(32)}"
    _session_put(token, email)
    return token

# ==================== DEPENDÊNCIAS ====================

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token não fornecido")
    token = credentials.credentials
    session = _session_get(token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido ou expirado")
    email = session["email"]
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado")
    if user.get("mfa_enabled") and not session.get("mfa_verified"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA não verificado")
    return {
        "email": email,
        "full_name": user.get("full_name"),
        "mfa_enabled": user.get("mfa_enabled", False),
        "session": session,
    }


def get_current_user_from_cookie(request: Request) -> Dict[str, Any]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        logger.error(f"❌ Cookie '{COOKIE_NAME}' não encontrado")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    logger.info(f"✅ Cookie encontrado: {token[:20]}...")
    session = _session_get(token)
    if not session:
        logger.error(f"❌ Token não encontrado no DynamoDB")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    email = session["email"]
    logger.info(f"✅ Sessão válida para: {email}")
    user = _user_get(email)
    if not user:
        logger.error(f"❌ Usuário {email} não encontrado")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if user.get("mfa_enabled") and not session.get("mfa_verified"):
        logger.error(f"❌ MFA não verificado para {email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA não verificado")
    logger.info(f"✅ Autenticação completa para: {email}")
    return {
        "email": email,
        "full_name": user.get("full_name"),
        "mfa_enabled": user.get("mfa_enabled", False),
        "session": session,
    }


def require_mfa(user: Dict[str, Any] = Depends(get_current_user_from_cookie)) -> Dict[str, Any]:
    if not user.get("mfa_enabled"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA necessário para esta operação")
    return user

# ==================== FUNÇÕES DE AUTENTICAÇÃO ====================

def register_user(email: str, password: str, full_name: Optional[str] = None) -> Dict[str, Any]:
    if _user_get(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuário já existe")
    user_data = {
        "email": email,
        "password": hash_password(password),
        "full_name": full_name,
        "mfa_secret": None,
        "mfa_enabled": False,
        "backup_codes": [],
        "created_at": datetime.now().isoformat(),
    }
    _user_put(email, user_data)
    logger.info(f"✅ Usuário registrado: {email}")
    return {"message": "Usuário criado com sucesso", "email": email}


def login_user(email: str, password: str, mfa_code: Optional[str] = None, response: Optional[Response] = None) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

    # Migração silenciosa SHA256 → bcrypt no primeiro login após atualização
    if not user["password"].startswith("$2"):
        user["password"] = hash_password(password)
        _user_put(email, user)

    if user["mfa_enabled"]:
        if not mfa_code:
            return {"message": "MFA requerido", "mfa_required": True, "authenticated": False}

        if verify_totp_code(user["mfa_secret"], mfa_code):
            token = create_session_token(email)
            if response:
                response.set_cookie(key=COOKIE_NAME, value=token, max_age=COOKIE_MAX_AGE,
                                    httponly=True, samesite="lax", secure=True)
                logger.info(f"✅ Cookie criado para {email}: {token[:20]}...")
            return {"message": "Login bem-sucedido", "authenticated": True, "email": email,
                    "full_name": user.get("full_name"), "token": token, "mfa_enabled": True}

        is_valid, updated_codes = verify_backup_code(user["backup_codes"], mfa_code)
        if is_valid:
            user["backup_codes"] = updated_codes
            _user_put(email, user)
            token = create_session_token(email)
            if response:
                response.set_cookie(key=COOKIE_NAME, value=token, max_age=COOKIE_MAX_AGE,
                                    httponly=True, samesite="lax", secure=True)
                logger.info(f"✅ Cookie criado para {email}: {token[:20]}...")
            return {"message": "Login bem-sucedido (backup code usado)", "authenticated": True, "email": email,
                    "full_name": user.get("full_name"), "token": token, "mfa_enabled": True,
                    "warning": f"Você tem {len(updated_codes)} backup codes restantes"}

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido")

    token = create_session_token(email)
    if response:
        response.set_cookie(key=COOKIE_NAME, value=token, max_age=COOKIE_MAX_AGE,
                            httponly=True, samesite="lax", secure=True)
        logger.info(f"✅ Cookie criado para {email}: {token[:20]}...")
    return {"message": "Login bem-sucedido", "authenticated": True, "email": email,
            "full_name": user.get("full_name"), "token": token, "mfa_enabled": False}


def setup_mfa(email: str, password: Optional[str] = None, code: Optional[str] = None) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")

    # Se já existe um secret configurado, exige prova de posse da conta antes
    # de gerar um novo -- sem isso, qualquer requisição sem autenticação
    # (só com o email) conseguia sobrescrever o MFA de qualquer conta em
    # segredo (mfa_enabled continua True) e sequestrá-la sabendo a senha.
    # Conta nova (mfa_secret ainda None, chamada direto por /auth/register)
    # continua liberada, sem quebrar o fluxo de onboarding.
    if user.get("mfa_secret"):
        if not password or not verify_password(password, user["password"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha incorreta")
        if user.get("mfa_enabled"):
            if not code or not verify_totp_code(user["mfa_secret"], code):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido")

    secret = generate_mfa_secret()
    backup_codes = generate_backup_codes()
    qr_code = generate_qr_code(email, secret)
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="Security Scanner")
    user["mfa_secret"] = secret
    user["backup_codes"] = hash_backup_codes(backup_codes)
    _user_put(email, user)
    logger.info(f"✅ MFA configurado para {email}")
    return {"secret": secret, "qr_code": qr_code, "backup_codes": backup_codes, "provisioning_uri": provisioning_uri}


def verify_and_activate_mfa(email: str, code: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    if not user.get("mfa_secret"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA não configurado. Execute setup primeiro")
    logger.info(f"🔍 Verificando MFA para {email}")
    if verify_totp_code(user["mfa_secret"], code):
        user["mfa_enabled"] = True
        _user_put(email, user)
        logger.info(f"✅ MFA ativado para {email}")
        return {"message": "MFA ativado com sucesso!", "mfa_enabled": True}
    logger.error(f"❌ Código inválido para {email}")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código inválido")


def disable_mfa(email: str, password: str, code: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha incorreta")
    if not verify_totp_code(user["mfa_secret"], code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido")
    user["mfa_enabled"] = False
    user["mfa_secret"] = None
    user["backup_codes"] = []
    _user_put(email, user)
    logger.info(f"✅ MFA desativado para {email}")
    return {"message": "MFA desativado com sucesso"}


def get_mfa_status(email: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    return {
        "email": email,
        "mfa_enabled": user.get("mfa_enabled", False),
        "backup_codes_remaining": len(user.get("backup_codes", [])),
    }


def regenerate_backup_codes(email: str, password: str, code: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha incorreta")
    if not verify_totp_code(user["mfa_secret"], code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido")
    new_codes = generate_backup_codes()
    user["backup_codes"] = hash_backup_codes(new_codes)
    _user_put(email, user)
    return {"message": "Backup codes regenerados", "backup_codes": new_codes}


def change_password(email: str, current_password: str, code: str, new_password: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    if not verify_password(current_password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha atual incorreta")

    if user.get("mfa_enabled"):
        if not verify_totp_code(user["mfa_secret"], code):
            is_valid, updated_codes = verify_backup_code(user.get("backup_codes", []), code)
            if not is_valid:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido")
            user["backup_codes"] = updated_codes

    try:
        validate_new_password(new_password, email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user["password"] = hash_password(new_password)
    _user_put(email, user)
    revoked = logout_all_sessions(email)
    logger.info(f"✅ Senha alterada para {email} ({revoked} sessão(ões) invalidada(s))")
    return {"message": "Senha alterada com sucesso. Faça login novamente.", "sessions_revoked": revoked}


def request_password_reset(email: str) -> None:
    """Nunca revela se o email existe -- só envia o link se a conta existir
    de fato. O endpoint sempre responde a mesma mensagem genérica."""
    user = _user_get(email)
    if not user:
        logger.info(f"ℹ️ Reset de senha solicitado para email não cadastrado: {email}")
        return
    token = secrets.token_urlsafe(32)
    _reset_token_put(token, email)
    reset_link = f"{APP_BASE_URL}/reset-password?token={token}"
    if _send_password_reset_email(email, reset_link):
        logger.info(f"✅ Email de reset de senha enviado para {email}")
    else:
        logger.warning(f"⚠️ Falha ao enviar email de reset de senha para {email}")


def reset_password(token: str, new_password: str) -> Dict[str, Any]:
    reset_item = _reset_token_get(token)
    if not reset_item:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Link de redefinição inválido ou expirado.")

    email = reset_item["email"]
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Link de redefinição inválido ou expirado.")

    try:
        validate_new_password(new_password, email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user["password"] = hash_password(new_password)
    _user_put(email, user)
    _reset_token_delete(token)
    revoked = logout_all_sessions(email)
    logger.info(f"✅ Senha redefinida via token para {email} ({revoked} sessão(ões) invalidada(s))")
    return {"message": "Senha redefinida com sucesso. Faça login normalmente.", "sessions_revoked": revoked}


def logout_user(token: str, response: Optional[Response] = None) -> Dict[str, Any]:
    _session_delete(token)
    if response:
        response.delete_cookie(key=COOKIE_NAME)
        logger.info(f"✅ Cookie removido")
    return {"message": "Logout realizado com sucesso"}


def logout_all_sessions(email: str) -> int:
    """Remove todas as sessões ativas de um email via DynamoDB GSI."""
    tokens = _sessions_for_email(email)
    for token in tokens:
        _session_delete(token)
    return len(tokens)

# ==================== INFORMAÇÕES ====================

def get_system_stats() -> Dict[str, Any]:
    if _backend() != "aws":
        active_count = len(read_json(SESSIONS_FILE, {}))
    else:
        try:
            resp = _tbl_sessions().scan(Select="COUNT")
            active_count = resp.get("Count", 0)
        except Exception:
            active_count = -1
    return {
        "total_users": len(USERS_DB),
        "users_with_mfa": sum(1 for u in USERS_DB.values() if u.get("mfa_enabled")),
        "active_sessions": active_count,
    }
