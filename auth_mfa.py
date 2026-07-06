"""
auth_mfa.py - Autenticação MFA com persistência em DynamoDB.

Sessões: DynamoDB (security-scanner-sessions) — sem race condition entre instâncias.
Usuários: DynamoDB (security-scanner-users) com cache em memória — consistência forte.
Migration: na primeira inicialização, se DynamoDB vazio, migra de users_db.json no S3.
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

# ==================== CONFIGURAÇÃO ====================

S3_BUCKET = os.environ.get("DB_S3_BUCKET", "security-scanner-db-442042548551")
DYNAMO_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")
SESSIONS_TABLE = os.environ.get("SESSIONS_DYNAMO_TABLE", "security-scanner-sessions")
USERS_TABLE = os.environ.get("USERS_DYNAMO_TABLE", "security-scanner-users")

SESSION_TTL_SECONDS = 86400  # 24 h

_dynamo = boto3.resource("dynamodb", region_name=DYNAMO_REGION)
_tbl_sessions = _dynamo.Table(SESSIONS_TABLE)
_tbl_users = _dynamo.Table(USERS_TABLE)

# ==================== DYNAMO — SESSÕES ====================

def _session_put(token: str, email: str) -> None:
    _tbl_sessions.put_item(Item={
        "token": token,
        "email": email,
        "created_at": datetime.now().isoformat(),
        "authenticated": True,
        "mfa_verified": True,
        "expires_at_unix": int(time.time()) + SESSION_TTL_SECONDS,
    })


def _session_get(token: str) -> Optional[Dict[str, Any]]:
    try:
        resp = _tbl_sessions.get_item(Key={"token": token})
        item = resp.get("Item")
        if not item:
            return None
        # Verificação manual de expiração (TTL do DynamoDB não é instantâneo)
        if int(item.get("expires_at_unix", 0)) < int(time.time()):
            _tbl_sessions.delete_item(Key={"token": token})
            return None
        return dict(item)
    except Exception as e:
        print(f"⚠️ DynamoDB get_session error: {e}")
        return None


def _session_delete(token: str) -> None:
    try:
        _tbl_sessions.delete_item(Key={"token": token})
    except Exception as e:
        print(f"⚠️ DynamoDB delete_session error: {e}")


def _sessions_for_email(email: str):
    """Retorna todos os tokens ativos de um email via GSI."""
    try:
        resp = _tbl_sessions.query(
            IndexName="email-index",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("email").eq(email),
        )
        return [item["token"] for item in resp.get("Items", [])]
    except Exception as e:
        print(f"⚠️ DynamoDB query sessions by email error: {e}")
        return []

# ==================== DYNAMO — USUÁRIOS ====================

# Cache em memória; DynamoDB é a fonte de verdade
USERS_DB: Dict[str, Dict[str, Any]] = {}
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}  # mantido para compatibilidade de importação


def _user_put(email: str, data: Dict[str, Any]) -> None:
    try:
        _tbl_users.put_item(Item={"email": email, **data})
        USERS_DB[email] = data
    except Exception as e:
        print(f"⚠️ DynamoDB put_user error: {e}")
        raise HTTPException(status_code=500, detail="Erro ao salvar usuário")


def _user_get(email: str) -> Optional[Dict[str, Any]]:
    if email in USERS_DB:
        return USERS_DB[email]
    try:
        resp = _tbl_users.get_item(Key={"email": email})
        item = resp.get("Item")
        if item:
            USERS_DB[email] = dict(item)
            return dict(item)
        return None
    except Exception as e:
        print(f"⚠️ DynamoDB get_user error: {e}")
        return None


def _users_load_all() -> Dict[str, Dict[str, Any]]:
    try:
        resp = _tbl_users.scan()
        return {item["email"]: dict(item) for item in resp.get("Items", [])}
    except Exception as e:
        print(f"⚠️ DynamoDB scan_users error: {e}")
        return {}


def _migrate_from_s3() -> None:
    """Migração única: copia users_db.json do S3 para DynamoDB."""
    if not S3_BUCKET:
        return
    try:
        s3 = boto3.client("s3", region_name=DYNAMO_REGION)
        resp = s3.get_object(Bucket=S3_BUCKET, Key="db/users_db.json")
        users = json.loads(resp["Body"].read().decode("utf-8"))
        if not users:
            return
        print(f"🔄 Migrando {len(users)} usuário(s) do S3 para DynamoDB...")
        for email, data in users.items():
            _tbl_users.put_item(Item={"email": email, **data})
        print(f"✅ Migração completa: {len(users)} usuário(s)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return
        print(f"⚠️ S3 migration error: {e}")
    except Exception as e:
        print(f"⚠️ Migration error: {e}")


# Carrega usuários na inicialização; migra do S3 se DynamoDB estiver vazio
USERS_DB = _users_load_all()
if not USERS_DB:
    _migrate_from_s3()
    USERS_DB = _users_load_all()

print(f"✅ Banco de dados carregado: {len(USERS_DB)} usuário(s)")

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

def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def generate_backup_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(4).upper() for _ in range(count)]

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

def verify_backup_code(user_backup_codes: list[str], code: str):
    code_upper = code.upper().replace("-", "").replace(" ", "")
    if code_upper in user_backup_codes:
        return True, [c for c in user_backup_codes if c != code_upper]
    return False, user_backup_codes

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
        print(f"❌ Cookie '{COOKIE_NAME}' não encontrado")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    print(f"✅ Cookie encontrado: {token[:20]}...")
    session = _session_get(token)
    if not session:
        print(f"❌ Token não encontrado no DynamoDB")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    email = session["email"]
    print(f"✅ Sessão válida para: {email}")
    user = _user_get(email)
    if not user:
        print(f"❌ Usuário {email} não encontrado")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if user.get("mfa_enabled") and not session.get("mfa_verified"):
        print(f"❌ MFA não verificado para {email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA não verificado")
    print(f"✅ Autenticação completa para: {email}")
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
    print(f"✅ Usuário registrado: {email}")
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
                print(f"✅ Cookie criado para {email}: {token[:20]}...")
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
                print(f"✅ Cookie criado para {email}: {token[:20]}...")
            return {"message": "Login bem-sucedido (backup code usado)", "authenticated": True, "email": email,
                    "full_name": user.get("full_name"), "token": token, "mfa_enabled": True,
                    "warning": f"Você tem {len(updated_codes)} backup codes restantes"}

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido")

    token = create_session_token(email)
    if response:
        response.set_cookie(key=COOKIE_NAME, value=token, max_age=COOKIE_MAX_AGE,
                            httponly=True, samesite="lax", secure=True)
        print(f"✅ Cookie criado para {email}: {token[:20]}...")
    return {"message": "Login bem-sucedido", "authenticated": True, "email": email,
            "full_name": user.get("full_name"), "token": token, "mfa_enabled": False}


def setup_mfa(email: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    secret = generate_mfa_secret()
    backup_codes = generate_backup_codes()
    qr_code = generate_qr_code(email, secret)
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="Security Scanner")
    user["mfa_secret"] = secret
    user["backup_codes"] = backup_codes
    _user_put(email, user)
    print(f"✅ MFA configurado para {email}")
    print(f"   Secret: {secret}")
    print(f"   Código atual: {pyotp.TOTP(secret).now()}")
    return {"secret": secret, "qr_code": qr_code, "backup_codes": backup_codes, "provisioning_uri": provisioning_uri}


def verify_and_activate_mfa(email: str, code: str) -> Dict[str, Any]:
    user = _user_get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    if not user.get("mfa_secret"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA não configurado. Execute setup primeiro")
    print(f"🔍 Verificando MFA para {email}")
    print(f"   Secret: {user['mfa_secret']}")
    print(f"   Código recebido: {code}")
    print(f"   Código esperado: {pyotp.TOTP(user['mfa_secret']).now()}")
    if verify_totp_code(user["mfa_secret"], code):
        user["mfa_enabled"] = True
        _user_put(email, user)
        print(f"✅ MFA ativado para {email}")
        return {"message": "MFA ativado com sucesso!", "mfa_enabled": True}
    print(f"❌ Código inválido para {email}")
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
    print(f"✅ MFA desativado para {email}")
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
    user["backup_codes"] = new_codes
    _user_put(email, user)
    return {"message": "Backup codes regenerados", "backup_codes": new_codes}


def logout_user(token: str, response: Optional[Response] = None) -> Dict[str, Any]:
    _session_delete(token)
    if response:
        response.delete_cookie(key=COOKIE_NAME)
        print(f"✅ Cookie removido")
    return {"message": "Logout realizado com sucesso"}


def logout_all_sessions(email: str) -> int:
    """Remove todas as sessões ativas de um email via DynamoDB GSI."""
    tokens = _sessions_for_email(email)
    for token in tokens:
        _session_delete(token)
    return len(tokens)

# ==================== INFORMAÇÕES ====================

def get_system_stats() -> Dict[str, Any]:
    try:
        resp = _tbl_sessions.scan(Select="COUNT")
        active_count = resp.get("Count", 0)
    except Exception:
        active_count = -1
    return {
        "total_users": len(USERS_DB),
        "users_with_mfa": sum(1 for u in USERS_DB.values() if u.get("mfa_enabled")),
        "active_sessions": active_count,
    }
