"""
api_with_mfa.py - FastAPI app do Security Multicloud Storage Scanner com MFA obrigatório.

Inclui:
- Páginas: /login, /mfa/setup, /dashboard
- Auth/MFA:
  POST /auth/register
  POST /auth/login
  GET  /auth/mfa/status
  POST /auth/mfa/verify
  POST /auth/logout
- API protegida (MFA obrigatório):
  GET  /api/dashboard
  GET  /scan/{target}            (scan público - compatível com dashboard)
  POST /scan/public              (scan público - recomendado)
  POST /scan/authenticated       (scan privado com credenciais)
  POST /generate-report          (gera PDF + DOCX no padrão do ambiente)
  GET  /reports_executive/{file} (download público do relatório gerado)

Obs:
- Este arquivo espera que existam no projeto:
  - templates/login.html
  - templates/mfa_setup.html
  - templates/dashboard.html
  - auth_mfa.py
  - auditor_s3_authenticated.py (classe S3AuthenticatedAuditor)
  - auditor_universal.py (opcional, para scan público multicloud)
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import NoCredentialsError

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator

# === Auth/MFA do projeto ===
from auth_mfa import (  # type: ignore
    ACTIVE_SESSIONS,
    S3_BUCKET,
    USERS_DB,
    change_password,
    get_current_user,
    login_user,
    logout_all_sessions,
    register_user,
    request_password_reset,
    require_mfa,
    reset_password,
    setup_mfa,
    sync_from_s3,
    validate_new_password,
    verify_and_activate_mfa,
)

# === Auditor autenticado (AWS S3) ===
from auditor_s3_authenticated import S3AuthenticatedAuditor  # type: ignore
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse

from logging_setup import setup_logging, get_logger, set_request_id, get_request_id, new_request_id
from metrics import put_metric, timed_metric
from starlette.middleware.base import BaseHTTPMiddleware

setup_logging()
logger = get_logger("api")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Gera (ou reaproveita) um request_id por requisição e o disponibiliza
    para todos os logs estruturados emitidos durante o processamento dela."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or new_request_id()
        set_request_id(request_id)
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response

# === Histórico de scans ===
try:
    from scan_history import save_scan, list_scans, load_recent  # type: ignore
    HISTORY_AVAILABLE = True
except Exception as _hist_e:
    HISTORY_AVAILABLE = False
    logger.warning(f"⚠️ scan_history indisponível: {_hist_e}")

# === IA — Claude (Anthropic) ===
try:
    import ai_analyzer  # type: ignore
    AI_AVAILABLE = True
    logger.info("✅ ai_analyzer carregado")
except Exception as _ai_e:
    AI_AVAILABLE = False
    logger.warning(f"⚠️ ai_analyzer indisponível: {_ai_e}")

# === PDF/DOCX Profissional ===
try:
    from generate_report import generate_executive_report as _gen_executive_report
    PROFESSIONAL_REPORT = True
    logger.info("✅ Gerador de relatórios profissional carregado")
except ImportError as e:
    PROFESSIONAL_REPORT = False
    logger.warning(f"⚠️  generate_report.py não encontrado, usando fallback: {e}")
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as rl_canvas
    from docx import Document


# -----------------------------------------------------------------------------
# App / Templates / Static
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = BASE_DIR / "reports_executive"
REPORTS_DIR.mkdir(exist_ok=True)

_S3_REPORTS_PREFIX = "reports/"

def _upload_report_s3(local_path: Path) -> None:
    if not S3_BUCKET or not local_path.exists() or not local_path.name:
        return
    try:
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        s3.upload_file(str(local_path), S3_BUCKET, _S3_REPORTS_PREFIX + local_path.name)
    except Exception as e:
        logger.warning(f"⚠️ S3 report upload error: {e}")

def _download_report_s3(filename: str) -> Path | None:
    if not S3_BUCKET or not filename:
        return None
    try:
        dest = REPORTS_DIR / filename
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        s3.download_file(S3_BUCKET, _S3_REPORTS_PREFIX + filename, str(dest))
        return dest
    except Exception:
        return None


def _email_safe(email: str) -> str:
    return email.replace("@", "_at_").replace(".", "_").lower()


def _save_last_scan(email: str, result: Dict[str, Any]) -> None:
    if not S3_BUCKET or not email:
        return
    try:
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        key = f"last-scan/{_email_safe(email)}.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(result, default=str).encode("utf-8"),
            ContentType="application/json",
        )
    except Exception as e:
        logger.warning(f"⚠️ _save_last_scan error: {e}")


def _load_last_scan(email: str) -> Optional[Dict[str, Any]]:
    if not S3_BUCKET or not email:
        return None
    try:
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        key = f"last-scan/{_email_safe(email)}.json"
        resp = s3.get_object(Bucket=S3_BUCKET, Key=key)
        return json.loads(resp["Body"].read().decode("utf-8"))
    except Exception:
        return None


class _ScanCache:
    """Cache do último scan por email — persiste no S3 para suportar múltiplas instâncias EC2."""

    def __init__(self) -> None:
        self._mem: Dict[str, Dict[str, Any]] = {}

    def __setitem__(self, email: str, result: Dict[str, Any]) -> None:
        self._mem[email] = result
        _save_last_scan(email, result)

    def get(self, email: Optional[str], default: Any = None) -> Any:
        if not email:
            return default
        if email in self._mem:
            return self._mem[email]
        return _load_last_scan(email) or default


# ── Async scan job store ──────────────────────────────────────────────────────
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="scan-worker")
_JOBS_S3_PREFIX = "scan-jobs/"
_JOB_STORE_MEM: Dict[str, Dict[str, Any]] = {}


def _job_write(job_id: str, data: Dict[str, Any]) -> None:
    _JOB_STORE_MEM[job_id] = data
    if not S3_BUCKET:
        return
    try:
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=f"{_JOBS_S3_PREFIX}{job_id}.json",
            Body=json.dumps(data, default=str).encode("utf-8"),
            ContentType="application/json",
        )
    except Exception as _e:
        logger.warning(f"⚠️ _job_write S3 error: {_e}")


def _job_read(job_id: str) -> Optional[Dict[str, Any]]:
    if job_id in _JOB_STORE_MEM:
        return _JOB_STORE_MEM[job_id]
    if not S3_BUCKET:
        return None
    try:
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        resp = s3.get_object(Bucket=S3_BUCKET, Key=f"{_JOBS_S3_PREFIX}{job_id}.json")
        data = json.loads(resp["Body"].read().decode("utf-8"))
        _JOB_STORE_MEM[job_id] = data
        return data
    except Exception:
        return None


def _run_in_background(
    job_id: str,
    scan_type: str,
    started_at: str,
    email: Optional[str],
    fn,
    *args,
    _request_id: Optional[str] = None,
    **kwargs,
) -> None:
    # ThreadPoolExecutor não propaga contextvars automaticamente -- sem isso,
    # os logs deste job apareceriam com request_id "-" em vez do id da
    # requisição HTTP que disparou a varredura assíncrona
    if _request_id:
        set_request_id(_request_id)
    _job_write(job_id, {
        "job_id": job_id, "type": scan_type, "status": "running",
        "started_at": started_at, "finished_at": None, "result": None, "error": None,
    })
    _scan_start = time.monotonic()
    try:
        result = fn(*args, **kwargs)
        if email:
            LAST_SCAN_BY_EMAIL[email] = result
            if HISTORY_AVAILABLE:
                try:
                    save_scan(email, scan_type, result)
                except Exception as _e:
                    logger.warning(f"⚠️ save_scan error: {_e}")

        # Disparo automático da análise por IA -- antes só rodava sob clique do
        # usuário no painel. Best-effort: nunca derruba o job de scan se a IA
        # falhar ou estiver indisponível, só fica sem a análise.
        analysis = None
        if AI_AVAILABLE:
            try:
                with timed_metric("AiAnalysisDuration", dimensions={"Operation": "auto_analyze"}):
                    analysis = ai_analyzer.analyze(result)
            except Exception as _e:
                logger.warning(f"⚠️ auto-analyze error: {_e}")

        _job_write(job_id, {
            "job_id": job_id, "type": scan_type, "status": "done",
            "started_at": started_at, "finished_at": datetime.now().isoformat(),
            "result": result, "error": None, "analysis": analysis,
        })
        put_metric("ScanDuration", (time.monotonic() - _scan_start) * 1000, unit="Milliseconds", dimensions={"Provider": scan_type})
        put_metric("ScanResult", 1, dimensions={"Provider": scan_type, "Result": "success"})
    except Exception as _e:
        logger.error(f"❌ Scan job {job_id} ({scan_type}) failed: {_e}")
        _job_write(job_id, {
            "job_id": job_id, "type": scan_type, "status": "error",
            "started_at": started_at, "finished_at": datetime.now().isoformat(),
            "result": None, "error": str(_e),
        })
        put_metric("ScanDuration", (time.monotonic() - _scan_start) * 1000, unit="Milliseconds", dimensions={"Provider": scan_type})
        put_metric("ScanResult", 1, dimensions={"Provider": scan_type, "Result": "failure"})


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

app = FastAPI(title="Security Multicloud Storage Scanner (MFA)")
app.add_middleware(RequestIdMiddleware)

_redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
try:
    import redis as _redis_lib
    _redis_client = _redis_lib.Redis.from_url(_redis_url, socket_connect_timeout=1, socket_timeout=1)
    _redis_client.ping()
    _storage_uri = _redis_url
    _redis_available = True
    logger.info("✅ Rate limiter: Redis backend ativo")
except Exception as _e:
    _redis_client = None
    _storage_uri = "memory://"
    _redis_available = False
    logger.warning(f"⚠️ Rate limiter: Redis indisponível ({_e}), usando memória por worker")

limiter = Limiter(key_func=get_client_ip, storage_uri=_storage_uri)
app.state.limiter = limiter


def _rate_limit_exceeded_handler_with_metric(request: Request, exc: RateLimitExceeded):
    """Métrica de abuso -- monitor de abuso de IA (Terraform: alarme em
    RateLimitExceeded). Wrap fino do handler padrão do slowapi, só pra
    registrar a métrica antes de devolver o 429 de sempre."""
    put_metric("RateLimitExceeded", 1, dimensions={"Path": request.url.path})
    return _rate_limit_exceeded_handler(request, exc)


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler_with_metric)
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # exc.errors() pode conter um ValueError cru em errors[i]['ctx']['error'] quando o
    # erro vem de um @field_validator que faz "raise ValueError(...)" (ex.: política de
    # senha) — json.dumps quebra nisso. jsonable_encoder sabe serializar esse caso.
    errors = jsonable_encoder(exc.errors())
    logger.error(f"❌ 422 em {request.method} {request.url.path}: {errors}")
    return JSONResponse(status_code=422, content={"detail": errors})
# Cache do último scan por usuário — persiste no S3 para suportar múltiplas instâncias
LAST_SCAN_BY_EMAIL: _ScanCache = _ScanCache()

# Rate limiting manual para /auth/login — os decorators @limiter.limit encadeados
# corrompem a inspeção de assinatura do FastAPI e causam 422 "Field required"
_login_ts_minute: Dict[str, List[float]] = defaultdict(list)
_login_ts_hour: Dict[str, List[float]] = defaultdict(list)

def _check_login_rate(ip: str) -> None:
    now = time.time()
    if _redis_available and _redis_client:
        key_min = f"login_rate:min:{ip}"
        key_hr  = f"login_rate:hr:{ip}"
        pipe = _redis_client.pipeline()
        pipe.zremrangebyscore(key_min, 0, now - 60)
        pipe.zcard(key_min)
        pipe.zremrangebyscore(key_hr, 0, now - 3600)
        pipe.zcard(key_hr)
        results = pipe.execute()
        count_min, count_hr = results[1], results[3]
        if count_min >= 3:
            raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto.")
        if count_hr >= 10:
            raise HTTPException(status_code=429, detail="Limite por hora atingido. Aguarde antes de tentar novamente.")
        pipe = _redis_client.pipeline()
        pipe.zadd(key_min, {str(now): now})
        pipe.expire(key_min, 61)
        pipe.zadd(key_hr, {str(now): now})
        pipe.expire(key_hr, 3601)
        pipe.execute()
    else:
        _login_ts_minute[ip] = [t for t in _login_ts_minute[ip] if now - t < 60]
        _login_ts_hour[ip]   = [t for t in _login_ts_hour[ip]   if now - t < 3600]
        if len(_login_ts_minute[ip]) >= 3:
            raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto.")
        if len(_login_ts_hour[ip]) >= 10:
            raise HTTPException(status_code=429, detail="Limite por hora atingido. Aguarde antes de tentar novamente.")
        _login_ts_minute[ip].append(now)
        _login_ts_hour[ip].append(now)

_cors_raw = os.environ.get("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()] or [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

# Domínios autorizados a criar conta — sem isso, /auth/register aceitava
# qualquer email, permitindo que qualquer pessoa se cadastrasse e acessasse o
# ambiente. Fail-closed de propósito: se a variável não estiver configurada,
# nenhum registro é permitido (em vez de abrir para todo mundo por omissão).
# Restringe por DOMÍNIO (ex.: "oi.net.br") em vez de lista de emails exatos —
# qualquer email corporativo do domínio pode se cadastrar, sem precisar
# adicionar cada endereço manualmente. Não afeta contas já existentes fora
# do domínio (o cadastro é o único ponto de checagem).
_allowed_domains_raw = os.environ.get("ALLOWED_REGISTRATION_DOMAINS", "")
ALLOWED_REGISTRATION_DOMAINS = {
    d.strip().lower().lstrip("@") for d in _allowed_domains_raw.split(",") if d.strip()
}


def _is_email_domain_allowed(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in ALLOWED_REGISTRATION_DOMAINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
# IMPORTANTE: no seu ambiente AWS, o browser abre diretamente o PDF/DOCX.
# Para evitar 401 no GET do arquivo (porque o browser não manda Authorization),
# exponho o diretório como estático (mesmo comportamento do seu print).
# /reports_executive/{filename} é servido pela rota dinâmica definida na seção de relatórios (com fallback S3)


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------
class UserRegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)

    @field_validator("password")
    @classmethod
    def _validate_password_strength(cls, v: str, info) -> str:
        try:
            return validate_new_password(v, info.data.get("email"))
        except ValueError as e:
            raise ValueError(str(e))


class ChangePasswordIn(BaseModel):
    current_password: str
    mfa_code: str = Field(min_length=6, max_length=64)
    new_password: str = Field(min_length=12, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _validate_new_password_strength(cls, v: str) -> str:
        try:
            return validate_new_password(v)
        except ValueError as e:
            raise ValueError(str(e))


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=12, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _validate_new_password_strength(cls, v: str) -> str:
        try:
            return validate_new_password(v)
        except ValueError as e:
            raise ValueError(str(e))


class UserLoginIn(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None


class MFASetupIn(BaseModel):
    email: EmailStr
    # Só exigidos quando a conta já tem um MFA configurado (ver setup_mfa em
    # auth_mfa.py) -- onboarding de conta nova (mfa_secret ainda None)
    # continua funcionando sem esses dois campos.
    password: Optional[str] = None
    code: Optional[str] = None


class MFAVerifyIn(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=10)


@app.post("/auth/mfa/setup")
def auth_mfa_setup(data: MFASetupIn):
    """Gera QR Code para MFA após o login"""
    try:
        email = str(data.email).lower().strip()

        # Sincroniza do S3 antes de buscar — garante visibilidade de usuários criados em outra instância
        sync_from_s3()

        # Validar se usuário existe
        user = USERS_DB.get(email)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        
        mfa = setup_mfa(email=email, password=data.password, code=data.code)
        
        return {
            "email": email,
            "qr_code": mfa.get("qr_code"),
            "secret": mfa.get("secret"),
            "backup_codes": mfa.get("backup_codes", []),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PublicScanIn(BaseModel):
    target: str = Field(..., description="Bucket/host alvo. Ex.: bucket.s3.amazonaws.com, storage.googleapis.com/bucket, *.blob.core.windows.net")
    max_objects: int = 10000


class AuthenticatedScanIn(BaseModel):
    provider: str = Field(default="AWS_S3")
    bucket: str

    # AWS
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    region_name: Optional[str] = None  # nome correto (o dashboard às vezes manda "region")

    # compat: alguns dashboards mandam "region"
    region: Optional[str] = None
    # GCS
    service_account_key: Optional[Dict[str, Any]] = None


    max_objects: int = 10000


class GenerateReportIn(BaseModel):
    scan_result: Dict[str, Any] = Field(default_factory=dict)
    scan_data: Dict[str, Any] = Field(default_factory=dict)  # alias frontend legacy
    report_title: str = "Relatório Executivo de Segurança"
    client_name: Optional[str] = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _safe_filename(name: str) -> str:
    keep = []
    for ch in str(name):
        if ch.isalnum() or ch in ("-", "_", ".", "@"):
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep)


def _format_bytes(num: Any) -> str:
    try:
        n = float(num or 0)
    except Exception:
        return str(num)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"

import re
from urllib.parse import urlparse

def _detect_provider(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return "UNIVERSAL"

    # Decide sempre pelo HOST parseado (urlparse), nunca por regex/substring
    # na string crua -- essa era a causa de um SSRF real: um "target" tipo
    # "attacker.com/x.s3.amazonaws.com/" continha ".s3.amazonaws.com/" em
    # QUALQUER posição da string (não só no host), então batia no regex
    # antigo e era roteado como AWS_S3 -- indo direto para S3Auditor, que
    # (sem esquema "://") caía no fallback "retorna a string inteira" e
    # montava a URL de requisição com "attacker.com" como host de verdade.
    normalized = t if "://" in t else f"https://{t}"
    host = (urlparse(normalized).hostname or "").lower()

    # AWS S3 (s3-REGION, s3.REGION, s3.amazonaws.com) -- ancorado no FIM do
    # host, não em qualquer lugar da string
    if re.search(r"\.s3([.-][a-z0-9-]+)?\.amazonaws\.com$", host):
        return "AWS_S3"

    # GCS
    if host == "storage.googleapis.com" or host.endswith(".storage.googleapis.com"):
        return "GCS"

    # Azure Blob
    if host.endswith(".blob.core.windows.net"):
        return "AZURE_BLOB"

    return "UNIVERSAL"



def _load_universal_auditor():
    """
    Tenta carregar um auditor multicloud do seu projeto (auditor_universal.py).
    Não falha se não existir.
    """
    try:
        import auditor_universal  # type: ignore

        for name in ("UniversalAuditor", "AuditorUniversal", "UniversalScanner", "UniversalStorageAuditor"):
            cls = getattr(auditor_universal, name, None)
            if cls:
                return cls
    except Exception:
        return None
    return None



def _ensure_recommendations(scan: Dict[str, Any], provider: str) -> None:
    """Garante recomendações mínimas quando não houver achados (para AWS/GCP/Azure)."""
    recos = scan.get('recommendations')
    if recos is None:
        recos = []
    if not isinstance(recos, list):
        recos = []

    files = scan.get('files') or scan.get('vulnerable_files') or []
    has_findings = isinstance(files, list) and len(files) > 0

    # tenta inferir risco
    risk_counts = scan.get('risk_counts') or {}
    if isinstance(risk_counts, dict):
        total_risks = sum(int(v or 0) for v in risk_counts.values() if str(v).isdigit() or isinstance(v,(int,float)))
    else:
        total_risks = 0

    if has_findings or total_risks > 0 or recos:
        scan['recommendations'] = recos
        return

    p = (provider or scan.get('provider') or 'UNIVERSAL').upper()
    base = [
        'Nenhum risco crítico detectado no momento.',
        'Mantenha boas práticas de segurança e monitoramento contínuo.',
    ]
    if p in ('AWS', 'AWS_S3', 'S3'):
        base += [
            'Revisar Block Public Access, ACLs e Bucket Policy do S3.',
            'Ativar CloudTrail/CloudWatch e alertas para mudanças de permissão.',
        ]
    elif p in ('GCP', 'GCS', 'GOOGLE', 'GOOGLE_CLOUD_STORAGE'):
        base += [
            'Revisar IAM do bucket e habilitar Public Access Prevention (quando aplicável).',
            'Habilitar logs de acesso e alertas para alterações de permissões.',
        ]
    elif p in ('AZURE', 'AZURE_BLOB', 'BLOB', 'AZURE_STORAGE'):
        base += [
            'Revisar o nível de acesso público do container (Private/Blob/Container).',
            'Ativar Microsoft Defender for Storage e logs/alertas de acesso.',
        ]
    else:
        base += [
            'Revisar permissões, políticas de acesso público e logs do storage.',
        ]

    scan['recommendations'] = base
def _normalize_scan_result(scan: Dict[str, Any], provider: str, target: str) -> Dict[str, Any]:
    # garante campos base usados no dashboard/relatório
    scan = scan or {}
    scan.setdefault("provider", provider)
    scan.setdefault("bucket", target)
    scan.setdefault("region", scan.get("region") or scan.get("region_name") or "-")
    scan.setdefault("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _ensure_recommendations(scan, provider)
    return scan


def _top_findings(scan: Dict[str, Any], limit: int = 12) -> list[str]:
    files = scan.get("files") or scan.get("vulnerable_files") or []
    if not isinstance(files, list):
        return []
    order = {"CRITICAL": 0, "Critical": 0, "HIGH": 1, "High": 1, "MEDIUM": 2, "Medium": 2, "LOW": 3, "Low": 3}

    def key_fn(f: Dict[str, Any]) -> Tuple[int, int]:
        sev = f.get("severity", "LOW")
        size = f.get("size", 0) or 0
        try:
            size_i = int(size)
        except Exception:
            size_i = 0
        return (order.get(str(sev), 9), -size_i)

    files_sorted = sorted(files, key=key_fn)[:limit]
    out: list[str] = []
    for f in files_sorted:
        key = f.get("key") or f.get("path") or f.get("name") or "-"
        sev = f.get("severity", "-")
        size = _format_bytes(f.get("size", 0))
        out.append(f"{sev}: {key} ({size})")
    return out


def _make_pdf(scan: Dict[str, Any], title: str, client_name: Optional[str]) -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    bucket = _safe_filename(scan.get("bucket", "target"))
    filename = f"relatorio_{bucket}_{ts}.pdf"
    path = REPORTS_DIR / filename

    c = rl_canvas.Canvas(str(path), pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 60, title)

    c.setFont("Helvetica", 11)
    c.drawString(40, height - 82, f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    if client_name:
        c.drawString(40, height - 100, f"Cliente: {client_name}")

    provider = scan.get("provider", "-")
    target = scan.get("bucket", "-")
    region = scan.get("region", "-")
    c.drawString(40, height - 122, f"Provider: {provider} | Alvo: {target} | Região: {region}")

    y = height - 160
    c.setFont("Helvetica-Bold", 13)
    c.drawString(40, y, "Resumo")
    y -= 18

    summary = scan.get("summary") or {}
    objects_scanned = summary.get("objects_scanned", summary.get("total_files", scan.get("total_files", 0)))
    total_size = summary.get("total_size_bytes", summary.get("total_size", scan.get("total_size_bytes", 0)))
    public_access = scan.get("public_access", scan.get("is_public", False))
    risk_score = scan.get("risk_score", scan.get("risk_total", scan.get("risk", "-")))

    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"- Objetos analisados: {objects_scanned}")
    y -= 16
    c.drawString(40, y, f"- Tamanho total analisado: {_format_bytes(total_size)}")
    y -= 16
    c.drawString(40, y, f"- Exposição: {'Público' if public_access else 'Privado'}")
    y -= 16
    c.drawString(40, y, f"- Risco (consolidado): {risk_score}")
    y -= 22

    c.setFont("Helvetica-Bold", 13)
    c.drawString(40, y, "Achados (amostra)")
    y -= 18
    c.setFont("Helvetica", 10)

    for line in _top_findings(scan, limit=14):
        if y < 80:
            c.showPage()
            y = height - 60
            c.setFont("Helvetica", 10)
        c.drawString(45, y, f"• {line[:145]}")
        y -= 14

    recs = scan.get("recommendations") or []
    if isinstance(recs, list) and recs:
        y -= 8
        c.setFont("Helvetica-Bold", 13)
        c.drawString(40, y, "Recomendações (top)")
        y -= 18
        c.setFont("Helvetica", 10)
        for rec in recs[:10]:
            if y < 80:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)
            c.drawString(45, y, f"• {str(rec)[:145]}")
            y -= 14

    c.showPage()
    c.save()
    return path


def _make_docx(scan: Dict[str, Any], title: str, client_name: Optional[str]) -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    bucket = _safe_filename(scan.get("bucket", "target"))
    filename = f"relatorio_{bucket}_{ts}.docx"
    path = REPORTS_DIR / filename

    doc = Document()
    doc.add_heading(title, level=0)
    doc.add_paragraph(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    if client_name:
        doc.add_paragraph(f"Cliente: {client_name}")

    provider = scan.get("provider", "-")
    target = scan.get("bucket", "-")
    region = scan.get("region", "-")
    doc.add_paragraph(f"Provider: {provider} | Alvo: {target} | Região: {region}")

    doc.add_heading("Resumo", level=1)
    summary = scan.get("summary") or {}
    objects_scanned = summary.get("objects_scanned", summary.get("total_files", scan.get("total_files", 0)))
    total_size = summary.get("total_size_bytes", summary.get("total_size", scan.get("total_size_bytes", 0)))
    public_access = scan.get("public_access", scan.get("is_public", False))
    risk_score = scan.get("risk_score", scan.get("risk_total", scan.get("risk", "-")))

    doc.add_paragraph(f"Objetos analisados: {objects_scanned}")
    doc.add_paragraph(f"Tamanho total analisado: {_format_bytes(total_size)}")
    doc.add_paragraph(f"Exposição: {'Público' if public_access else 'Privado'}")
    doc.add_paragraph(f"Risco (consolidado): {risk_score}")

    doc.add_heading("Achados (amostra)", level=1)
    for line in _top_findings(scan, limit=20):
        doc.add_paragraph(line, style="List Bullet")

    recs = scan.get("recommendations") or []
    if isinstance(recs, list) and recs:
        doc.add_heading("Recomendações (top)", level=1)
        for rec in recs[:15]:
            doc.add_paragraph(str(rec), style="List Bullet")

    doc.save(str(path))
    return path


# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/login")




@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("30/minute")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/mfa/setup", response_class=HTMLResponse, include_in_schema=False)
def mfa_setup_page(request: Request):
    return templates.TemplateResponse("mfa_setup.html", {"request": request})


@app.get("/change-password", response_class=HTMLResponse, include_in_schema=False)
def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})


@app.get("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@app.get("/reset-password", response_class=HTMLResponse, include_in_schema=False)
def reset_password_page(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page(request: Request):
    # Proteção real é via /api/dashboard (com Authorization)
    return templates.TemplateResponse("dashboard.html", {"request": request})


# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# -----------------------------------------------------------------------------
# Auth/MFA API
# -----------------------------------------------------------------------------
@app.post("/auth/register")
def auth_register(data: UserRegisterIn):
    if not _is_email_domain_allowed(str(data.email)):
        raise HTTPException(status_code=403, detail="Este email não está autorizado a criar uma conta.")
    register_user(email=data.email, password=data.password, full_name=data.full_name)
    # ✅ CORRIGIDO: setup_mfa agora só precisa do email
    mfa = setup_mfa(email=data.email)
    return {
        "registered": True,
        "mfa_setup_required": True,
        "qr_code": mfa["qr_code"],
        "backup_codes": mfa.get("backup_codes", []),
        "email": data.email,
    }


@app.post("/auth/login")
def auth_login(request: Request, data: UserLoginIn, response: Response):
    _check_login_rate(get_client_ip(request))
    try:
        result = login_user(email=data.email, password=data.password, mfa_code=data.mfa_code, response=response)
    except HTTPException as e:
        put_metric("AuthFailure", 1, dimensions={"Reason": str(e.status_code)})
        raise
    if result.get("authenticated"):
        put_metric("AuthSuccess", 1)
    return result


@app.post("/auth/change-password")
def auth_change_password(data: ChangePasswordIn, user=Depends(require_mfa)):
    return change_password(
        email=user["email"],
        current_password=data.current_password,
        code=data.mfa_code,
        new_password=data.new_password,
    )


@app.post("/auth/forgot-password")
def auth_forgot_password(data: ForgotPasswordIn):
    # Resposta sempre idêntica, exista ou não a conta — evita que a rota vire
    # uma ferramenta de descobrir quais emails têm cadastro
    request_password_reset(email=str(data.email))
    return {"message": "Se este email estiver cadastrado, enviamos um link de redefinição de senha."}


@app.post("/auth/reset-password")
def auth_reset_password(data: ResetPasswordIn):
    return reset_password(token=data.token, new_password=data.new_password)


@app.get("/auth/mfa/status")
def auth_mfa_status(email: EmailStr):
    user = USERS_DB.get(str(email))
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {
        "email": user.get("email"),
        "mfa_enabled": bool(user.get("mfa_enabled")),
        "has_secret": bool(user.get("mfa_secret")),
    }


@app.post("/auth/mfa/verify")
def auth_mfa_verify(data: MFAVerifyIn):
    return verify_and_activate_mfa(email=data.email, code=data.code)


@app.post("/auth/logout")
def auth_logout(user=Depends(get_current_user)):
    email = user.get("email")
    removed = logout_all_sessions(email)
    return {"ok": True, "removed_sessions": removed}


# -----------------------------------------------------------------------------
# API protegida (MFA obrigatório)
# -----------------------------------------------------------------------------
@app.get("/api/dashboard")
def dashboard_api(user=Depends(require_mfa)):
    return {"ok": True, "user": user}


# -----------------------------------------------------------------------------
# Status de job assíncrono
# -----------------------------------------------------------------------------
@app.get("/scan/job/{job_id}")
def scan_job_status(job_id: str, user=Depends(require_mfa)):
    """Consulta o status de um scan assíncrono iniciado com ?async=true."""
    job = _job_read(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado.")
    if job.get("status") != "done":
        return {k: v for k, v in job.items() if k != "result"}
    return job


# -----------------------------------------------------------------------------
# Scan público (compatível com dashboard)
# -----------------------------------------------------------------------------
@app.get("/scan/{target:path}")
def scan_public_compat(target: str, max_objects: int = 10000, user=Depends(require_mfa)):
    payload = PublicScanIn(target=target, max_objects=max_objects)
    return scan_public(payload, user)


def _exec_public_scan(payload: PublicScanIn, user) -> Dict[str, Any]:
    """Lógica central do scan público — reutilizada pelo modo síncrono e async."""
    provider = _detect_provider(payload.target)

    if provider == 'AWS_S3':
        try:
            from auditor import S3Auditor  # type: ignore
            aws_aud = S3Auditor(payload.target, max_objects=payload.max_objects)
            result = aws_aud.run()
            return _normalize_scan_result(result, provider=provider, target=payload.target)
        except Exception:
            pass

    Universal = _load_universal_auditor()
    if not Universal:
        raise HTTPException(
            status_code=501,
            detail="auditor_universal.py não encontrado (scan público multicloud indisponível neste ambiente).",
        )

    auditor = None
    for ctor_kwargs in (
        {"target": payload.target, "max_objects": payload.max_objects, "region": "global"},
        {"target": payload.target, "max_objects": payload.max_objects},
        {"domain": payload.target, "max_objects": payload.max_objects},
        {"domain": payload.target},
    ):
        try:
            auditor = Universal(**ctor_kwargs)  # type: ignore
            break
        except TypeError:
            continue

    if auditor is None:
        try:
            auditor = Universal(payload.target, payload.max_objects)  # type: ignore
        except Exception:
            auditor = Universal(payload.target)  # type: ignore

    result = auditor.run() if hasattr(auditor, "run") else auditor.scan()  # type: ignore
    return _normalize_scan_result(result, provider=provider, target=payload.target)


@app.post("/scan/public")
def scan_public(payload: PublicScanIn, user=Depends(require_mfa), async_mode: bool = Query(False, alias="async")):
    email = user.get("email") if isinstance(user, dict) else None

    if async_mode:
        job_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        _job_write(job_id, {"job_id": job_id, "type": "public", "status": "queued",
                            "started_at": started_at, "finished_at": None, "result": None, "error": None})
        def _do_public():
            return _attach_attack_paths(_exec_public_scan(payload, user))
        _EXECUTOR.submit(_run_in_background, job_id, "public", started_at, email, _do_public, _request_id=get_request_id())
        return JSONResponse({"job_id": job_id, "status": "queued"})

    result = _attach_attack_paths(_exec_public_scan(payload, user))
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
        if HISTORY_AVAILABLE:
            try:
                save_scan(email, result.get("provider", "unknown").lower(), result)
            except Exception as _e:
                logger.warning(f"⚠️ save_scan error: {_e}")
    return result


# -----------------------------------------------------------------------------
# Scan autenticado (AWS S3)
# -----------------------------------------------------------------------------
@app.post("/scan/authenticated")
def scan_authenticated(payload: AuthenticatedScanIn, user=Depends(require_mfa), async_mode: bool = Query(False, alias="async")):
    provider = (payload.provider or "AWS_S3").upper()
    email = user.get("email") if isinstance(user, dict) else None

    if async_mode:
        job_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        _job_write(job_id, {"job_id": job_id, "type": provider.lower(), "status": "queued",
                            "started_at": started_at, "finished_at": None, "result": None, "error": None})
        def _do_authenticated():
            p = (payload.provider or "AWS_S3").upper()
            if p == "GCS":
                from auditor_gcs_authenticated import GCSAuthenticatedAuditor
                key = dict(payload.service_account_key or {})
                if "private_key" in key and isinstance(key["private_key"], str):
                    key["private_key"] = key["private_key"].replace("\\n", "\n")
                result = GCSAuthenticatedAuditor(bucket_name=payload.bucket, service_account_key=key, max_objects=payload.max_objects).run()
                return _attach_attack_paths(_normalize_scan_result(result, provider="GCS", target=payload.bucket))
            region_name = payload.region_name or payload.region
            result = S3AuthenticatedAuditor(
                bucket_name=payload.bucket,
                aws_access_key_id=payload.aws_access_key_id,
                aws_secret_access_key=payload.aws_secret_access_key,
                aws_session_token=payload.aws_session_token,
                region_name=region_name,
                max_objects=payload.max_objects,
            ).run()
            return _attach_attack_paths(_normalize_scan_result(result, provider="AWS_S3", target=payload.bucket))
        _EXECUTOR.submit(_run_in_background, job_id, provider.lower(), started_at, email, _do_authenticated, _request_id=get_request_id())
        return JSONResponse({"job_id": job_id, "status": "queued"})

    try:
        # GCS AUTENTICADO
        if provider == "GCS":
            from auditor_gcs_authenticated import GCSAuthenticatedAuditor
            if not payload.service_account_key:
                raise HTTPException(status_code=400, detail="Credencial GCS ausente (service_account_key JSON).")
            # Normaliza \n escapados no private_key (problema comum ao colar JSON no textarea)
            key = dict(payload.service_account_key)
            if "private_key" in key and isinstance(key["private_key"], str):
                key["private_key"] = key["private_key"].replace("\\n", "\n")
            auditor = GCSAuthenticatedAuditor(
                bucket_name=payload.bucket,
                service_account_key=key,
                max_objects=payload.max_objects,
            )
            result = auditor.run()
            result = _attach_attack_paths(_normalize_scan_result(result, provider="GCS", target=payload.bucket))

        # AWS S3 AUTENTICADO
        elif provider == "AWS_S3":
            region_name = payload.region_name or payload.region
            if not payload.aws_access_key_id or not payload.aws_secret_access_key:
                raise HTTPException(status_code=400, detail="Credenciais AWS ausentes (aws_access_key_id / aws_secret_access_key).")
            auditor = S3AuthenticatedAuditor(
                bucket_name=payload.bucket,
                aws_access_key_id=payload.aws_access_key_id,
                aws_secret_access_key=payload.aws_secret_access_key,
                aws_session_token=payload.aws_session_token,
                region_name=region_name,
                max_objects=payload.max_objects,
            )
            result = auditor.run()
            result = _attach_attack_paths(_normalize_scan_result(result, provider="AWS_S3", target=payload.bucket))

        else:
            raise HTTPException(status_code=400, detail=f"Provider '{provider}' não suportado.")

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Credencial inválida: {e}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro ao executar scan autenticado: {e}")

    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
        if HISTORY_AVAILABLE:
            try:
                save_scan(email, result.get("provider", "unknown").lower(), result)
            except Exception as _e:
                logger.warning(f"⚠️ save_scan error: {_e}")

    return result


# Compatibilidade com versões antigas do dashboard
@app.post("/scan/airdrop")
def scan_airdrop(payload: AuthenticatedScanIn, user=Depends(require_mfa)):
    return scan_authenticated(payload, user)


@app.post("/scan/amazetest")
def scan_amazetest(payload: AuthenticatedScanIn, user=Depends(require_mfa)):
    return scan_authenticated(payload, user)


# -----------------------------------------------------------------------------
# Scan IAM — CSPM (AWS Identity & Access Management)
# -----------------------------------------------------------------------------
class IamScanIn(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: Optional[str] = None
    region_name: str = "us-east-1"


def _attach_attack_paths(result: Dict[str, Any]) -> Dict[str, Any]:
    """Fase 2 do roadmap de Mapa de Grafo de Ataque — computa os caminhos
    em cima do grafo que o auditor já devolveu (Fase 0/1), sem o auditor
    precisar saber de path-finding. Aditivo: se não houver chave "graph"
    (auditor ainda não migrado) ou o cálculo falhar por qualquer motivo,
    o resultado original segue intacto — nunca derruba o scan por causa
    disso."""
    graph = result.get("graph")
    if not graph:
        return result
    try:
        from graph_engine import find_attack_paths, graph_summary
        result["attack_paths"] = find_attack_paths(graph)
        result["graph_summary"] = graph_summary(graph)
    except Exception as _e:
        logger.warning(f"⚠️ Cálculo de attack_paths falhou, seguindo sem ele: {_e}")
    return result


@app.post("/scan/iam")
def scan_iam(payload: IamScanIn, user=Depends(require_mfa), async_mode: bool = Query(False, alias="async")):
    """
    Audita a postura de segurança IAM da conta AWS (CSPM).
    Requer permissões: iam:Get*, iam:List*, sts:GetCallerIdentity.
    """
    email = user.get("email") if isinstance(user, dict) else None

    if async_mode:
        job_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        _job_write(job_id, {"job_id": job_id, "type": "aws_iam", "status": "queued",
                            "started_at": started_at, "finished_at": None, "result": None, "error": None})
        def _do_iam():
            from auditor_iam import IAMAuditor
            result = IAMAuditor(
                aws_access_key_id=payload.aws_access_key_id,
                aws_secret_access_key=payload.aws_secret_access_key,
                aws_session_token=payload.aws_session_token,
                region_name=payload.region_name or "us-east-1",
            ).run()
            return _attach_attack_paths(result)
        _EXECUTOR.submit(_run_in_background, job_id, "aws_iam", started_at, email, _do_iam, _request_id=get_request_id())
        return JSONResponse({"job_id": job_id, "status": "queued"})

    try:
        from auditor_iam import IAMAuditor
        auditor = IAMAuditor(
            aws_access_key_id=payload.aws_access_key_id,
            aws_secret_access_key=payload.aws_secret_access_key,
            aws_session_token=payload.aws_session_token,
            region_name=payload.region_name or "us-east-1",
        )
        result = auditor.run()
        result = _attach_attack_paths(result)
        if email:
            LAST_SCAN_BY_EMAIL[email] = result
            if HISTORY_AVAILABLE:
                try:
                    save_scan(email, "aws_iam", result)
                except Exception as _e:
                    logger.warning(f"⚠️ save_scan error: {_e}")
        return result
    except NoCredentialsError:
        raise HTTPException(status_code=400, detail="Credenciais AWS inválidas ou sem permissão IAM.")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro no scan IAM: {e}")


# -----------------------------------------------------------------------------
# Scan IAM — CSPM GCP (Google Cloud IAM)
# -----------------------------------------------------------------------------
class GcpIamScanIn(BaseModel):
    service_account_key: dict


@app.post("/scan/iam/gcp")
def scan_iam_gcp(payload: GcpIamScanIn, user=Depends(require_mfa), async_mode: bool = Query(False, alias="async")):
    """
    Audita postura de segurança IAM de um projeto GCP (CSPM).
    Requer permissões: roles/iam.securityReviewer ou roles/viewer no projeto.
    """
    email = user.get("email") if isinstance(user, dict) else None

    if async_mode:
        job_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        _job_write(job_id, {"job_id": job_id, "type": "gcp_iam", "status": "queued",
                            "started_at": started_at, "finished_at": None, "result": None, "error": None})
        def _do_gcp_iam():
            from auditor_iam_gcp import GCPIAMAuditor
            result = GCPIAMAuditor(service_account_key=payload.service_account_key).run()
            return _attach_attack_paths(result)
        _EXECUTOR.submit(_run_in_background, job_id, "gcp_iam", started_at, email, _do_gcp_iam, _request_id=get_request_id())
        return JSONResponse({"job_id": job_id, "status": "queued"})

    try:
        from auditor_iam_gcp import GCPIAMAuditor
        auditor = GCPIAMAuditor(service_account_key=payload.service_account_key)
        result = auditor.run()
        result = _attach_attack_paths(result)
        if email:
            LAST_SCAN_BY_EMAIL[email] = result
            if HISTORY_AVAILABLE:
                try:
                    save_scan(email, "gcp_iam", result)
                except Exception as _e:
                    logger.warning(f"⚠️ save_scan error: {_e}")
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro no scan IAM GCP: {e}")


# -----------------------------------------------------------------------------
# Scan IAM — CSPM Azure (Azure IAM / Entra ID)
# -----------------------------------------------------------------------------
class AzureIamScanIn(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str


@app.post("/scan/iam/azure")
def scan_iam_azure(payload: AzureIamScanIn, user=Depends(require_mfa), async_mode: bool = Query(False, alias="async")):
    """
    Audita postura de segurança IAM da subscription Azure + Entra ID (CSPM).
    Requer permissões: Reader na subscription + Microsoft Graph: Policy.Read.All, RoleManagement.Read.All.
    """
    email = user.get("email") if isinstance(user, dict) else None

    if async_mode:
        job_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        _job_write(job_id, {"job_id": job_id, "type": "azure_iam", "status": "queued",
                            "started_at": started_at, "finished_at": None, "result": None, "error": None})
        def _do_azure_iam():
            from auditor_iam_azure import AzureIAMAuditor
            result = AzureIAMAuditor(
                tenant_id=payload.tenant_id,
                client_id=payload.client_id,
                client_secret=payload.client_secret,
                subscription_id=payload.subscription_id,
            ).run()
            return _attach_attack_paths(result)
        _EXECUTOR.submit(_run_in_background, job_id, "azure_iam", started_at, email, _do_azure_iam, _request_id=get_request_id())
        return JSONResponse({"job_id": job_id, "status": "queued"})

    try:
        from auditor_iam_azure import AzureIAMAuditor
        auditor = AzureIAMAuditor(
            tenant_id=payload.tenant_id,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            subscription_id=payload.subscription_id,
        )
        result = auditor.run()
        result = _attach_attack_paths(result)
        if email:
            LAST_SCAN_BY_EMAIL[email] = result
            if HISTORY_AVAILABLE:
                try:
                    save_scan(email, "azure_iam", result)
                except Exception as _e:
                    logger.warning(f"⚠️ save_scan error: {_e}")
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro no scan IAM Azure: {e}")


# -----------------------------------------------------------------------------
# Scan Kubernetes (kubeconfig YAML)
# -----------------------------------------------------------------------------
class K8sScanIn(BaseModel):
    kubeconfig: str = Field(..., description="Conteúdo do arquivo ~/.kube/config em YAML")
    max_objects: int = 10000


def _run_full_k8s_scan(kubeconfig_yaml: str, max_objects: int) -> dict:
    """
    Roda o scan de storage (K8sStorageAuditor: PVs, PVCs, Secrets, ConfigMaps,
    StorageClasses, hostPath) e o scan de RBAC/rede/workload (K8sAuthenticatedAuditor:
    ClusterRoles, ClusterRoleBindings, Services expostos, NetworkPolicy ausente,
    containers privilegiados) contra o mesmo kubeconfig e mescla tudo num único
    relatório. Se o auditor de RBAC falhar (ex.: ServiceAccount sem permissão), o
    scan de storage continua valendo — o erro só é anexado a 'errors'.
    """
    from auditor_k8s import K8sStorageAuditor
    from auditor_k8s_authenticated import K8sAuthenticatedAuditor

    result = K8sStorageAuditor(kubeconfig_yaml=kubeconfig_yaml, max_objects=max_objects).run()

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write(kubeconfig_yaml)
            tmp_path = tmp.name
        os.chmod(tmp_path, 0o600)

        rbac_result = K8sAuthenticatedAuditor(
            kubeconfig_path=tmp_path, max_resources=max_objects,
        ).run()

        result["files"] = list(result.get("files", [])) + list(rbac_result.get("files", []))
        result["cluster_version"] = rbac_result.get("cluster", "-")
        result["platform"] = rbac_result.get("platform", "-")
        result["namespace_filter"] = rbac_result.get("namespace_filter", "-")
        result["recommendations"] = sorted(
            set(result.get("recommendations", [])) | set(rbac_result.get("recommendations", []))
        )
        result["errors"] = list(result.get("errors", [])) + list(rbac_result.get("errors", []))
        # K8sStorageAuditor não produz grafo (não lê RBAC) -- só o
        # K8sAuthenticatedAuditor (Fase 4 do roadmap) tem essa chave.
        if "graph" in rbac_result:
            result["graph"] = rbac_result["graph"]
    except Exception as e:
        result.setdefault("errors", []).append(
            f"Scan de RBAC/rede/workload não pôde ser executado: {e}. Verifique se o "
            "kubeconfig tem permissão de leitura em ClusterRoles, ClusterRoleBindings, "
            "Services e NetworkPolicies — veja o manifesto de exemplo no formulário de scan."
        )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # severity_distribution/risk_score recalculados sobre a lista mesclada — não dá para
    # só somar os dois dicts porque K8sAuthenticatedAuditor usa chaves maiúsculas
    # (CRITICAL/HIGH/...) e o dashboard espera chaves minúsculas.
    files = result.get("files", [])
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in files:
        sev = str(f.get("severity", "LOW")).lower()
        dist[sev if sev in dist else "low"] += 1
    result["severity_distribution"] = dist

    total = len(files)
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_score = total * 4 if total else 1
    raw = sum(dist[k] * weights[k] for k in dist)
    result["risk_score"] = min(100, int((raw / max_score) * 100)) if total else 0

    return _attach_attack_paths(result)


@app.post("/scan/k8s")
def scan_k8s(payload: K8sScanIn, user=Depends(require_mfa), async_mode: bool = Query(False, alias="async")):
    """
    Audita um cluster Kubernetes via kubeconfig YAML: storage (PVs, PVCs, Secrets,
    ConfigMaps, StorageClasses, hostPath) + RBAC, exposição de rede e segurança de
    workload (ver _run_full_k8s_scan).
    """
    email = user.get("email") if isinstance(user, dict) else None

    if async_mode:
        job_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        _job_write(job_id, {"job_id": job_id, "type": "k8s", "status": "queued",
                            "started_at": started_at, "finished_at": None, "result": None, "error": None})
        def _do_k8s():
            return _run_full_k8s_scan(payload.kubeconfig, payload.max_objects)
        _EXECUTOR.submit(_run_in_background, job_id, "k8s", started_at, email, _do_k8s, _request_id=get_request_id())
        return JSONResponse({"job_id": job_id, "status": "queued"})

    try:
        result = _run_full_k8s_scan(payload.kubeconfig, payload.max_objects)
        if email:
            LAST_SCAN_BY_EMAIL[email] = result
            if HISTORY_AVAILABLE:
                try:
                    save_scan(email, "k8s", result)
                except Exception as _e:
                    logger.warning(f"⚠️ save_scan error: {_e}")
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro no scan Kubernetes: {e}")


# -----------------------------------------------------------------------------
# Histórico de scans
# -----------------------------------------------------------------------------

@app.get("/scan/history")
def scan_history_endpoint(
    provider: Optional[str] = None,
    limit: int = 20,
    user=Depends(require_mfa),
):
    """Lista os últimos scans do usuário logado. Filtre por provider opcional."""
    if not HISTORY_AVAILABLE:
        raise HTTPException(status_code=503, detail="Histórico de scans indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    if not email:
        raise HTTPException(status_code=401, detail="Usuário não identificado.")
    scans = list_scans(email, provider=provider, limit=limit)
    return {"email": email, "total": len(scans), "scans": scans}


# -----------------------------------------------------------------------------
# IA — Análise com Claude
# -----------------------------------------------------------------------------

class AiAskIn(BaseModel):
    question: str = Field(..., max_length=2000)
    use_history: bool = True
    provider: Optional[str] = None


@app.post("/ai/analyze")
@limiter.limit("20/minute")
def ai_analyze(request: Request, user=Depends(require_mfa)):
    """Análise executiva do último scan com Claude."""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ai_analyzer indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    scan  = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if not scan:
        raise HTTPException(status_code=404, detail="Nenhum scan encontrado. Realize um scan primeiro.")
    try:
        with timed_metric("AiAnalysisDuration", dimensions={"Operation": "analyze"}):
            analysis = ai_analyzer.analyze(scan)
        return {"analysis": analysis}
    except ai_analyzer.AiRefusalError:
        put_metric("AiRefusal", 1, dimensions={"Operation": "analyze"})
        return {"analysis": "O Claude recusou processar esta solicitação por motivos de segurança. Tente novamente mais tarde."}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"❌ Erro ai_analyze: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro na análise: {e}")


@app.post("/ai/compare")
@limiter.limit("20/minute")
def ai_compare(request: Request, user=Depends(require_mfa), provider: Optional[str] = None):
    """Compara o scan atual com o histórico e retorna análise de evolução."""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ai_analyzer indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    scan  = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if not scan:
        raise HTTPException(status_code=404, detail="Nenhum scan encontrado. Realize um scan primeiro.")
    history = []
    if HISTORY_AVAILABLE and email:
        try:
            history = load_recent(email, provider=provider, n=3)
        except Exception as _e:
            logger.warning(f"⚠️ load_recent error: {_e}")
    try:
        with timed_metric("AiAnalysisDuration", dimensions={"Operation": "compare"}):
            comparison = ai_analyzer.compare(scan, history)
        return {"comparison": comparison, "history_scans_used": len(history)}
    except ai_analyzer.AiRefusalError:
        put_metric("AiRefusal", 1, dimensions={"Operation": "compare"})
        return {"comparison": "O Claude recusou processar esta solicitação por motivos de segurança. Tente novamente mais tarde.", "history_scans_used": len(history)}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"❌ Erro ai_compare: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro na comparação: {e}")


@app.post("/ai/ask")
@limiter.limit("10/minute")
def ai_ask(request: Request, body: dict = Body(...), user=Depends(require_mfa)):
    """Responde uma pergunta livre sobre o scan atual e/ou histórico.

    O body chega como `dict` cru (em vez de `body: AiAskIn` direto na
    assinatura) porque, sob `@limiter.limit`, o FastAPI resolve anotações de
    tipo usando os `__globals__` do wrapper do slowapi — que não conhece
    `AiAskIn`, definida só neste módulo — e o parâmetro acaba sendo tratado
    como query param em vez de body. `dict` é builtin e sempre resolve;
    validamos contra `AiAskIn` manualmente logo abaixo."""
    try:
        parsed = AiAskIn.model_validate(body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ai_analyzer indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    scan  = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if not scan:
        raise HTTPException(status_code=404, detail="Nenhum scan encontrado. Realize um scan primeiro.")
    history = []
    if parsed.use_history and HISTORY_AVAILABLE and email:
        try:
            history = load_recent(email, provider=parsed.provider, n=3)
        except Exception as _e:
            logger.warning(f"⚠️ load_recent error: {_e}")
    try:
        with timed_metric("AiAnalysisDuration", dimensions={"Operation": "ask"}):
            answer = ai_analyzer.ask(parsed.question, scan, history, user_email=email)
        return {"answer": answer, "history_scans_used": len(history)}
    except ai_analyzer.AiRefusalError:
        put_metric("AiRefusal", 1, dimensions={"Operation": "ask"})
        return {"answer": "O Claude recusou processar esta solicitação por motivos de segurança. Tente reformular a pergunta.", "history_scans_used": len(history)}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"❌ Erro ai_ask: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro ao responder: {e}")


# -----------------------------------------------------------------------------
# Relatório Executivo (PDF + DOCX) no padrão do ambiente AWS
# -----------------------------------------------------------------------------
@app.post("/generate-report")
def generate_report(data: GenerateReportIn, user=Depends(require_mfa)):
    # Aceita scan_result ou scan_data (chave legacy do frontend)
    scan: Dict[str, Any] = data.scan_result or data.scan_data or {}
    email = user.get("email") if isinstance(user, dict) else None

    cached_scan = LAST_SCAN_BY_EMAIL.get(email) if email else None

    # Se o frontend mandou um scan resumido/compacto, prefira o scan completo em cache
    incoming_files = scan.get("files") if isinstance(scan, dict) else None
    incoming_has_files = isinstance(incoming_files, list) and len(incoming_files) > 0

    if cached_scan and (not scan or not incoming_has_files):
        logger.info("DEBUG /generate-report -> usando scan completo do cache")
        scan = cached_scan

    if not scan:
        raise HTTPException(status_code=400, detail="Nenhum scan disponível para gerar relatório. Execute um scan antes.")

    files_before = len(scan.get("files", [])) if isinstance(scan, dict) and isinstance(scan.get("files"), list) else 0
    logger.info(
        f"DEBUG /generate-report scan_keys={list(scan.keys()) if isinstance(scan, dict) else type(scan)} "
        f"files_before={files_before} "
        f"provider_before={scan.get('provider') if isinstance(scan, dict) else 'N/A'} "
        f"bucket_before={scan.get('bucket') if isinstance(scan, dict) else 'N/A'}"
    )

    # Normaliza pra evitar relatório vazio
    provider = scan.get("provider") or _detect_provider(str(scan.get("bucket", "")))
    target = str(scan.get("bucket") or scan.get("target") or "-")
    scan = _normalize_scan_result(scan, provider=provider, target=target)

    files_after = len(scan.get("files", [])) if isinstance(scan, dict) and isinstance(scan.get("files"), list) else 0
    logger.info(
        f"DEBUG /generate-report normalized files_after={files_after} "
        f"provider_after={scan.get('provider') if isinstance(scan, dict) else 'N/A'} "
        f"bucket_after={scan.get('bucket') if isinstance(scan, dict) else 'N/A'}"
    )

    # ── Usar gerador profissional com gráficos ────────────────────────
    if PROFESSIONAL_REPORT:
        try:
            client_info = {
                "name": data.client_name or "Cliente",
                "contact": email or "-",
            }
            results = _gen_executive_report(scan, client_info=client_info, output_format="both")
            pdf_file = Path(results.get("pdf", "")) if results.get("pdf") else None
            docx_file = Path(results.get("docx", "")) if results.get("docx") else None
            if pdf_file and pdf_file.exists() and pdf_file.name:
                _upload_report_s3(pdf_file)
            if docx_file and docx_file.exists() and docx_file.name:
                _upload_report_s3(docx_file)
            return {
                "success": True,
                "files": {
                    "pdf": f"reports_executive/{pdf_file.name}" if pdf_file and pdf_file.exists() and pdf_file.name else None,
                    "docx": f"reports_executive/{docx_file.name}" if docx_file and docx_file.exists() and docx_file.name else None,
                },
                "pdf_error": results.get("pdf_error"),
                "message": "Relatórios profissionais gerados com sucesso",
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Erro no gerador profissional: {e}")

    # ── Fallback simples ──────────────────────────────────────────────
    pdf_path = _make_pdf(scan, data.report_title, data.client_name)
    docx_path = _make_docx(scan, data.report_title, data.client_name)
    return {
        "success": True,
        "files": {
            "pdf": f"reports_executive/{pdf_path.name}",
            "docx": f"reports_executive/{docx_path.name}",
        },
        "message": "Relatórios gerados com sucesso",
    }

@app.get("/reports_executive/{filename}", include_in_schema=False)
def serve_report_file(filename: str):
    """Serve relatório do disco local ou baixa do S3 se não encontrado nesta instância."""
    safe = _safe_filename(filename)
    if not safe:
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido")
    path = REPORTS_DIR / safe
    if not path.exists():
        downloaded = _download_report_s3(safe)
        if downloaded:
            path = downloaded
    if not path.exists():
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    media_type = (
        "application/pdf"
        if safe.lower().endswith(".pdf")
        else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    return FileResponse(str(path), media_type=media_type)


# Rota opcional (quando quiser forçar download com filename)
@app.get("/download-report/{filename}")
def download_report(filename: str, user=Depends(require_mfa)):
    safe = _safe_filename(filename)
    if not safe:
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido")
    path = REPORTS_DIR / safe
    if not path.exists():
        path = _download_report_s3(safe) or path
    if not path.exists():
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    media = "application/pdf" if safe.lower().endswith(".pdf") else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return FileResponse(str(path), media_type=media, filename=safe)
# ==================================================
# EXECUÇÃO DIRETA DO SERVIDOR (quando rodar python)
# ==================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_with_mfa:app", host="0.0.0.0", port=8000, reload=False)

