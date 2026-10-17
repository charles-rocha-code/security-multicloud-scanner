"""
scan_history.py — Persiste e recupera histórico de scans. STORAGE_BACKEND=aws
usa S3 (mesmo bucket que users_db/sessions_db, DB_S3_BUCKET); STORAGE_BACKEND=local
(padrão) usa local_data/scan_history/ -- sem depender de AWS.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from local_store import DATA_DIR, read_json, write_json

S3_BUCKET  = os.getenv("DB_BUCKET") or os.getenv("DB_S3_BUCKET", "security-scanner-db-442042548551")
REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-2")
PREFIX     = "scan-history/"
LOCAL_DIR  = DATA_DIR / PREFIX

# provider vira segmento de caminho (modo local) e de prefixo S3 (modo aws).
# Sem essa restrição, provider="../<outro_usuario>" saía da pasta do usuário
# autenticado e listava/carregava o histórico de outro tenant. Regex em vez de
# allowlist fixa: os valores vêm de vários auditores (aws_s3, azure_blob,
# universal, public...) e uma lista fechada quebraria a cada auditor novo.
# Aceita maiúsculas na borda (o dashboard manda "AWS_IAM"), normaliza pra minúscula.
PROVIDER_PATTERN = r"^[A-Za-z0-9_]{1,32}$"
_PROVIDER_RE     = re.compile(PROVIDER_PATTERN)


def _backend() -> str:
    return os.environ.get("STORAGE_BACKEND", "local")


def _s3():
    return boto3.client("s3", region_name=REGION)


def _email_safe(email: str) -> str:
    return email.replace("@", "_at_").replace(".", "_").lower()


def normalize_provider(provider: str) -> str:
    """Devolve o provider em minúsculas ou levanta ValueError se ele não for
    um identificador simples (ver PROVIDER_PATTERN)."""
    if not isinstance(provider, str) or not _PROVIDER_RE.fullmatch(provider):
        raise ValueError(f"provider inválido: {provider!r}")
    return provider.lower()


def _index_scan_for_rag(email: str, provider: str, ts: str, result: dict) -> None:
    """
    Indexa um resumo do scan na base de conhecimento (RAG) para retrieval
    semântico em ai_analyzer.ask() — além do histórico fixo de "últimos N"
    já usado ali. Nunca derruba o save_scan: falha aqui só é logada.
    """
    try:
        import rag
        sd = result.get("severity_distribution", {})
        summary_text = (
            f"Scan {provider} de {email} em {ts}\n"
            f"Alvo: {result.get('bucket') or result.get('target') or result.get('account_id', '?')}\n"
            f"Severidade: CRÍTICO={sd.get('critical', 0)} ALTO={sd.get('high', 0)} "
            f"MÉDIO={sd.get('medium', 0)} BAIXO={sd.get('low', 0)}\n"
            f"Risk score: {result.get('risk_score', 0)}/100\n"
            f"Total de findings: {len(result.get('files', []))}"
        )
        rag.index_chunk(text=summary_text, source=f"{email}:{provider}:{ts}", category="scan", owner=email)
    except Exception as e:
        print(f"⚠️  scan_history._index_scan_for_rag error: {e}")


def save_scan(email: str, provider: str, result: dict) -> str:
    """Salva resultado de scan (S3 em modo aws, local_data/ em modo local).
    Retorna a chave gerada (mesmo formato relativo nos dois backends)."""
    if not email:
        return ""

    # Scan que já terminou não deve ser perdido por causa do rótulo: provider
    # fora do formato vai pra "unknown" em vez de virar caminho.
    try:
        provider_dir = normalize_provider(provider)
    except ValueError:
        provider_dir = "unknown"

    ts  = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    key = f"{PREFIX}{_email_safe(email)}/{provider_dir}/{ts}.json"

    payload = {
        "email":     email,
        "provider":  provider,
        "timestamp": ts,
        "result":    result,
    }

    if _backend() != "aws":
        write_json(DATA_DIR / key, payload)
        print(f"📦 Scan salvo (local): {key}")
        _index_scan_for_rag(email, provider, ts, result)
        return key

    if not S3_BUCKET:
        return ""
    try:
        _s3().put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(payload, indent=2, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        print(f"📦 Scan salvo: {key}")
        _index_scan_for_rag(email, provider, ts, result)
        return key
    except Exception as e:
        print(f"⚠️  scan_history.save_scan error: {e}")
        return ""


def list_scans(email: str, provider: Optional[str] = None, limit: int = 20) -> list[dict]:
    """Lista metadados dos últimos N scans de um usuário (mais recente primeiro)."""
    if not email:
        return []

    if provider:
        provider = normalize_provider(provider)

    if _backend() != "aws":
        user_dir = LOCAL_DIR / _email_safe(email)
        base = user_dir / provider if provider else user_dir
        # Defesa em profundidade: mesmo que a validação acima afrouxe um dia,
        # nunca listar nada fora da pasta do próprio usuário.
        if not base.resolve().is_relative_to(user_dir.resolve()):
            raise ValueError(f"provider inválido: {provider!r}")
        if not base.exists():
            return []
        files = sorted(base.rglob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
        out = []
        for f in files:
            parts = f.relative_to(LOCAL_DIR).parts
            out.append({
                "key":           f"{PREFIX}{'/'.join(parts)}",
                "provider":      parts[1] if len(parts) > 2 else "unknown",
                "timestamp":     (parts[2].replace(".json", "") if len(parts) > 2 else parts[-1].replace(".json", "")),
                "size_bytes":    f.stat().st_size,
                "last_modified": datetime.utcfromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return out

    if not S3_BUCKET:
        return []

    prefix = f"{PREFIX}{_email_safe(email)}/"
    if provider:
        prefix += f"{provider}/"

    try:
        resp = _s3().list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
        objects = sorted(
            resp.get("Contents", []),
            key=lambda x: x["LastModified"],
            reverse=True,
        )[:limit]

        out = []
        for obj in objects:
            parts = obj["Key"].replace(PREFIX, "").split("/")
            out.append({
                "key":           obj["Key"],
                "provider":      parts[1] if len(parts) > 2 else "unknown",
                "timestamp":     (parts[2].replace(".json", "") if len(parts) > 2 else ""),
                "size_bytes":    obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
            })
        return out
    except Exception as e:
        print(f"⚠️  scan_history.list_scans error: {e}")
        return []


def load_scan(key: str) -> dict:
    """Carrega um scan pela chave retornada por save_scan()/list_scans()."""
    if _backend() != "aws":
        return read_json(DATA_DIR / key, {})
    resp = _s3().get_object(Bucket=S3_BUCKET, Key=key)
    return json.loads(resp["Body"].read().decode("utf-8"))


def load_recent(email: str, provider: Optional[str] = None, n: int = 3) -> list[dict]:
    """Carrega os N scans mais recentes de um usuário."""
    metas  = list_scans(email, provider, limit=n)
    result = []
    for meta in metas:
        try:
            result.append(load_scan(meta["key"]))
        except Exception as e:
            print(f"⚠️  scan_history.load_recent error: {e}")
    return result
