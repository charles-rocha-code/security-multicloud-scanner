"""
test_graph_local.py — Valida localmente a Fase 0 do Mapa de Grafo de Ataque
(IAMAuditor emitindo nós/arestas, não só findings) ponta a ponta, pela
aplicação real via HTTP — não só a classe isolada.

Usa as credenciais AWS já configuradas no ambiente (AWS CLI local) e as
tabelas DynamoDB "-dev" (nunca produção). Cria um usuário de teste e remove
ao final.

Uso:
  export STORAGE_BACKEND=aws
  export USERS_DYNAMO_TABLE=security-scanner-users-dev
  export SESSIONS_DYNAMO_TABLE=security-scanner-sessions-dev
  export PASSWORD_RESETS_DYNAMO_TABLE=security-scanner-password-resets-dev
  export ALLOWED_REGISTRATION_DOMAINS=""
  python3 test_graph_local.py
"""
from __future__ import annotations

import os
import sys

import boto3
import pyotp
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

REQUIRED_DEV_TABLES = ("USERS_DYNAMO_TABLE", "SESSIONS_DYNAMO_TABLE")
for var in REQUIRED_DEV_TABLES:
    if "-dev" not in os.environ.get(var, ""):
        raise SystemExit(
            f"Abortando: {var} não aponta para uma tabela -dev "
            f"(valor atual: {os.environ.get(var, '<não definida>')!r}). "
            "Defina as variáveis -dev antes de rodar este script — "
            "ver docstring no topo do arquivo."
        )

from api_with_mfa import app  # noqa: E402
import auth_mfa  # noqa: E402

TEST_EMAIL = "teste-grafo-local@example.com"
TEST_PASSWORD = "SenhaForte!2026"


def main() -> None:
    client = TestClient(app)

    try:
        auth_mfa._tbl_users().delete_item(Key={"email": TEST_EMAIL})
    except Exception:
        pass

    auth_mfa.register_user(email=TEST_EMAIL, password=TEST_PASSWORD, full_name="Teste Grafo")
    mfa = auth_mfa.setup_mfa(email=TEST_EMAIL)
    totp = pyotp.TOTP(mfa["secret"])
    auth_mfa.verify_and_activate_mfa(email=TEST_EMAIL, code=totp.now())

    resp = client.post(
        "/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "mfa_code": totp.now()},
    )
    assert resp.status_code == 200, f"Login falhou: {resp.status_code} {resp.text}"
    cookie_header = resp.headers.get("set-cookie", "")
    cookie_value = cookie_header.split(";")[0] if cookie_header else None
    assert cookie_value, "Login não retornou cookie de sessão"

    creds = boto3.Session().get_credentials().get_frozen_credentials()
    resp2 = client.post(
        "/scan/iam",
        json={
            "aws_access_key_id": creds.access_key,
            "aws_secret_access_key": creds.secret_key,
            "aws_session_token": creds.token,
            "region_name": "us-east-2",
        },
        headers={"Cookie": cookie_value},
    )
    assert resp2.status_code == 200, f"Scan falhou: {resp2.status_code} {resp2.text}"
    result = resp2.json()

    assert "graph" in result, "Chave 'graph' não chegou na resposta HTTP — regressão!"
    assert "attack_paths" in result, "Chave 'attack_paths' não chegou na resposta HTTP — regressão (Fase 2)!"
    assert "graph_summary" in result, "Chave 'graph_summary' não chegou na resposta HTTP — regressão (Fase 2)!"
    print(f"OK — findings: {len(result['files'])}, "
          f"grafo: {len(result['graph']['nodes'])} nós / {len(result['graph']['edges'])} arestas, "
          f"attack_paths: {len(result['attack_paths'])}")

    auth_mfa._tbl_users().delete_item(Key={"email": TEST_EMAIL})
    print("Usuário de teste removido da tabela -dev.")


if __name__ == "__main__":
    main()
