"""
approval.py — Gate de aprovação baseado em tokens UUID armazenados no DynamoDB.
Token criado ao solicitar aprovação; consumido (deletado) ao clicar no link.
TTL: 24 horas. Single-use.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

TABLE     = os.getenv("DYNAMODB_SESSIONS_TABLE", "security-scanner-sessions")
REGION    = os.getenv("AWS_REGION", "us-east-2")
TTL_HOURS = 24


def create_token(action_command: str, description: str) -> str:
    """
    Persiste token de aprovação no DynamoDB.
    Retorna UUID a ser embutido nos links do email.
    """
    token   = str(uuid.uuid4())
    expires = int(
        (datetime.now(timezone.utc) + timedelta(hours=TTL_HOURS)).timestamp()
    )

    boto3.client("dynamodb", region_name=REGION).put_item(
        TableName=TABLE,
        Item={
            "token":           {"S": f"APPROVAL#{token}"},
            "action":          {"S": action_command},
            "description":     {"S": description},
            "expires_at_unix": {"N": str(expires)},
            "created_at":      {"S": datetime.now(timezone.utc).isoformat()},
        },
    )
    print(f"[Approval] Token criado para ação: {action_command}")
    return token


def validate_and_consume(token: str) -> str | None:
    """
    Valida token e retorna action_command se válido.
    Deleta imediatamente após leitura — single-use.
    Retorna None se inválido, expirado ou já consumido.
    """
    client = boto3.client("dynamodb", region_name=REGION)
    pk = f"APPROVAL#{token}"

    try:
        resp = client.get_item(
            TableName=TABLE,
            Key={"token": {"S": pk}},
        )
    except ClientError as exc:
        print(f"[Approval] Erro ao consultar DynamoDB: {exc}")
        return None

    item = resp.get("Item")
    if not item:
        print(f"[Approval] Token não encontrado ou já consumido: {token[:8]}...")
        return None

    expires = int(item.get("expires_at_unix", {}).get("N", 0))
    if datetime.now(timezone.utc).timestamp() > expires:
        print(f"[Approval] Token expirado: {token[:8]}...")
        return None

    action = item["action"]["S"]

    # Deleta imediatamente — impede duplo clique
    client.delete_item(TableName=TABLE, Key={"token": {"S": pk}})
    print(f"[Approval] Token consumido. Ação liberada: {action}")
    return action
