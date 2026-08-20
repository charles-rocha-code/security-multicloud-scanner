"""
rag.py — Base de conhecimento (RAG) compartilhada. Mesma lógica usada pelos
agentes autônomos do Lambda watchdog (repo Terraform-Multicloud_scanner,
lambda/watchdog/agents/tools/rag.py) — duplicado aqui porque os dois
runtimes (EC2 e Lambda) não compartilham pacote Python entre repositórios.

Embeddings via Bedrock Titan (amazon.titan-embed-text-v2:0). Similaridade
calculada em memória (cosine) — sem OpenSearch Serverless, cujo piso de custo
é desproporcional ao volume deste projeto (dezenas a centenas de chunks).

Em STORAGE_BACKEND=local (padrão sem AWS) o RAG fica desativado de forma
graciosa: retrieve() volta [] e index_chunk() é no-op -- sem Bedrock não há
como gerar embedding de qualidade real, e um embedding local aproximado não
valeria o código extra. /ai/ask continua funcionando com o histórico de scans
como contexto, só perde a busca semântica.
"""
from __future__ import annotations

import json
import math
import os
import time
import uuid

import boto3

BEDROCK_REGION = "us-east-1"
EMBED_MODEL    = "amazon.titan-embed-text-v2:0"
# RAG_KNOWLEDGE_TABLE permite apontar para a tabela -dev isolada em testes
# locais (mesmo padrão de USERS_DYNAMO_TABLE/SESSIONS_DYNAMO_TABLE) — sem
# isso, qualquer teste local escreve na base de conhecimento de produção.
TABLE          = os.getenv("RAG_KNOWLEDGE_TABLE", "security-scanner-knowledge")
DYNAMO_REGION  = "us-east-2"


def _backend() -> str:
    return os.environ.get("STORAGE_BACKEND", "local")


def embed_text(text: str) -> list[float]:
    """Gera o embedding de um texto via Bedrock Titan."""
    client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    resp = client.invoke_model(
        modelId=EMBED_MODEL,
        contentType="application/json",
        accept="application/json",
        body=json.dumps({"inputText": text}),
    )
    body = json.loads(resp["body"].read())
    return body["embedding"]


def index_chunk(text: str, source: str, category: str = "", owner: str = "") -> str:
    """Gera embedding e grava um chunk na base de conhecimento. Retorna o chunk_id.

    `owner` (normalmente o e-mail do usuário dono do dado) permite que
    `retrieve()` restrinja a busca semântica ao próprio tenant — sem isso,
    qualquer chunk indexado é visível para qualquer busca."""
    if _backend() != "aws":
        return str(uuid.uuid4())
    embedding = embed_text(text)
    chunk_id  = str(uuid.uuid4())
    table = boto3.resource("dynamodb", region_name=DYNAMO_REGION).Table(TABLE)
    table.put_item(Item={
        "chunk_id":   chunk_id,
        "text":       text,
        "embedding":  json.dumps(embedding),
        "source":     source,
        "category":   category,
        "owner":      owner,
        "created_at": int(time.time()),
    })
    return chunk_id


def _cosine(a: list[float], b: list[float]) -> float:
    dot    = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def retrieve(query: str, k: int = 3, category: str | None = None, owner: str | None = None) -> list[dict]:
    """
    Retorna os k chunks mais similares à query, por similaridade de cosseno.
    `category` filtra por tipo de chunk (ex: "changelog", "scan") quando a
    tabela mistura conteúdo de fontes diferentes.
    `owner`, quando informado, restringe a busca aos chunks daquele dono —
    sem isso, a busca semântica cruza dados de todos os tenants da tabela.
    Chunks indexados antes desse campo existir (sem `owner`) ficam de fora
    de buscas filtradas: comportamento seguro por padrão.
    """
    if _backend() != "aws":
        return []
    query_embedding = embed_text(query)
    table = boto3.resource("dynamodb", region_name=DYNAMO_REGION).Table(TABLE)

    items = []
    resp = table.scan()
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        items.extend(resp.get("Items", []))

    if category is not None:
        items = [item for item in items if item.get("category") == category]
    if owner is not None:
        items = [item for item in items if item.get("owner") == owner]

    scored = []
    for item in items:
        embedding = json.loads(item["embedding"])
        score = _cosine(query_embedding, embedding)
        scored.append((score, item))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [
        {
            "text":     item["text"],
            "source":   item["source"],
            "category": item.get("category", ""),
            "score":    round(score, 4),
        }
        for score, item in scored[:k]
    ]
