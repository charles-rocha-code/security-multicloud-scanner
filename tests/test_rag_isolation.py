"""
rag.py::retrieve() é o isolamento multi-tenant do RAG -- o comentário no
próprio código diz "sem isso, a busca semântica cruza dados de todos os
tenants da tabela". Esse é o teste de segurança de maior risco do lote
inteiro, e não tinha nenhuma cobertura, manual ou automatizada, até hoje.

embed_text() fala com o Bedrock de verdade -- não dá pra (nem faz sentido)
mockar isso com moto. A solução: monkeypatch embed_text pra devolver um
vetor fixo (não estamos testando qualidade de embedding aqui, só que o
filtro por owner funciona), e moto só pra mockar a tabela DynamoDB.
"""
import boto3
import pytest
from moto import mock_aws

import rag

TEST_TABLE = "test-security-scanner-knowledge"


@pytest.fixture
def dynamo_table(monkeypatch):
    monkeypatch.setattr(rag, "TABLE", TEST_TABLE)
    monkeypatch.setattr(rag, "embed_text", lambda text: [1.0, 0.0, 0.0])

    with mock_aws():
        client = boto3.client("dynamodb", region_name=rag.DYNAMO_REGION)
        client.create_table(
            TableName=TEST_TABLE,
            KeySchema=[{"AttributeName": "chunk_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "chunk_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield


def test_retrieve_nao_cruza_dados_entre_tenants(dynamo_table):
    rag.index_chunk("dado sigiloso do cliente A", source="scan-a", owner="clienteA@example.com")
    rag.index_chunk("dado sigiloso do cliente B", source="scan-b", owner="clienteB@example.com")

    resultado = rag.retrieve("qualquer busca", k=10, owner="clienteA@example.com")

    fontes = {item["source"] for item in resultado}
    assert fontes == {"scan-a"}
    assert "scan-b" not in fontes


def test_chunk_sem_owner_fica_fora_de_busca_filtrada(dynamo_table):
    # Comportamento documentado como seguro por padrão: chunk indexado
    # antes do campo owner existir não vaza pra uma busca com owner
    rag.index_chunk("dado legado sem dono definido", source="scan-legado", owner="")

    resultado = rag.retrieve("qualquer busca", k=10, owner="clienteA@example.com")

    assert resultado == []


def test_sem_filtro_de_owner_busca_ve_tudo(dynamo_table):
    # Confirma que o filtro é opt-in -- não quebra o uso interno onde ver
    # tudo é intencional (ex: agentes do watchdog enriquecendo alertas)
    rag.index_chunk("dado do cliente A", source="scan-a", owner="clienteA@example.com")
    rag.index_chunk("dado do cliente B", source="scan-b", owner="clienteB@example.com")

    resultado = rag.retrieve("qualquer busca", k=10)  # sem owner=

    fontes = {item["source"] for item in resultado}
    assert fontes == {"scan-a", "scan-b"}


def test_retrieve_respeita_k(dynamo_table):
    for i in range(5):
        rag.index_chunk(f"chunk numero {i}", source=f"s{i}", owner="clienteA@example.com")

    resultado = rag.retrieve("busca", k=2, owner="clienteA@example.com")

    assert len(resultado) == 2
