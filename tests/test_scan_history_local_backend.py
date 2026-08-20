"""
save_scan()/list_scans()/load_recent() em STORAGE_BACKEND=local precisam
concordar sobre onde os arquivos ficam -- um teste manual (rodando a app de
verdade) pegou uma regressão real aqui: save_scan() gravava em
local_data/scan-history/ (via PREFIX), list_scans() procurava em
local_data/scan_history/ (LOCAL_DIR com underscore, hardcoded solto). Sem
esse teste, um scan salvo nunca aparecia no histórico nem alimentava o
contexto de /ai/ask (load_recent), silenciosamente.
"""
import pytest

import scan_history


@pytest.fixture
def local_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setattr(scan_history, "DATA_DIR", tmp_path)
    monkeypatch.setattr(scan_history, "LOCAL_DIR", tmp_path / scan_history.PREFIX)
    # Sem RAG/Bedrock disponível aqui -- _index_scan_for_rag já trata isso
    # sozinho (rag.retrieve/index_chunk viram no-op fora de STORAGE_BACKEND=aws).
    yield


def test_save_scan_aparece_em_list_scans(local_backend):
    key = scan_history.save_scan("user@example.com", "AWS_S3", {"risk_score": 42})
    assert key

    metas = scan_history.list_scans("user@example.com")

    assert len(metas) == 1
    assert metas[0]["key"] == key


def test_load_recent_carrega_o_conteudo_salvo(local_backend):
    scan_history.save_scan("user@example.com", "AWS_S3", {"risk_score": 7})

    recent = scan_history.load_recent("user@example.com", n=1)

    assert len(recent) == 1
    assert recent[0]["result"]["risk_score"] == 7


def test_list_scans_filtra_por_provider(local_backend):
    scan_history.save_scan("user@example.com", "AWS_S3", {"risk_score": 1})
    scan_history.save_scan("user@example.com", "GCS", {"risk_score": 2})

    metas = scan_history.list_scans("user@example.com", provider="gcs")

    assert len(metas) == 1
    assert metas[0]["provider"] == "gcs"


def test_list_scans_nao_cruza_usuarios(local_backend):
    scan_history.save_scan("user-a@example.com", "AWS_S3", {"risk_score": 1})
    scan_history.save_scan("user-b@example.com", "AWS_S3", {"risk_score": 2})

    metas = scan_history.list_scans("user-a@example.com")

    assert len(metas) == 1
