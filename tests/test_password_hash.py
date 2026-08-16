"""
verify_password (auth_mfa.py) autentica dois formatos ao mesmo tempo: bcrypt
(novo) e SHA256 sem sal (legado, de antes da migração). Código de
compatibilidade assim é o tipo de coisa que alguém remove sem querer numa
limpeza futura "porque ninguém lembra por que está ali" -- este teste é a
memória disso.
"""
import hashlib

from auth_mfa import hash_password, verify_password


def test_autentica_hash_bcrypt_novo():
    senha = "uma-senha-bem-forte-123456"
    hash_novo = hash_password(senha)

    assert hash_novo.startswith("$2")
    assert verify_password(senha, hash_novo) is True


def test_rejeita_senha_errada_contra_hash_bcrypt():
    hash_novo = hash_password("senha-correta-123456")
    assert verify_password("senha-errada-123456", hash_novo) is False


def test_autentica_hash_sha256_legado():
    # Formato de antes da migração pra bcrypt -- sem prefixo "$2"
    senha = "senha-de-conta-antiga-123456"
    hash_legado = hashlib.sha256(senha.encode()).hexdigest()

    assert verify_password(senha, hash_legado) is True


def test_rejeita_senha_errada_contra_hash_sha256_legado():
    hash_legado = hashlib.sha256("senha-certa-123456".encode()).hexdigest()
    assert verify_password("senha-errada-123456", hash_legado) is False


def test_hash_bcrypt_tem_custo_12():
    # bcrypt embute o custo no próprio hash ($2b$12$...) -- confirma que
    # ninguém baixou o custo de rounds sem querer numa mudança futura
    hash_novo = hash_password("qualquer-senha-123456")
    custo = hash_novo.split("$")[2]
    assert custo == "12"
