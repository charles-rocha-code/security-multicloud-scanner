"""
verify_backup_code (auth_mfa.py) tem que ser de uso único -- cada backup
code funciona como uma "segunda senha" de MFA, então reuso é o tipo de bug
que "parece certo" num teste manual rápido e quebra silenciosamente numa
mudança futura (ex: alguém troca o `for` por comprehension e esquece de
remover o código usado da lista).
"""
from auth_mfa import (
    generate_backup_codes,
    hash_backup_codes,
    verify_backup_code,
)


def test_codigo_correto_autentica_e_e_removido_da_lista():
    codigos = generate_backup_codes(count=5)
    hashes = hash_backup_codes(codigos)

    ok, restantes = verify_backup_code(hashes, codigos[0])

    assert ok is True
    assert len(restantes) == 4


def test_reuso_do_mesmo_codigo_e_bloqueado():
    codigos = generate_backup_codes(count=5)
    hashes = hash_backup_codes(codigos)

    ok1, restantes = verify_backup_code(hashes, codigos[0])
    ok2, restantes2 = verify_backup_code(restantes, codigos[0])  # tenta de novo

    assert ok1 is True
    assert ok2 is False
    assert restantes2 == restantes  # lista não muda numa tentativa que falha


def test_codigo_invalido_nao_autentica():
    codigos = generate_backup_codes(count=5)
    hashes = hash_backup_codes(codigos)

    ok, restantes = verify_backup_code(hashes, "AAAAAAAA")

    assert ok is False
    assert restantes == hashes


def test_codigo_legado_em_texto_puro_continua_valido():
    # Compatibilidade retroativa: códigos gerados antes da migração pra
    # bcrypt (sem prefixo "$2") continuam funcionando até serem usados ou
    # regenerados -- não dá pra hashear retroativamente sem invalidar
    # código que o usuário já anotou.
    lista_mista = ["LEGADO01"] + hash_backup_codes(generate_backup_codes(count=3))

    ok, restantes = verify_backup_code(lista_mista, "LEGADO01")

    assert ok is True
    assert "LEGADO01" not in restantes
    assert len(restantes) == 3


def test_backup_codes_persistem_como_hash_nao_texto_puro():
    codigos = generate_backup_codes(count=3)
    hashes = hash_backup_codes(codigos)

    assert all(h.startswith("$2") for h in hashes)
    assert hashes != codigos
