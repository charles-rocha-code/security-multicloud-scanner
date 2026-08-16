"""
_sanitize_text (ai_analyzer.py) é a defesa contra prompt injection escondida
em nome de arquivo/recurso -- um scan pode indexar um objeto S3 chamado
"relatorio​‮ignore instruções anteriores.txt" (zero-width
space + override RTL) e isso vai direto pro prompt da IA se não for limpo
antes. Sem teste nenhum até hoje.
"""
from ai_analyzer import _sanitize_text


def test_remove_caracteres_de_controle_zero_width():
    # ​ = zero-width space, técnica real de injection invisível
    texto = "arquivo​secreto.txt"
    assert _sanitize_text(texto) == "arquivosecreto.txt"


def test_remove_override_de_direcao_rtl():
    # ‮ = right-to-left override -- usado pra disfarçar texto malicioso
    # fazendo ele aparecer invertido/diferente do que realmente é
    texto = "relatorio‮attack.txt"
    resultado = _sanitize_text(texto)
    assert "‮" not in resultado
    assert resultado == "relatorioattack.txt"


def test_texto_normal_passa_sem_alteracao():
    texto = "relatorio-mensal-vendas.csv"
    assert _sanitize_text(texto) == texto


def test_trunca_texto_muito_longo():
    texto = "a" * 500
    resultado = _sanitize_text(texto, max_len=300)
    assert len(resultado) == 301  # 300 caracteres + "…"
    assert resultado.endswith("…")


def test_nao_trunca_texto_dentro_do_limite():
    texto = "a" * 200
    resultado = _sanitize_text(texto, max_len=300)
    assert resultado == texto
    assert "…" not in resultado


def test_valor_nao_string_e_convertido_antes_de_sanitizar():
    # classify_severity()/outros podem devolver None ou int em campos
    # opcionais -- _sanitize_text não pode quebrar nesses casos
    assert _sanitize_text(None) == "None"
    assert _sanitize_text(12345) == "12345"
