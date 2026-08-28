"""
scan_content_for_secrets (engine_risk.py) é o que acha segredo escondido
dentro de um arquivo "sem cara de sensível" (.txt/.log sem extensão
CRITICAL). O limiar de entropia (4.0 bits/char) é um número mágico
ajustável -- merece teste dedicado pra não regredir silenciosamente (falso
negativo) numa "simplificação" futura da regex, nem virar barulho (falso
positivo) em texto comum.
"""
from engine_risk import scan_content_for_secrets, should_scan_content


def test_detecta_chave_aws_embutida_em_texto_comum():
    resultado = scan_content_for_secrets("notas do projeto\nchave: AKIAABCDEFGHIJKLMNOP\nfim")  # nosemgrep: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value -- chave falsa, fixture pra testar o próprio motor de detecção
    assert resultado is not None
    sev, _ = resultado
    assert sev == "CRITICAL"


def test_detecta_chave_privada():
    resultado = scan_content_for_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIExyz1234567890abcdef")
    assert resultado is not None
    sev, _ = resultado
    assert sev == "CRITICAL"


def test_detecta_jwt():
    resultado = scan_content_for_secrets(
        "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQrZ1234567890"
    )
    assert resultado is not None
    sev, _ = resultado
    assert sev == "HIGH"


def test_detecta_token_de_alta_entropia_sem_padrao_conhecido():
    resultado = scan_content_for_secrets("token=Xk9mZq2Lp8vN4wR7tY1sB6dF3hJ0cA5eG")
    assert resultado is not None
    sev, motivo = resultado
    assert sev == "HIGH"
    assert "entropia" in motivo.lower()


def test_texto_comum_nao_gera_falso_positivo():
    assert scan_content_for_secrets("reuniao marcada para terca as 15h, levar notebook") is None


def test_string_repetitiva_longa_nao_gera_falso_positivo():
    # 20+ caracteres, mas baixa entropia (padrão repetitivo) -- não deve
    # bater no limiar de 4.0 bits/char mesmo tendo o tamanho mínimo do regex
    assert scan_content_for_secrets("abababababababababababab") is None


def test_should_scan_content_pula_arquivo_ja_critical():
    # .env já é CRITICAL pela extensão -- não precisa baixar de novo
    assert should_scan_content("config.env", 100, "CRITICAL") is False


def test_should_scan_content_pula_arquivo_grande_demais():
    assert should_scan_content("log.txt", 60_000, "LOW") is False  # > 50KB


def test_should_scan_content_aceita_candidato_elegivel():
    assert should_scan_content("notas.txt", 100, "LOW") is True
