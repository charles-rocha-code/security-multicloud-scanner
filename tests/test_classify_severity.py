"""
classify_severity (engine_risk.py) é o "contrato do auditor" -- todos os
auditores (S3/GCS/Azure) dependem dele pra decidir severidade. A regra de
precedência (padrão de nome vence extensão quando o rank é maior) hoje só
existe como comentário no código -- este teste trava esse contrato.
"""
from engine_risk import classify_severity


def test_padrao_de_nome_vence_extensao_quando_mais_severo():
    # credentials.sql -> extensão .sql é HIGH, mas o padrão "credentials"
    # é CRITICAL -- o comentário do código documenta exatamente este caso
    sev, _ = classify_severity("backup_credentials.sql")
    assert sev == "CRITICAL"


def test_extensao_critical_isolada():
    sev, reason = classify_severity("chave_producao.pem")
    assert sev == "CRITICAL"
    assert "privada" in reason.lower() or "chave" in reason.lower()


def test_env_e_sempre_critical():
    sev, _ = classify_severity(".env")
    assert sev == "CRITICAL"


def test_arquivo_sem_padrao_sensivel_e_low():
    sev, reason = classify_severity("notas-da-reuniao.txt")
    assert sev == "LOW"
    assert reason == "Arquivo sem padrão sensível detectado"


def test_extensao_vence_quando_padrao_de_nome_e_menos_severo():
    # "internal-report.pem" -> extensão .pem é CRITICAL, padrão "internal"
    # é só MEDIUM -- o rank mais alto (extensão, aqui) deve vencer
    sev, _ = classify_severity("internal-report.pem")
    assert sev == "CRITICAL"


def test_case_insensitive():
    sev, _ = classify_severity("CHAVE.PEM")
    assert sev == "CRITICAL"
