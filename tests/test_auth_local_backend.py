"""
STORAGE_BACKEND=local (padrão do projeto sem AWS) precisa sustentar o mesmo
fluxo de autenticação que hoje só tem cobertura implícita contra DynamoDB:
registro -> sessão -> logout, persistência sobrevivendo ao cache em memória,
e reset de senha logando o link em vez de tentar SES. Sem isso, uma
regressão no caminho local (ex: alguém volta a instanciar boto3 no import)
só apareceria rodando a app de verdade, não na suíte.
"""
import pytest

import auth_mfa

TEST_EMAIL = "local-backend-test@example.com"
TEST_PASSWORD = "SenhaForte!2026"


@pytest.fixture
def local_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setattr(auth_mfa, "SESSIONS_FILE", tmp_path / "sessions.json")
    monkeypatch.setattr(auth_mfa, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(auth_mfa, "PASSWORD_RESETS_FILE", tmp_path / "password_resets.json")
    monkeypatch.setattr(auth_mfa, "USERS_DB", {})
    yield


def test_registro_login_logout_sem_aws(local_backend):
    auth_mfa.register_user(email=TEST_EMAIL, password=TEST_PASSWORD, full_name="Teste Local")

    login = auth_mfa.login_user(email=TEST_EMAIL, password=TEST_PASSWORD)
    assert login["authenticated"] is True
    token = login["token"]

    session = auth_mfa._session_get(token)
    assert session is not None
    assert session["email"] == TEST_EMAIL

    auth_mfa.logout_user(token)
    assert auth_mfa._session_get(token) is None


def test_usuario_persiste_no_arquivo_local_nao_so_no_cache(local_backend):
    auth_mfa.register_user(email=TEST_EMAIL, password=TEST_PASSWORD)
    assert auth_mfa.USERS_FILE.exists()

    # Limpa o cache em memória -- se a leitura só funcionasse via cache,
    # isso quebraria a próxima chamada.
    auth_mfa.USERS_DB.clear()

    user = auth_mfa._user_get(TEST_EMAIL)
    assert user is not None
    assert user["email"] == TEST_EMAIL


def test_reset_de_senha_local_loga_link_em_vez_de_enviar_email(local_backend, caplog):
    auth_mfa.register_user(email=TEST_EMAIL, password=TEST_PASSWORD)

    with caplog.at_level("INFO"):
        auth_mfa.request_password_reset(TEST_EMAIL)

    assert any("Link de redefinição de senha" in rec.message for rec in caplog.records)

    resets = auth_mfa.read_json(auth_mfa.PASSWORD_RESETS_FILE, {})
    assert len(resets) == 1
    token = next(iter(resets))

    nova_senha = "OutraSenhaForte!2026"
    auth_mfa.reset_password(token, nova_senha)

    login = auth_mfa.login_user(email=TEST_EMAIL, password=nova_senha)
    assert login["authenticated"] is True
