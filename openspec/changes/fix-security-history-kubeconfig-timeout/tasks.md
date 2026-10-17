## 1. Histórico de scans — validação de provider (item 1)

- [x] 1.1 Adicionar em `scan_history.py` o helper de normalização de provider (regex `^[a-z0-9_]{1,32}$` após `.lower()`) e verificar com teste unitário que aceita `k8s`, `aws_iam`, `AWS_IAM`, `azure_blob`, `universal`, `public`, `unknown` e rejeita `../x`, `a/b`, `.`, `""`, string de 33 chars
- [x] 1.2 Usar o helper em `list_scans` (levanta `ValueError` em inválido) e conferir no modo local que o diretório resolvido continua dentro da pasta do usuário; verificar com teste em `tests/test_scan_history_local_backend.py` que `list_scans(email_a, provider="../<pasta_de_b>")` levanta erro e não retorna scans de B
- [x] 1.3 Usar o helper em `save_scan` gravando como `unknown` quando inválido; verificar com teste que `save_scan(email, "../evil", ...)` cria o arquivo em `<pasta_do_usuario>/unknown/` e nada fora dela
- [x] 1.4 Restringir `provider` na borda: `Query(None, pattern=...)` em `GET /scan/history` e `Field(pattern=...)` em `AiAskIn` / `AiAskToolsIn`; verificar com teste de endpoint (TestClient + sessão MFA mockada, mesmo padrão de `tests/test_ai_ask_tools_endpoint.py`) que `?provider=../x` responde 422 e `?provider=k8s` responde 200

## 2. Kubeconfig — recusar `exec` / `auth-provider` (item 2)

- [x] 2.1 Criar o validador de kubeconfig (YAML → dict, recusa `users[].user.exec` e `users[].user.auth-provider`, recusa YAML inválido/não-mapeamento) e verificar com teste novo `tests/test_kubeconfig_validation.py` cobrindo: token aceito, client-cert aceito, exec recusado, auth-provider recusado, YAML inválido recusado
- [x] 2.2 Chamar o validador em `K8sStorageAuditor._load_config` antes do `KubeConfigLoader`; verificar com teste que um kubeconfig com `exec` cujo comando cria um arquivo-sentinela levanta erro e o arquivo-sentinela **não** é criado
- [x] 2.3 Chamar o validador no construtor de `K8sAuthenticatedAuditor` (lendo o arquivo de `kubeconfig_path`) antes do `load_kube_config`; verificar com o mesmo teste de sentinela via `kubeconfig_path`
- [x] 2.4 Adicionar `field_validator` em `K8sScanIn.kubeconfig` e `AiAskToolsIn.kubeconfig`; verificar com teste de endpoint que `POST /scan/k8s` e `POST /ai/ask-tools` com `exec` respondem 422 e que `POST /scan/k8s` com YAML inválido responde 422 (não 500)
- [x] 2.5 Confirmar que o kubeconfig do piloto local (`token`) continua passando: rodar o validador sobre `security-scanner-kubeconfig-kind-microservices-lab.yaml` e verificar que não levanta

## 3. Timeout da tool K8s (item 5)

- [x] 3.1 Trocar o `with ThreadPoolExecutor` de `_execute_tool` por executor de módulo + `BoundedSemaphore` (`MAX_CONCURRENT_TOOL_RUNS`), liberando o semáforo quando a auditoria realmente terminar; verificar com teste em `tests/test_ai_tools.py` que, com `TOOL_TIMEOUT_SECONDS` reduzido via monkeypatch e uma tool fake que dorme mais que isso, `_execute_tool` retorna erro de timeout em menos de `timeout + 1s`
- [x] 3.2 Verificar com teste que, com todas as vagas ocupadas por tools fake bloqueadas, uma nova chamada retorna na hora erro de "scanner ocupado" sem submeter tarefa, e que a vaga volta a ficar livre quando a tool fake termina
- [x] 3.3 Verificar com teste que exceções da tool continuam virando `{"error": ...}` e que o resultado de sucesso continua passando por `_sanitize_tool_result`

## 4. Documentação e validação final

- [x] 4.1 Atualizar o README (seção de scan K8s) dizendo que kubeconfig com `exec`/`auth-provider` (EKS/GKE/AKS via CLI de nuvem) é recusado e que o caminho suportado é ServiceAccount com token; verificar lendo a seção renderizada
- [x] 4.2 Rodar `pytest tests/ -q` e verificar que tudo passa (92 testes anteriores + os novos)
- [x] 4.3 Smoke test no app local rodando: `GET /scan/history?provider=../x` → 422, `GET /scan/history?provider=k8s` → 200 (com sessão válida), `/login` → 200
  - Resultado: no servidor ao vivo (sem sessão) `/login` 200 e as rotas protegidas 401, sem 500 após o reload. Os casos com sessão (422 / 200) foram verificados com TestClient sobre o mesmo `app` em `tests/test_scan_history_endpoint.py` e `tests/test_kubeconfig_validation.py` — não foi criada sessão MFA artificial no `local_data/`.
- [x] 4.4 Rodar `openspec validate fix-security-history-kubeconfig-timeout --strict` e verificar que passa
