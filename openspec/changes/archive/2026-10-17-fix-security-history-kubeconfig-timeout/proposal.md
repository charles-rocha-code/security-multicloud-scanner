## Why

A revisão do PR #11 levantou três falhas confirmadas por leitura de código (e, no caso do timeout, reproduzidas): um usuário autenticado consegue ler o histórico de scans de outro, consegue executar comando arbitrário no servidor enviando um kubeconfig, e uma tool lenta do `/ai/ask-tools` prende threads do FastAPI muito além do timeout declarado. Hoje o app só escuta em `127.0.0.1` com 4 usuários locais, então o impacto é contido — mas as três viram críticas assim que o ambiente AWS voltar (ALB público, múltiplos tenants), e precisam estar corrigidas antes disso.

## What Changes

- **Histórico de scans (path traversal):** o valor de `provider` passa a ser validado antes de virar segmento de caminho/prefixo em `scan_history` (`save_scan`, `list_scans`, `load_recent`). Valores fora do formato aceito são rejeitados: `GET /scan/history`, `/ai/ask` e `/ai/ask-tools` respondem 422 (mesmo padrão de validação que os endpoints de IA já usam).
- **Kubeconfig enviado pelo usuário (RCE):** todo kubeconfig recebido de fora (`/scan/k8s`, `/ai/ask-tools`) é inspecionado **antes** de chegar em `load_kube_config` / `KubeConfigLoader`; se algum `users[].user` declarar `exec` ou `auth-provider`, o scan é recusado com erro claro. Autenticação por token e certificado de cliente continua funcionando.
- **Timeout da tool K8s:** `_execute_tool` passa a devolver o erro de timeout dentro do limite declarado (`TOOL_TIMEOUT_SECONDS`), sem esperar a thread do auditor terminar, e limita quantas auditorias podem ficar rodando em background ao mesmo tempo para não esgotar o threadpool do app.

## Capabilities

### New Capabilities
- `scan-history`: isolamento do histórico de scans por usuário — o filtro `provider` não pode sair da área do usuário autenticado.
- `k8s-kubeconfig-validation`: regras para aceitar um kubeconfig vindo do usuário antes de carregá-lo (proibir mecanismos que executam código local).

### Modified Capabilities
- `ai-tool-calling`: o requisito "Falha de tool não derruba a resposta" ganha a garantia de que timeout de tool encerra a espera dentro do limite e não acumula threads presas.

## Impact

- **Código:** `scan_history.py`, `api_with_mfa.py` (`/scan/history`, `AiAskIn`, `AiAskToolsIn`, `/scan/k8s`), `auditor_k8s.py` (`K8sStorageAuditor._load_config`), `auditor_k8s_authenticated.py` (construtor), `ai_tools.py` (`_execute_tool`, `_run_k8s_audit`).
- **API:** `GET /scan/history?provider=<inválido>` passa de 200 (com dados de outra pasta) para 422. `POST /scan/k8s` com kubeconfig `exec`/`auth-provider` passa de "executa e escaneia" para 422. Kubeconfigs de EKS/GKE/AKS gerados por `aws eks update-kubeconfig` / `gcloud` (que usam `exec`) deixam de ser aceitos — o caminho suportado é o kubeconfig de ServiceAccount com token, que é o que o script de onboarding já gera.
- **Sem mudança:** kubeconfig local do piloto (`security-scanner-kubeconfig-kind-microservices-lab.yaml`, autenticação por `token`), modo AWS de persistência, formato das respostas de sucesso.
- **Testes:** novos casos em `tests/test_scan_history_local_backend.py`, `tests/test_ai_tools.py` e um teste novo para a validação de kubeconfig.
