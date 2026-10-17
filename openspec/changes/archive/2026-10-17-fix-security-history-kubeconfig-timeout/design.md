## Context

Motivação em `proposal.md`. Estado atual relevante para o "como":

- `scan_history.py` monta o caminho local como `LOCAL_DIR / _email_safe(email) / provider.lower()` e lista com `rglob`; no modo AWS, o mesmo valor vira parte do prefixo S3. `save_scan` usa o mesmo padrão para gravar. Nenhum dos dois valida `provider`.
- `provider` chega por três portas: query string de `GET /scan/history` (`Optional[str]` cru), e os campos `provider` de `AiAskIn` / `AiAskToolsIn` (validados manualmente com `model_validate`, que já responde 422 em erro). Na gravação, vem de constantes (`"k8s"`, `"aws_iam"`...) ou de `result["provider"].lower()` (`aws_s3`, `gcs`, `azure_blob`, `kubernetes`, `universal`...).
- O kubeconfig do usuário é carregado em dois lugares: `K8sStorageAuditor._load_config` (`KubeConfigLoader(config_dict=...).load_and_set`) e o construtor de `K8sAuthenticatedAuditor` (`config.load_kube_config(config_file=...)`). Os dois executam o plugin `users[].user.exec` durante o load, antes de `assert_server_not_ssrf_target`. Confirmado na versão instalada da biblioteca `kubernetes`.
- `ai_tools._execute_tool` usa `with ThreadPoolExecutor(max_workers=1)`; o `__exit__` chama `shutdown(wait=True)`, então o `return` do timeout só acontece depois que o auditor termina (reproduzido: timeout de 1s retornou em 6s). `/ai/ask-tools` é `def` síncrono, então cada espera ocupa uma thread do threadpool do FastAPI.

## Goals / Non-Goals

**Goals:**
- Fechar as três falhas com validação na borda (request) **e** defesa em profundidade no ponto de uso (`scan_history`, auditores), para que um caminho novo que esqueça a validação da borda não reabra o problema.
- Não quebrar o piloto local (kubeconfig `kind` com `token`) nem os testes atuais.

**Non-Goals:**
- Matar a thread do auditor depois do timeout (Python não cancela thread em execução); só garantir que a requisição não espera e que o número de threads presas é limitado.
- Corrigir os demais achados da revisão (config global do K8s, rebaixamento em `kube-system`, RoleBinding→ClusterRole, coluna Namespace) — ficam para outro change.
- Suportar kubeconfig de EKS/GKE/AKS com `exec` (ver Risks).

## Decisions

### 1. Validação de `provider`: regex + normalização, num helper único em `scan_history`
`scan_history` ganha um helper (ex.: `normalize_provider(value) -> str`) com a regra `^[a-z0-9_]{1,32}$` após `.lower()`.
- `list_scans`/`load_recent` levantam `ValueError` para provider inválido.
- `save_scan` grava como `unknown` em vez de levantar — um scan que terminou não deve ser perdido por causa do rótulo.
- Na borda: `AiAskIn.provider` e `AiAskToolsIn.provider` ganham `Field(pattern=...)` (422 via o `model_validate` existente); `GET /scan/history` usa `Query(None, pattern=...)` (422 nativo do FastAPI).
- Defesa extra no modo local: após montar `base`, conferir que `base.resolve()` continua dentro de `(LOCAL_DIR / email_safe).resolve()`.

**Alternativa considerada:** allowlist fixa de providers. Rejeitada: os valores vêm de vários auditores (`aws_s3`, `azure_blob`, `universal`, `public`...) e uma lista fechada quebraria o histórico a cada auditor novo. A regex fecha traversal do mesmo jeito.

### 2. Kubeconfig: função de validação compartilhada, chamada na borda e nos auditores
Novo helper puro (ex.: `validate_user_kubeconfig(yaml_text) -> dict`, em módulo próprio ou em `ssrf_guard.py`, que já concentra guardas desse tipo) que:
- faz `yaml.safe_load`; exige um `dict`;
- percorre `users[].user` e levanta `ValueError` se encontrar a chave `exec` ou `auth-provider`.

Chamado em:
- `K8sScanIn` e `AiAskToolsIn` como `field_validator` do campo `kubeconfig` → 422 na borda.
- `K8sStorageAuditor._load_config` antes do `KubeConfigLoader`.
- `K8sAuthenticatedAuditor.__init__` antes do `load_kube_config` quando houver `kubeconfig_path` (lê o arquivo e valida). Também cobre o arquivo default do piloto em `ai_tools`.

**Alternativa considerada:** allowlist de chaves permitidas em `user` (token, certificados...). Mais restritiva, mas quebraria campos legítimos e raros (`impersonate`, `as-groups`). Denylist de `exec`/`auth-provider` cobre exatamente os dois mecanismos que a biblioteca usa para executar código.

### 3. Timeout: executor de módulo com limite de concorrência e espera não bloqueante
- Um `ThreadPoolExecutor` de módulo em `ai_tools` com `max_workers = MAX_CONCURRENT_TOOL_RUNS` (ex.: 2), mais um `threading.BoundedSemaphore` do mesmo tamanho.
- `_execute_tool` tenta `acquire(blocking=False)`; se falhar, devolve na hora `{"error": "scanner ocupado..."}`.
- Submete a tarefa com um wrapper que libera o semáforo em `finally` quando a auditoria **realmente** terminar (mesmo depois do timeout).
- Espera com `future.result(timeout=TOOL_TIMEOUT_SECONDS)` **fora** de qualquer `with` do executor; em timeout devolve o erro imediatamente.

Efeito: a requisição sempre volta em ~`TOOL_TIMEOUT_SECONDS`, e no pior caso existem no máximo `MAX_CONCURRENT_TOOL_RUNS` auditorias zumbis, em vez de uma por requisição.

**Alternativas consideradas:**
- `shutdown(wait=False)` no executor local por chamada: resolve a espera, mas não limita threads acumuladas.
- Rodar a auditoria em processo separado (`multiprocessing`) para poder matá-la: isolamento real, mas custo alto de serialização/fork e mudança de modelo de execução. Fora do escopo.

## Risks / Trade-offs

- [Kubeconfig de nuvem gerenciada (EKS/GKE/AKS) usa `exec` e passa a ser recusado] → É o caminho que permitia RCE; o fluxo suportado é o de ServiceAccount com token (script de onboarding). A mensagem de erro do 422 dirá isso explicitamente. Documentar no README.
- [Auditoria zumbi continua consumindo rede/CPU após o timeout] → Limitada a `MAX_CONCURRENT_TOOL_RUNS` threads; cada chamada à API do cluster já tem `_request_timeout`, então elas terminam sozinhas.
- [Regex de provider rejeitar um valor legítimo hoje usado pelo dashboard] → Todos os valores gravados hoje (`aws_s3`, `aws_iam`, `gcp_iam`, `azure_iam`, `azure_blob`, `gcs`, `kubernetes`, `k8s`, `universal`, `public`, `unknown`) casam com a regex; teste cobre a lista.
- [`field_validator` em `K8sScanIn` muda o código de erro de kubeconfig inválido de 500 para 422] → Mudança desejada (spec "Kubeconfig inválido é recusado sem erro 500").

## Migration Plan

Sem migração de dados: os diretórios/prefixos de histórico existentes já usam providers que casam com a regex. Deploy é a troca de código normal; rollback é reverter o commit.
