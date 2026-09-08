## Why

Hoje `POST /ai/ask` (`api_with_mfa.py:1597`, implementado em `ai_analyzer.ask()`) só interpreta o último scan já feito e o histórico recente — monta contexto e faz uma única chamada `messages.create()` **sem `tools=`**. O usuário não pode pedir "rode uma auditoria de IAM agora" e receber um resultado fresco; só pode perguntar sobre o que já foi escaneado. Isso já foi mapeado em `docs/langchain-adoption-roadmap.md` (Fase 1) como o maior ganho real de capacidade disponível hoje, e um padrão equivalente já roda em produção no Lambda watchdog (`claude_tools.py`, noutro repo) com tool-calling manual via `urllib` — este change porta esse padrão pro app, usando o SDK `anthropic` nativo (sem LangChain: ver decisão registrada no roadmap).

## What Changes

- Novo endpoint `POST /ai/ask-tools`, **paralelo** a `/ai/ask` — não substitui nem modifica o endpoint existente.
- Novo módulo (`ai_tools.py`, ou seção isolada em `ai_analyzer.py`) com:
  - Um `TOOLS` (lista de schemas Anthropic) + dispatch para auditores selecionados a rodar sob demanda.
  - Loop manual de tool-use (`tool_use` → executa → `tool_result` → re-chama), no mesmo espírito de `claude_tools.py` do Lambda — sem framework externo (`langchain`/`langgraph` fora de escopo, ver `docs/langchain-adoption-roadmap.md`).
- **Escopo reduzido a K8s** (atualização pós-inspeção): `IAMAuditor` exige `aws_access_key_id`/`aws_secret_access_key` reais no construtor — sem ambiente AWS disponível hoje (100% local, ver memória de projeto), não há credencial nenhuma pra essa tool usar. `IAMAuditor` fica **fora** deste change; só `K8sAuthenticatedAuditor` (`auditor_k8s_authenticated.py`) é exposto como tool. IAM volta a ser considerado quando houver ambiente AWS de novo — change futuro e separado.
- A proteção anti-SSRF (`ssrf_guard.assert_server_not_ssrf_target`) já é **inerente** ao construtor de `K8sAuthenticatedAuditor` (`auditor_k8s_authenticated.py:88`) — a tool wrapper não precisa chamá-la separadamente, só precisa deixar a exceção que ela levanta virar `tool_result` de erro.
- O corpo de `/ai/ask-tools` ganha um campo opcional `kubeconfig` (mesmo formato de `K8sScanIn.kubeconfig` em `/scan/k8s`) — a credencial do cluster nunca é parâmetro que o modelo preenche (não entra no schema da tool nem no `tool_use.input`); fica só na *closure* da função wrapper, resolvida a partir do request. Sem `kubeconfig` no request, a tool usa o kubeconfig de teste local do repo (`security-scanner-kubeconfig-kind-microservices-lab.yaml`) — conveniência só para o ambiente local atual, não uma escolha de produto.
- Rate limit próprio no novo endpoint (não herda o `10/minute` de `/ai/ask` automaticamente — precisa de decisão explícita em `design.md`, dado que rodar um auditor de verdade é mais caro que só ler um scan já feito).

## Capabilities

### New Capabilities
- `ai-tool-calling`: endpoint `/ai/ask-tools` autenticado (mesma sessão MFA de `/ai/ask`) que permite ao Claude decidir, via tool-use nativo do SDK `anthropic`, rodar `K8sAuthenticatedAuditor` sob demanda para responder a uma pergunta livre do usuário, em vez de só interpretar o último scan já feito.

### Modified Capabilities
(nenhuma — `/ai/ask` e `ai_analyzer.ask()` permanecem intocados nesta fase; ver Fase 2 do roadmap para a promoção futura)

## Impact

- **Código novo**: `ai_tools.py` (ou seção em `ai_analyzer.py`), rota nova em `api_with_mfa.py`.
- **Código lido, não alterado**: `auditor_k8s_authenticated.py` (`K8sAuthenticatedAuditor`, que já embute a checagem de `ssrf_guard.py`). `auditor_iam.py` fica fora de escopo deste change.
- **Sem dependência nova**: usa `anthropic` (já instalado), zero pacote adicional.
- **Sem mudança de storage**: não toca `rag.py`, DynamoDB, nem o histórico de scans.
- **Testes**: seguir o padrão de `tests/` (moto para AWS, monkeypatch para chamadas externas) — nenhum teste deve bater na Anthropic API real nem em nuvem real.
