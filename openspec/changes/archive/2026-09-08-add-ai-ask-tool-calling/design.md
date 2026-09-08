## Context

`ai_analyzer.ask()` (`ai_analyzer.py:236`) hoje monta contexto (scan atual + até 3 do histórico + RAG opcional) e faz uma única chamada `messages.create()` sem `tools=`. Não há capacidade de tool-calling no app hoje. Um padrão equivalente já roda em produção em outro repo (`terraform-scanner-ha/lambda/watchdog/agents/tools/claude_tools.py`): `TOOLS` (lista de schemas) + `_DISPATCH` (dict função) + loop manual de tool-use, com `urllib` puro (o Lambda evita deliberadamente o SDK `anthropic` por peso de empacotamento — ver `docs/langchain-adoption-roadmap.md`). O app roda em EC2 via `uvicorn`, sem essa restrição — já tem `anthropic` instalado. Ver proposal.md para motivação completa.

## Goals / Non-Goals

**Goals:**
- Provar o padrão de tool-calling nativo do SDK `anthropic` num endpoint novo, sem risco para `/ai/ask` em produção.
- Reaproveitar `K8sAuthenticatedAuditor` como está, sem modificá-lo.

**Non-Goals:**
- Não promover para `/ai/ask` nesta fase (isso é a Fase 2 do roadmap, change futuro e separado).
- Não adotar LangChain/LangGraph (decisão já registrada em `docs/langchain-adoption-roadmap.md`: o ganho de `@tool`/`AgentExecutor` sobre o loop manual é abstração, não capacidade nova, e o padrão manual já está provado em `claude_tools.py`).
- Não expor `IAMAuditor` nem auditores de storage (S3/GCS/Azure Blob) como tool nesta fase — sem ambiente AWS disponível hoje (100% local), IAM não tem credencial real pra usar; volta a ser considerado em change futuro separado quando houver ambiente AWS de novo.
- Não mexer no Lambda watchdog nem no seu `claude_tools.py`.

## Decisions

### Loop de tool-use manual, sem framework
Alternativa considerada: `client.beta.messages.tool_runner` (helper do SDK `anthropic`) em vez de loop escrito à mão.
Escolha: loop manual, no mesmo formato de `claude_tools.py`, por dois motivos — (1) mantém o padrão idêntico ao já validado em produção no Lambda, reduzindo a distância entre os dois códigos que resolvem o mesmo problema em runtimes diferentes; (2) o volume de tools desta fase (2) não justifica ainda a camada de abstração do tool runner. Reavaliar se o número de tools crescer.

### Tool como wrapper fino sobre a classe de auditor existente
`K8sAuthenticatedAuditor` é uma classe (`GraphCollector`), não uma função `run()` solta — diferente do padrão função-por-módulo do Lambda (`watchdog.py`, `incident.py`). A tool function instancia a classe e chama seu método de execução, capturando exceção e traduzindo pra `tool_result` de erro (ver Requirement "Falha de tool não derruba a resposta"). Nenhuma mudança na classe de auditor.

### Credencial via corpo da requisição, nunca via input da tool
Alternativa considerada: deixar o schema da tool incluir um campo `kubeconfig`, preenchido pelo modelo a partir do que o usuário colar na conversa.
Escolha: rejeitada — colocar credencial em `tool_use.input` a exporia no histórico de mensagens, em logs, e ao próprio modelo desnecessariamente. Em vez disso, `/ai/ask-tools` aceita `kubeconfig` opcional no corpo da requisição HTTP (mesmo formato de `K8sScanIn.kubeconfig` em `/scan/k8s`), resolvido para dentro da *closure* da tool function antes do loop de tool-use começar. Sem `kubeconfig` no request, cai para o kubeconfig de teste local do repo (`security-scanner-kubeconfig-kind-microservices-lab.yaml`) — conveniência do ambiente local atual (100% local, sem AWS), não uma escolha de produto para quando houver múltiplos tenants com clusters reais.

### Rate limit separado, valor conservador
Alternativa considerada: herdar `10/minute` de `/ai/ask`.
Escolha: limite próprio, mais baixo (proposta: `5/minute` por usuário) — rodar um auditor de verdade custa mais (chamadas AWS/K8s reais) que ler um scan já salvo. Valor exato a confirmar em tasks.md/implementação olhando `timed_metric("AiAnalysisDuration")` do endpoint existente como referência de custo real.

### Flag de disponibilidade separada de `AI_AVAILABLE`
O endpoint novo SHALL checar `AI_AVAILABLE` (mesma flag de hoje — indisponibilidade do `ai_analyzer`) mas não precisa de flag de feature adicional: por ser endpoint novo e não substituir nada, não há necessidade do padrão "flag desligada por padrão" que a Fase 2 do roadmap propõe para a promoção futura a `/ai/ask`.

## Risks / Trade-offs

- [Tool de K8s exposta a input do modelo pode ser induzida a apontar para endpoint arbitrário] → mitigado pelo `ssrf_guard.assert_server_not_ssrf_target()` já embutido no construtor de `K8sAuthenticatedAuditor` (Requirement dedicado no spec).
- [`kubeconfig` no corpo da requisição pode acabar em logs de acesso/erro] → mesmo risco que `/scan/k8s` já tem hoje; nenhuma mudança de comportamento de logging introduzida por este change, só reaproveita o padrão existente.
- [Duplicação de padrão entre `claude_tools.py` (Lambda) e o novo `ai_tools.py` (app)] → aceito conscientemente: os dois runtimes não compartilham pacote Python (mesma razão já documentada para `rag.py` duplicado). Manter a mesma forma de `TOOLS`/dispatch nos dois reduz o custo de leitura cruzada, mesmo sem compartilhar código.
- [Custo/latência de rodar um auditor real dentro de uma requisição HTTP síncrona] → mitigado pelo rate limit próprio mais conservador; medir com `timed_metric` antes de considerar promoção (Fase 2).
- [Auditor de K8s pode demorar o suficiente para estourar timeout de request] → tasks.md deve incluir decisão explícita de timeout por execução de tool, não deixar implícito.
- [Escopo do piloto ficou restrito a K8s só porque não há ambiente AWS hoje, não por limitação técnica do padrão] → aceito como trade-off temporário; revisitar IAM como tool quando houver ambiente AWS de novo (change futuro).

## Migration Plan

Não há migração — endpoint inteiramente novo, sem dado existente a migrar. Rollback: remover o endpoint e `ai_tools.py`; zero impacto em `/ai/ask` ou qualquer outro endpoint.

## Open Questions

- Valor exato do rate limit (`5/minute` é uma proposta inicial, não medida) — resolver com dado real de latência assim que o piloto rodar contra um cluster de teste.
