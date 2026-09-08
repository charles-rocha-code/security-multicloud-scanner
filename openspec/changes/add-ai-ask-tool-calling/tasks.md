## 1. Módulo de tools

- [x] 1.1 Criar `ai_tools.py` com `TOOLS` (schema Anthropic para "run_k8s_audit" apenas — IAM fora de escopo, sem ambiente AWS disponível) e `_DISPATCH` (dict função), no mesmo formato de `claude_tools.py` (Lambda) — verificar importando o módulo sem erro e checando `len(TOOLS) == 1`
- [x] 1.2 Implementar wrapper que recebe `kubeconfig` (str) via closure (não via schema/input da tool), instancia `K8sAuthenticatedAuditor` (`auditor_k8s_authenticated.py`) e executa — a checagem SSRF já é inerente ao construtor do auditor, não precisa ser chamada separadamente — verificar com teste que injeta um kubeconfig apontando pra alvo SSRF e confirma recusa antes de qualquer chamada de rede
- [x] 1.3 Tratar exceção do wrapper (auditor falha, kubeconfig ausente/inválido, SSRF recusado pelo construtor) devolvendo `tool_result` com `is_error: true` e mensagem legível, nunca propagando exceção não tratada — verificar com teste que força cada tipo de falha e confere que a resposta da tool chega como erro estruturado, não como crash

## 2. Loop de tool-use

- [x] 2.1 Implementar a função que chama `messages.create()` com `tools=TOOLS`, processa blocos `tool_use`, executa via `_DISPATCH` (com `kubeconfig` já resolvido — do request ou do default local — passado por closure/argumento da função, nunca pelo `tool_use.input`), e re-chama com os `tool_result` até `stop_reason != "tool_use"` — verificar com teste que simula (mock) uma resposta da Anthropic API pedindo uma tool e confirma que o loop completa e retorna texto final
- [x] 2.2 Tratar `stop_reason == "refusal"` do mesmo jeito que `ai_analyzer._extract_text()` já faz hoje (reaproveitar ou espelhar `AiRefusalError`) — verificar com teste que simula recusa e confirma que não há `IndexError`
- [x] 2.3 Definir timeout por execução de tool (Risco identificado em design.md: auditor K8s pode demorar) — verificar com teste que simula um auditor lento e confirma que o timeout é respeitado

## 3. Endpoint

- [x] 3.1 Adicionar `POST /ai/ask-tools` em `api_with_mfa.py`, exigindo a mesma dependência `require_mfa` de `/ai/ask`, sem alterar `/ai/ask` existente — verificar com teste de integração que uma requisição sem sessão MFA válida recebe 401/403
- [x] 3.2 Adicionar campo opcional `kubeconfig: Optional[str]` ao body do novo endpoint (mesmo formato de `K8sScanIn.kubeconfig`); sem esse campo, resolver para o kubeconfig de teste local do repo (`security-scanner-kubeconfig-kind-microservices-lab.yaml`) — verificar com dois testes: um enviando `kubeconfig` próprio, outro sem enviar nada e confirmando o fallback local
- [x] 3.3 Aplicar rate limit próprio via `@limiter.limit(...)` com valor inicial `5/minute` (proposta de design.md, open question a confirmar) — verificar com teste que a 6ª requisição no mesmo minuto recebe 429, e que isso não afeta a cota de `/ai/ask`
- [x] 3.4 Emitir métrica `timed_metric("AiAnalysisDuration", dimensions={"Operation": "ask_tools"})` no novo endpoint, reaproveitando o padrão já usado por `/ai/ask`/`/ai/analyze` — verificar inspecionando a chamada no código (sem exigir CloudWatch real em teste local)

## 4. Testes de regressão

- [x] 4.1 Confirmar que a suíte de testes existente (`pytest tests/`) continua passando sem nenhuma alteração, comprovando que `/ai/ask` e `ai_analyzer.ask()` não foram tocados
- [x] 4.2 Rodar `tests/test_rag_isolation.py` (se aplicável ao novo módulo) — o novo endpoint não deve introduzir nenhum caminho que ignore o filtro `owner`/`category` do RAG existente

## 5. Documentação

- [x] 5.1 Atualizar `docs/langchain-adoption-roadmap.md` marcando a Fase 1 como implementada, com link pro PR/commit — mesmo padrão já usado nos outros roadmaps do projeto (`dspm-kspm-roadmap.md`)
