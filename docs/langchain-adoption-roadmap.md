# Avaliação de adoção do LangChain/LangGraph — security-multicloud-scanner

Documento de análise e roadmap. Não implementado, não commitado — decisão pendente do usuário sobre se e por onde começar.

## TL;DR

A análise em 4 pontos que motivou este documento (orquestração de agentes, RAG, tool-calling, memória) está correta na direção, mas superestima a dor real em dois dos quatro pontos e ignora uma restrição de arquitetura que descarta um deles por completo. Recomendação:

| # | Ponto | Veredito | Onde |
|---|---|---|---|
| 1 | Orquestração de agentes (LangGraph) | **Não agora** | Lambda watchdog |
| 2 | RAG (retriever abstraído) | **Sim, como piloto isolado** | App (EC2) |
| 3 | Tool-calling em `/ai/ask` | **Sim — maior ganho real** | App (EC2) |
| 4 | Memória de conversa | **Sim, mas é feature nova, não migração** | App (EC2) |

O maior valor prático não é "trocar código caseiro por abstração testada" (como a análise original enquadra) — é destravar uma capacidade que `/ai/ask` genuinamente não tem hoje: rodar uma auditoria nova sob demanda, não só interpretar uma já feita.

---

## Correção de premissas

Antes de desenhar o roadmap, valeu conferir cada uma das quatro afirmações da análise original contra o código real. Duas delas não bateram.

### 1. "WatchdogAgent, IncidentAgent, ScalerAgent... coordenados por lógica Python própria"

Parcialmente impreciso. Não são classes nem objetos com estado — são módulos de função (`watchdog.py`, `incident.py`, `scaler.py`, `deploy.py`, `waf_agent.py`, `drift.py`) despachados por `orchestrator.py`, um `if/elif` de ~70 linhas sobre uma string de comando. A única cadeia real de dois passos que existe hoje é:

```python
if command == "watchdog":
    result = watchdog.run()
    if result["status"] == "anomaly":
        incident.respond(result["findings"])
    return result
```

Isso não é um problema de orquestração — é uma condicional. LangGraph resolve grafos com múltiplos nós, arestas condicionais decididas por raciocínio (frequentemente de um LLM), ciclos, e checkpointing de estado entre etapas longas. Nenhuma dessas necessidades existe no código atual. Adotar LangGraph aqui seria buscar uma solução antes do problema justificar o tamanho dela.

**Mais grave**: `terraform-scanner-ha/lambda/watchdog/agents/tools/claude_tools.py` documenta, no próprio docstring, uma decisão deliberada de **não usar nem o SDK `anthropic` (pip)** nesse Lambda — porque ele é um zip puro (`data.archive_file` direto, sem `requirements.txt`/layer) e vendorizar o SDK + suas dependências transitivas (`httpx`, `pydantic` com wheels compilados) seria "um salto de complexidade de empacotamento desproporcional a uma chamada diária". `langgraph` + `langchain-core` têm superfície de dependência maior que o SDK `anthropic` sozinho. Introduzir isso aqui contradiz uma decisão de engenharia já tomada e documentada — não é uma omissão a corrigir, é um trade-off já pesado.

### 2. RAG "sobre DynamoDB, não vector store de verdade"

Correto — mas incompleto de um jeito que importa. A tabela `security-scanner-knowledge` é **compartilhada entre dois runtimes de dois repositórios diferentes** (o app em EC2 e o Lambda watchdog, que mantém uma cópia paralela de `rag.py` porque os dois não compartilham pacote Python). O filtro `owner`/`category` em `rag.retrieve()` não é um parâmetro de conveniência — é o que impede o RAG de findings de um cliente vazar pra outro, e o que impede o RAG de changelog interno do Lambda vazar pro RAG de scan do app. Isso é o princípio #7 do próprio `devops-appsec-advisor` (isolamento multi-tenant), aplicado nesta camada.

Trocar por um `VectorStoreRetriever` do LangChain não é plugar uma peça — é reimplementar um filtro de segurança em cima de uma abstração de terceiros, em dois códigos que não compartilham pacote. Dá pra fazer, mas o filtro `owner`/`category` precisa continuar sendo parâmetro de primeira classe na chamada, testado explicitamente (como já é hoje em `tests/test_rag_isolation.py`), não algo que se assume que a abstração preserva.

### 3. Tool-calling — "isso destrava o `/ai/ask` a realmente rodar uma auditoria"

Correto que `/ai/ask` hoje não roda nada — `ai_analyzer.ask()` (`ai_analyzer.py:236`) monta contexto (scan atual + até 3 do histórico + resultados de RAG) e faz uma única chamada `messages.create()` **sem `tools=`**. Sem capacidade de tool-calling nenhuma.

Mas "zero tool-calling no projeto" é impreciso — **já existe um padrão funcionando em produção**: `claude_tools.py` no Lambda define um `TOOLS` (lista de schemas) + `_DISPATCH` (dict de função) e já resolve o loop de tool-use manualmente, com `urllib` puro. Esse é o template a portar/adaptar pro app (que roda em EC2, sem a restrição de empacotamento do Lambda) — não é preciso desenhar o padrão do zero, só decidir se a implementação usa `@tool` do LangChain ou continua o padrão manual já validado.

### 4. Memória de conversa — "hoje recebe pergunta + histórico bruto no prompt"

Aqui a imprecisão muda o enquadramento do trabalho. Conferido em `api_with_mfa.py:1586` (`POST /ai/ask`): não existe **nenhum conceito de sessão/conversa** na API hoje. Cada chamada é independente, sem `conversation_id`, rate-limited em 10/min por usuário. O "histórico" que `ask()` recebe é histórico de **scans** (`load_recent(email, provider, n=3)`), não histórico de **perguntas e respostas anteriores**. Não existe hoje nada que se pareça com "o usuário perguntou X, respondi Y, agora ele pergunta Z referindo-se a Y".

Isso não é migração de uma memória existente pra uma abstração melhor — é adicionar uma feature de produto que não existe: decidir o que é uma "sessão" pro usuário do scanner (por login? por scan? por janela de tempo?), antes de decidir a ferramenta que a implementa.

---

## Escopo: onde aplica e onde não

```
Lambda (terraform-scanner-ha/lambda/watchdog/)     App (security-multicloud-scanner/, EC2 + uvicorn)
├── zip puro, sem layer                             ├── pip install normal, sem restrição de empacotamento
├── já evita o SDK anthropic por peso                ├── já usa fastapi, boto3, anthropic, bcrypt, etc.
├── 1 cadeia condicional real (watchdog→incident)    ├── 3 endpoints /ai/* com potencial de tool-calling real
└── NÃO mexer                                        └── candidato pro piloto
```

---

## Roadmap faseado

Cada fase é isolada, reversível, e não deve depender da seguinte ter sido decidida ainda. Preserva o padrão já usado neste projeto pra mudança de risco (cluster k3s de teste isolado antes de mexer em produção, pytest com `moto` antes de subir código que toca DynamoDB).

### Fase 0 — Decisões prévias (sem escrever código)

Antes de instalar qualquer dependência nova:

1. **Decidir o conceito de sessão** pro ponto 4 (memória). Sem isso, qualquer implementação de memória vira retrabalho quando o produto decidir depois.
2. **Confirmar orçamento de dependência nova** — `langchain-core` + `langchain-anthropic` (ou só usar o SDK `anthropic` com tool-calling manual, sem LangChain nenhum, pro ponto 3). Vale medir: o ganho de usar `@tool`/`AgentExecutor` do LangChain sobre o padrão manual que já existe em `claude_tools.py` é abstração, não capacidade nova — o `/ai/ask` ganharia tool-calling de qualquer jeito, com ou sem o framework.
3. **Congelar escopo do piloto**: só a Fase 1 abaixo, sem compromisso de seguir pras demais.

Critério de saída: as 3 decisões acima registradas (mesmo que informalmente), sem nenhuma linha de código nova.

### Fase 1 — Piloto isolado: tool-calling em endpoint novo, não em `/ai/ask`

> **Atualização 07/09/2026 — implementada.** `POST /ai/ask-tools` (`api_with_mfa.py`) + `ai_tools.py`, planejados e implementados via OpenSpec (`openspec/changes/add-ai-ask-tool-calling/`, ainda não arquivado). Escopo reduzido a **só K8s** em relação ao plano original abaixo — `IAMAuditor` ficou fora porque o ambiente é 100% local hoje, sem credencial AWS real pra essa tool usar (ver `project_no_aws_environment` na memória do projeto); IAM volta a ser considerado quando houver ambiente AWS de novo. Decisão nova que não estava neste doc original: a credencial do cluster (`kubeconfig`) chega pelo corpo da requisição HTTP (mesmo campo de `/scan/k8s`) ou cai pro kubeconfig de teste local do repo — nunca é parâmetro que o modelo preenche. Sem LangChain, como já decidido abaixo — loop de tool-use manual com o SDK `anthropic`. 12 testes novos (`tests/test_ai_tools.py`, `tests/test_ai_ask_tools_endpoint.py`), suíte completa em 91/91. Ainda não commitado/PR aberto.

Objetivo original (contexto do planejamento abaixo): provar o padrão sem arriscar o endpoint de produção que já tem rate-limit e usuários reais.

- Criar `ai_tools.py` (ou seção nova em `ai_analyzer.py`) com um `TOOLS`/dispatch no mesmo espírito de `claude_tools.py` do Lambda, mas envolvendo os auditores que fazem sentido rodar sob demanda: `auditor_iam.py`, `auditor_k8s.py` (com `ssrf_guard` já aplicado — não pular essa checagem ao expor como tool), possivelmente `auditor_universal.py`.
- Endpoint novo, `POST /ai/ask-tools` (ou flag `use_tools: bool` em `AiAskIn`, desligada por padrão) — não substitui `/ai/ask`, roda em paralelo.
- Testes primeiro: seguir o padrão já criado em `tests/` (moto pra DynamoDB, monkeypatch pra chamadas externas) — nenhum teste deve bater na Anthropic API de verdade nem em nenhuma nuvem real.
- Decisão de framework aqui: começar **sem LangChain**, só `tools=` nativo do SDK `anthropic` (o SDK já suporta tool-use nativamente, é o que `claude_tools.py` já faz manualmente com `urllib`). Só considerar `langchain-anthropic`/`AgentExecutor` se o loop de tool-use crescer a ponto de a orquestração manual (parse de `tool_use` blocks, re-chamada com `tool_result`) virar código repetido em mais de um lugar.

Critério de saída: endpoint novo, com testes, atrás de flag, sem tocar `/ai/ask` em produção. Rollback: apagar o endpoint novo, zero impacto no resto.

### Fase 2 — Validar em produção, promover

- Se a Fase 1 se provar (resposta melhor, sem regressão de latência/custo perceptível — `/ai/ask` já tem `timed_metric("AiAnalysisDuration")`, reaproveitar a métrica), promover a flag `use_tools` pra default `true` em `/ai/ask` normal, mantendo o caminho antigo (`ai_analyzer.ask()` sem tools) como fallback se `AI_AVAILABLE` mas a chamada com tools falhar.
- Critério de saída: `/ai/ask` roda com tool-calling em produção, com fallback testado.

### Fase 3 — RAG por trás de uma interface (sem trocar o storage ainda)

**Atualização de 08/2026** — a premissa "só se o volume justificar" abaixo deixou de ser hipotética. Conferido direto na tabela de produção (`aws dynamodb describe-table --table-name security-scanner-knowledge`): **65 itens, 1,5MB** — já ultrapassa o limite de 1MB por página do `Scan()`, então `retrieve()` hoje já faz no mínimo 2 idas ao DynamoDB por chamada, não 1. Não é mais uma projeção futura, é medido.

Isso também mudou o desenho dos dois passos abaixo — viraram três, com o primeiro sem dependência nenhuma de ferramenta externa:

1. **Correção imediata, baixo risco, sem tocar o storage**: GSI por `category` na tabela (`rag_knowledge.tf`) + trocar `table.scan()` por `table.query(IndexName="category-index", ...)` em `retrieve()` quando `category` é passado (é sempre, em todo caller de produção — só os testes chamam sem filtro). Não resolve o cosseno calculado em Python item a item, só corta o I/O de trazer categoria errada pra memória antes de filtrar. Aditivo, reversível, não muda a assinatura de `retrieve()`, não quebra `tests/test_rag_isolation.py`.

2. Envolver o `rag.py` atual atrás de uma interface (`langchain_core.retrievers.BaseRetriever` se for usar LangChain, ou só uma classe própria se não for) — **sem trocar o storage**. O `owner`/`category` continuam parâmetros obrigatórios da chamada, não config implícita da classe. `tests/test_rag_isolation.py` continua sendo o teste que decide se essa fase passou.

3. **Gate de troca de storage: trocado de "se o volume justificar" (vago) para "quando o tooling suportar" (checável, binário).** A AWS lançou busca vetorial nativa no DynamoDB em 05/08/2026 — tecnicamente a opção certa, porque é aditiva dentro do mesmo banco/tabela que já é usado, sem novo serviço, com o filtro `owner`/`category` promovido a parâmetro nativo da própria busca (`SearchConditionExpression`) em vez de pós-filtro em Python. **Verificado nos changelogs primários em 08/2026, ainda não disponível neste repo:**
   - `boto3` precisa de **1.43.64+** (a entrada exata do `CHANGELOG.rst` oficial: *"Vector indexes are a type of index in Amazon DynamoDB that enable similarity search..."*) — o repo está em `1.42.97` (`requirements.lock.txt`), abaixo da série 1.43.x inteira. Bump simples, sem breaking change conhecido.
   - `terraform-provider-aws`: zero menção a vetor+DynamoDB em todo o `CHANGELOG.md`, inclusive na versão mais recente na data da checagem (`6.58.0`, lançada no mesmo dia do anúncio da AWS) e na `6.59.0 (Unreleased)`. Mais grave: **`v5.100.0`, a versão travada neste repo, é de 12/06/2025 — o último release real da série 5.x**, que ficou congelada quando o provider migrou pra série 6.x seis dias depois. Ou seja, mesmo quando a feature sair, ela sai na 6.x — subir de `v5.100.0` pra `v6.x` é upgrade de versão maior com guia de breaking changes próprio, não um bump trivial.
   - Reavaliar este gate periodicamente (ex.: junto de cada revisão de roadmap), não uma vez só. Enquanto o gate não abre, o passo 1 acima é o único ganho de escala disponível.
   - OpenSearch Serverless segue **não recomendado** — não por custo (as coleções "NextGen", GA em 28/05/2026, têm scale-to-zero e derrubaram o piso de ~US$350/mês que motivou a rejeição original), mas por redundância: seria um serviço novo pra operar (rede, política de acesso, IAM adicional) resolvendo o que o DynamoDB nativo já resolveria dentro do serviço que o projeto já usa.

Critério de saída: passo 1 (GSI) implantado e testado independente do resto; passos 2–3 só avançam quando o gate de tooling do passo 3 abrir. Rollback do passo 1: reverter pro `scan()`, o GSI fica só sem uso.

### Fase 4 — Memória de conversa (feature nova)

Só depois da Fase 0 ter decidido o que é uma "sessão":

- Adicionar `conversation_id` ao `AiAskIn`, opcional (retrocompatível — sem ele, comportamento atual, stateless).
- Armazenar histórico de turnos (pergunta + resposta) em DynamoDB, TTL curto (não é histórico de scan, é histórico de conversa — vida útil menor, ex.: 24h), sob a mesma política de isolamento por `owner`/`email` já usada no resto do projeto.
- `RunnableWithMessageHistory` do LangChain é uma opção aqui; a alternativa sem framework é só passar a lista de `messages` acumulada pro `.messages.create()`, truncada por contagem de tokens (mais simples, menos dependência nova).

Critério de saída: nova funcionalidade, opt-in, sem quebrar nenhum chamador que não manda `conversation_id`.

### Fase 5 — Reavaliar orquestração do Lambda (não antes de tudo acima)

Só revisitar o ponto 1 (LangGraph no watchdog) se **as duas condições abaixo** se tornarem verdadeiras ao mesmo tempo:

- O Lambda ganhar um layer/empacotamento que não seja mais zip puro (custo de infra já pago por outro motivo).
- A cadeia de decisão crescer de 1 condicional pra um grafo real, com 3+ transições decididas por julgamento (não `if/elif` fixo) — o que hoje não existe.

Até lá, não há trabalho a fazer aqui.

---

## O que não fazer

- Não tocar em `terraform-scanner-ha/lambda/watchdog/` — a restrição de empacotamento é uma decisão já tomada, não uma lacuna.
- Não trocar as quatro coisas de uma vez — cada fase acima tem critério de saída próprio e é revertível isolada.
- Não assumir que "framework testado pela comunidade" implica preservar automaticamente o filtro `owner`/`category` do RAG — isso precisa de teste explícito, framework nenhum garante isolamento de dado específico do domínio.
- Não introduzir `langchain`/`langgraph` como dependência só pelo ponto 1 ou só pelo ponto 4 isoladamente — o ganho real do framework (se houver) aparece quando o tool-calling da Fase 1/2 e a memória da Fase 4 dividem a mesma abstração; adotado por um ponto só, o custo de nova dependência provavelmente não compensa frente ao padrão manual que já existe e funciona (`claude_tools.py`).

## Checkpoint antes de começar

Perguntas que só quem decide o produto responde, e que travam a Fase 0:

1. Qual auditor(es) faz sentido `/ai/ask` poder rodar sob demanda primeiro — IAM, K8s, os dois?
2. "Sessão" de conversa é por login, por scan, ou por janela de tempo curta (ex.: 30 min de inatividade)?
3. Vale a pena a dependência do LangChain em si, ou o padrão manual que já está provado em `claude_tools.py` resolve o mesmo problema com uma dependência a menos?
