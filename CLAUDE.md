# CLAUDE.md — Security Multicloud Scanner

Este arquivo é lido automaticamente pelo Claude Code no início de cada sessão.
Ele define **como o Claude deve ler o projeto, validar o system design e a
arquitetura da aplicação** antes de propor ou aplicar qualquer mudança.

> Escopo deste repositório: **somente a aplicação** (FastAPI + auditores + relatórios + IA).
> Terraform, agentes de infraestrutura AWS e skills de operação (`/waf`, `/health`,
> `/scale`, `/logs`, `/drift`, `/blue-green`) ficam em
> https://github.com/charles-rocha-code/Terraform-Multicloud_scanner — não crie IaC aqui.

---

## 1. Protocolo obrigatório de leitura do projeto

Antes de qualquer tarefa que altere código (feature, bugfix, refactor, change do
OpenSpec), execute as etapas abaixo **na ordem**. Em tarefas pequenas e
localizadas, as etapas 1.1 e 1.2 bastam, desde que você leia todos os módulos
que o arquivo alterado importa ou que o importam.

### 1.1 Contexto e contrato
Leia, nesta ordem:
1. `README.md` — features, providers, checks CIS, LLM Firewall, Attack Path Graph.
2. `.env.example` — variáveis de ambiente e o significado de `STORAGE_BACKEND`.
3. `requirements.txt`, `requirements.lock.txt`, `requirements-dev.txt`, `pytest.ini`.
4. `openspec/config.yaml` e **todas** as specs em `openspec/specs/**/spec.md`
   (são a fonte de verdade de requisitos já aceitos).
5. `openspec/changes/` (changes ativos) — não implemente nada que conflite com eles.
6. `docs/*-roadmap.md` — direção futura (CWPP, SAST/DAST, DSPM/KSPM, LangChain).

### 1.2 Mapa de código (camadas)
Leia os módulos por camada e monte mentalmente o mapa abaixo. Confirme que ele
ainda corresponde ao código real (ver seção 2.3).

| Camada | Módulos |
|---|---|
| API / borda HTTP | `api_with_mfa.py` (rotas, middlewares, CORS, rate limit, jobs assíncronos), `templates/*.html` |
| Autenticação | `auth_mfa.py` (bcrypt, TOTP, backup codes, sessões, reset de senha via SES/log) |
| Auditores — storage | `auditor.py` (S3 público), `auditor_s3_authenticated.py`, `auditor_gcs.py`, `auditor_gcs_authenticated.py`, `auditor_azure.py`, `auditor_azure_authenticated.py`, `auditor_universal.py` (dispatcher público) |
| Auditores — IAM/CSPM | `auditor_iam.py` (AWS), `auditor_iam_gcp.py`, `auditor_iam_azure.py` |
| Auditores — Kubernetes | `auditor_k8s.py`, `auditor_k8s_authenticated.py`, `cve_mapping.py`, `cve_updater.py` |
| Motor de risco | `engine_risk.py` (severidade, entropia/segredos, score 0–100, recomendações) |
| Grafo de ataque | `graph_model.py` (`GraphCollector`, nós/arestas), `graph_engine.py` (networkx, caminhos de ataque) |
| IA / LLM Firewall | `ai_analyzer.py`, `ai_tools.py` (tool calling), `rag.py` (retrieval isolado por `owner`) |
| Persistência | `local_store.py` (JSON com lock), `scan_history.py` (local ou S3), DynamoDB via `auth_mfa.py` |
| Relatórios | `generate_report.py` (PDF/DOCX executivo) |
| Transversal | `ssrf_guard.py`, `kubeconfig_guard.py` (recusa kubeconfig com `exec`/`auth-provider` antes do load), `logging_setup.py` (request id), `metrics.py` (CloudWatch ou log) |
| Testes | `tests/` (pytest + moto, sem rede) — `test_graph_local.py` na raiz é smoke manual, não roda no CI |
| CI/CD | `.github/workflows/` (`test`, `security-scan`, `code-review`, `deploy`, `reset-db`), `.deploy/security-scanner.service` |

### 1.3 Fluxos críticos (rastreie de ponta a ponta)
Para cada fluxo, siga a chamada da rota até a persistência:
1. **Login + MFA:** `/auth/login` → `auth_mfa` → sessão → `/auth/mfa/verify` → dependência de sessão MFA nas rotas protegidas.
2. **Scan:** `/scan/*` → validação Pydantic → `ssrf_guard` (quando há URL/endpoint) → auditor → `engine_risk` → `GraphCollector` → `scan_history.save_scan` → indexação RAG com `owner`.
3. **Job assíncrono:** `ThreadPoolExecutor` em `api_with_mfa.py` → estado do job (`scan-jobs/` no S3 em modo AWS) → `/scan/job/{job_id}`.
4. **IA:** `/ai/ask` e `/ai/ask-tools` → sanitização → `rag.retrieve(owner=...)` → Anthropic → tratamento de recusa.
5. **Relatório:** `/generate-report` → `generate_report.py` → `/download-report/{filename}`.

---

## 2. Validação de system design e arquitetura

Depois da leitura, valide o design contra os **invariantes** abaixo. Qualquer
violação deve ser reportada antes de implementar, e qualquer mudança nova não
pode introduzir violações.

### 2.1 Invariantes de arquitetura
- **A1 — Paridade de backends:** toda funcionalidade com estado funciona em `STORAGE_BACKEND=local` (padrão, sem AWS) e `STORAGE_BACKEND=aws`. O backend é lido em tempo de chamada (via função), não só na importação, para que `monkeypatch.setenv` funcione nos testes.
- **A2 — App stateless entre instâncias:** em produção rodam 2–4 instâncias EC2 atrás de um ALB. Nenhum estado que precise ser visto por outra instância (sessão, job, histórico, rate limit) pode viver só em memória do processo ou em disco local quando `STORAGE_BACKEND=aws`.
- **A3 — Auditores desacoplados da API:** auditores não importam FastAPI nem acessam `Request`; recebem credenciais/alvo por parâmetro e devolvem dicts serializáveis. Auditores que geram grafo herdam de `GraphCollector`.
- **A4 — Formato de finding único:** severidades são `CRITICAL | HIGH | MEDIUM | LOW` e passam por `engine_risk` para score e distribuição. Não crie escalas paralelas.
- **A5 — Credenciais efêmeras:** credenciais de nuvem/kubeconfig enviadas pelo usuário são usadas apenas durante o scan; nunca são persistidas, logadas, indexadas no RAG ou expostas ao modelo (ver spec `ai-tool-calling`).
- **A6 — Fronteira app × infra:** nenhum Terraform, ARN fixo novo ou lógica de operação de infra neste repo, exceto o que já existe nos workflows de deploy.

### 2.2 Invariantes de segurança
- **S1 — MFA obrigatório** em toda rota de dados (`/api/*`, `/scan/*`, `/ai/*`, `/generate-report`, `/download-report/*`). Rotas públicas permitidas: páginas HTML, `/health`, `/auth/*` do fluxo de login/reset.
- **S2 — SSRF:** toda URL/endpoint vindo do usuário (incluindo `server` de kubeconfig) passa por `ssrf_guard.assert_server_not_ssrf_target` antes de qualquer chamada de rede. Loopback só liberado com `STORAGE_BACKEND=local` explícito.
- **S3 — Isolamento de tenant no RAG:** `rag.retrieve` sempre chamado com `owner` do usuário da sessão. Chunks sem `owner` nunca retornam.
- **S4 — Rate limit** nas rotas de login, reset de senha e `/ai/*`, com fallback em memória se o Redis cair (sem bloquear o boot).
- **S5 — Parsing seguro:** XML com `defusedxml`; YAML com `safe_load`; nada de `eval`, `pickle` ou `shell=True` com entrada do usuário.
- **S6 — Download de arquivos:** nomes de arquivo validados contra path traversal e restritos ao diretório de relatórios do próprio usuário.
- **S7 — Segredos:** nada de chave, token ou credencial em código ou testes. Respeite `.gitleaksignore`/`.semgrepignore` sem ampliá-los para esconder achados novos.
- **S8 — Supply chain:** actions do GitHub fixadas por SHA; dependências novas entram em `requirements.txt` **e** `requirements.lock.txt`.

### 2.3 Checklist de validação (execute e reporte)
1. O mapa da seção 1.2 bate com o código? Liste módulos novos, removidos ou que mudaram de responsabilidade.
2. Para cada rota em `api_with_mfa.py`, confirme a dependência de autenticação/MFA (S1).
3. Para cada auditor, confirme A3, A4 e o uso de `ssrf_guard` quando aplicável (S2).
4. Procure estado em memória de processo usado entre requisições (dicts globais, caches, `defaultdict`) e avalie contra A2.
5. Confirme que todo caminho de escrita/leitura tem ramo `local` e `aws` (A1).
6. Confirme `owner` em todas as chamadas a `rag.index_chunk` e `rag.retrieve` (S3).
7. Procure credenciais em logs, histórico de scan, RAG ou prompts (A5, S7).
8. Rode `pytest tests/ -v` e registre falhas.
9. Identifique dívida técnica relevante: tamanho de `api_with_mfa.py` e `generate_report.py`, módulos ainda soltos na raiz (sem pacotes por camada), `reset_users.sh` quebrado (ver `docs/aws-return-roadmap.md`), modelo da Anthropic hardcoded em `ai_analyzer.py`, e qualquer arquivo legado ou doc duplicado que tenha voltado a aparecer (o histórico fica em `docs/legacy/`).
10. Compare o design atual com o alvo do README (ECS Fargate + CloudFront + DynamoDB + S3 + Secrets Manager) e aponte o que bloqueia a migração (ex.: dependência de disco local, estado em memória).

### 2.4 Formato do relatório de validação
Quando for pedido para "ler o projeto" ou "validar a arquitetura", ou antes de
um change grande, responda com:

```
## Relatório de Arquitetura — <data>
### Resumo (3–5 linhas)
### Mapa de componentes (divergências em relação ao CLAUDE.md)
### Violações de invariantes
| ID | Invariante | Arquivo:linha | Severidade | Evidência | Correção sugerida |
### Riscos de system design (escalabilidade, disponibilidade, acoplamento)
### Dívida técnica priorizada
### Resultado dos testes
### Próximos passos (propostas para OpenSpec)
```

Regras: cite sempre `arquivo:linha`; separe fato observado de inferência; não
corrija nada durante a validação, apenas reporte. Correções viram um change do OpenSpec.

---

## 3. Fluxo de mudança (OpenSpec)

Mudanças não triviais seguem o fluxo spec-driven já configurado em `.claude/`:

1. `/opsx:explore` — explorar o problema (use o protocolo da seção 1).
2. `/opsx:propose` — criar `proposal.md`, `design.md`, `tasks.md` e delta de spec. O `design.md` **deve** declarar quais invariantes da seção 2 são afetados e como são preservados.
3. `/opsx:apply` — implementar tarefa por tarefa, com testes.
4. `/opsx:sync` e `/opsx:archive` — atualizar `openspec/specs/` e arquivar.

Bugfix pequeno e isolado pode ir direto, mas ainda precisa de teste e da checagem dos invariantes tocados.

---

## 4. Comandos

```bash
./install.sh && source venv/bin/activate        # setup (cria .env a partir do .env.example)
uvicorn api_with_mfa:app --reload               # roda local, STORAGE_BACKEND=local
pytest tests/ -v                                # testes (sem rede, moto para AWS)
pytest tests/test_ssrf_guard.py -v              # um arquivo específico
semgrep scan --config=p/python --config=p/secrets --config=p/security-audit --exclude=venv --exclude=docs
```

Nunca rode `reset_users.sh` ou os workflows `deploy`/`reset-db` sem pedido
explícito: eles alteram ambiente (e hoje o reset está quebrado nos dois modos —
ver `docs/aws-return-roadmap.md`).

---

## 5. Convenções de código

- Python 3.12, type hints, Pydantic v2 (`field_validator`) para entrada de API.
- Logs via `logging_setup.get_logger`, sempre com request id; nunca `print`.
- Métricas via `metrics.put_metric` / `timed_metric`.
- Comentários e docstrings em português, explicando o **porquê** (padrão já usado no repo).
- Todo teste novo vai em `tests/test_*.py`, sem rede e sem credencial real; mocke `embed_text` e chamadas à Anthropic.
- Toda feature de segurança (guard, sanitização, isolamento) precisa de teste negativo (o ataque é bloqueado).
- Não adicione arquivos `*_OLD`, `*_backup` ou docs duplicados; remova em vez de copiar.

---

## 6. O que não fazer

- Não desabilitar MFA, rate limit, SSRF guard ou sanitização "para testar".
- Não persistir nem logar credenciais de scan.
- Não tornar `STORAGE_BACKEND=aws` obrigatório para rodar localmente.
- Não mover lógica de auditor para dentro de rotas FastAPI.
- Não alterar ARNs, buckets ou nomes de recursos AWS nos workflows sem pedido explícito.
- Não marcar uma tarefa como concluída com testes falhando.
