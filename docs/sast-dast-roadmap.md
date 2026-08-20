# Roadmap de SAST/DAST na esteira de CI/CD — security-multicloud-scanner

Documento de análise e roadmap. Não implementado, não commitado — decisão
pendente do usuário sobre se e por onde começar.

## TL;DR

| # | Item | Veredito | Onde |
|---|---|---|---|
| 1 | Secret scanning (Gitleaks, CLI) | **Sim, agora** | Job novo, non-blocking |
| 2 | SAST (Semgrep, CLI) | **Sim, agora** | Job novo, non-blocking |
| 3 | Dependabot — automação (`dependabot.yml`) | **Sim, agora** | Novo arquivo, zero código Python |
| 4 | DAST (ZAP baseline) | **Sim, mas depois (fase 3)** | App local sem AWS, non-blocking |
| 5 | Code scanning nativo do GitHub (CodeQL) | **Avaliar depois** | Repo é privado — pode depender de plano pago |

Achado que muda o desenho: o repo é **privado**
(`gh api repos/.../{owner}/{repo}` → `"private": true`). Os recursos de
segurança *nativos da plataforma* GitHub (CodeQL default setup, secret
scanning avançado) para repositório privado normalmente exigem GitHub
Advanced Security — recurso pago fora de conta Enterprise, e não confirmei o
plano desta conta. Ferramentas **CLI rodando como job normal do Actions**
(Semgrep, Gitleaks, ZAP) não dependem disso — só consomem minutos de Actions,
que o repo já usa hoje via `test.yml`/`code-review.yml`. Por isso o roadmap
prioriza a via CLI e trata os recursos nativos do GitHub como opcionais,
condicionados a confirmar o plano da conta primeiro.

---

## Correção de premissas

### 1. "`code-review.yml` já cobre isso"

Não cobre. É a Claude Code Action (plugin `code-review`) — foco documentado
em correção, simplificação e reuso, sem base de regras CWE/OWASP nem
detecção de padrão de vulnerabilidade conhecida (ex.: não é treinado pra
apontar "esse `eval()` é injeção", só o faria se um revisor humano também
notasse). É complementar a um SAST de verdade, não substituto.

### 2. "DAST contra a app real nunca foi viável aqui"

Era verdade até a sessão anterior. Antes da migração pra
`STORAGE_BACKEND=local`, subir a aplicação de verdade em CI exigia
credenciais AWS reais (DynamoDB/S3) como secret do GitHub Actions — e usar
credencial de produção só pra um scan de PR é o tipo de risco que
provavelmente seria rejeitado com razão. Com `STORAGE_BACKEND=local`, a app
sobe com `uvicorn api_with_mfa:app` sem nenhum segredo AWS, o que torna DAST
prático pela primeira vez.

### 3. "SAST/DAST tem que ser bloqueante desde o dia 1"

`test.yml` já documenta a filosofia oposta pro que existe hoje: roda em todo
PR, aparece como check visível, mas não bloqueia merge até acumular tempo de
"check verde" — aí sim promovido via branch protection (mesmo racional já
usado pro Checkov em `terraform.yml`, citado no comentário do próprio
arquivo). Um scanner novo rodando pela primeira vez contra um código que
nunca foi escaneado (incluindo arquivos legados como `api.py`/`api_backup.py`,
candidatos a código morto) provavelmente gera ruído inicial alto — bloquear
merge nesse momento travaria trabalho não relacionado.

---

## Fases

### Fase 0 — Decisões prévias (sem escrever código)

1. **Non-blocking por quanto tempo?** Recomendo o mesmo padrão do `test.yml`
   atual: non-blocking até acumular um período de baseline "verde", promover
   depois via branch protection (Settings → Branches), não por mudança de
   código no workflow.
2. **Confirmar o plano da conta GitHub** (Free/Team/Enterprise) — define se
   CodeQL default setup e secret scanning nativo entram no roadmap sem custo
   extra, ou se ficam de fora e a via CLI (Semgrep/Gitleaks) é o caminho
   permanente, não só o inicial.
3. **Escopo do DAST**: baseline scan (passivo — só observa respostas HTTP,
   não tenta explorar) versus full active scan (tenta explorar de verdade).
   Recomendo **só baseline** por ora — um active scan contra `/scan/public`
   correria o risco de disparar chamadas HTTP reais a buckets/hosts públicos
   de terceiros a partir do runner do GitHub, e de poluir `local_data/` ou
   acionar o rate limiter de propósito.

Critério de saída: as 3 decisões acima registradas, sem nenhuma linha de
workflow nova.

### Fase 1 — SAST + Secret scanning (Semgrep + Gitleaks)

- Job novo (workflow separado, ex. `security-scan.yml`, ou seção nova em
  `test.yml` — a decidir na Fase 0 se deve seguir a filosofia de "gates
  separados, não misturar" já documentada no comentário do `test.yml`).
- `semgrep --config auto` (ou um config mais específico pra Python/FastAPI,
  a definir) + `gitleaks detect --source .` — ambos CLI, sem dependência de
  recurso pago do GitHub.
- Non-blocking desde o início (mesmo espírito do soft-fail já usado em
  Checkov no `terraform.yml` do outro repo, citado como referência no
  `test.yml` deste).

Critério de saída: roda em todo PR, aparece como check, não bloqueia merge.
Rollback: remover o job, zero impacto no resto da esteira.

### Fase 2 — Dependabot: de alerta passivo pra automação

Hoje os `vulnerability-alerts` já estão ativos no repo (confirmado via API),
mas sem `dependabot.yml` — os alertas só aparecem no painel do GitHub, e a
correção depende de alguém olhar manualmente (foi assim que o fix de
Pillow/cryptography/python-multipart/urllib3 do commit `5aaf769` aconteceu:
reativo, não automatizado).

- `dependabot.yml`: `package-ecosystem: pip`, branch `main`, schedule
  semanal — abre PR automático quando uma dependência tem CVE, não muda
  nada além disso (não roda código, não precisa de novo secret).

Critério de saída: primeiro PR automático de segurança do Dependabot
aparecendo no repo.

### Fase 3 — DAST (ZAP baseline contra a app local, sem AWS)

- Workflow novo: sobe `uvicorn api_with_mfa:app` com `STORAGE_BACKEND=local`
  (zero segredo AWS, mesma validação já feita na sessão anterior) em
  background, roda `zaproxy/action-baseline` contra `http://127.0.0.1:8000`.
- Fase 3a (primeiro escopo): só rotas públicas sem sessão —
  `/login`, `/health`, e a superfície de `/scan/public` com um alvo
  inofensivo. Rotas atrás de MFA (`/dashboard`, `/api/*`) ficam de fora
  deste primeiro escopo — cobri-las exigiria automatizar registro + MFA +
  cookie de sessão dentro do próprio workflow antes do ZAP rodar, escopo
  maior que decidir depois (Fase 3b, opcional).
- Non-blocking.

Critério de saída: relatório do ZAP anexado ao run do Actions, non-blocking,
sem tocar nas rotas autenticadas ainda.

### Fase 4 — Promover pra bloqueante (opcional, mais pra frente)

Só depois de cada scanner acumular tempo de baseline verde/estável — critério
igual ao já usado hoje pro `test.yml`: branch protection exigindo o check,
não mudança no arquivo do workflow.

---

## O que não fazer

- Não rodar DAST *active scan* (só baseline/passivo) contra `/scan/*` — risco
  de tráfego real saindo do runner do GitHub contra hosts de terceiros.
- Não habilitar CodeQL default setup / secret scanning nativo do GitHub antes
  de confirmar se o plano da conta cobre isso pra repositório privado sem
  custo — a via CLI (Semgrep/Gitleaks) já cobre o mesmo terreno sem essa
  dependência.
- Não misturar o job de SAST/DAST dentro do `test.yml` sem decidir isso
  antes na Fase 0 — o próprio `test.yml` documenta a filosofia de manter
  gates com propósitos diferentes em arquivos separados.
- Não tornar nenhum dos scanners bloqueante no primeiro PR em que aparecer —
  gera ruído contra código legado nunca escaneado antes (`api.py`,
  `api_backup.py`, etc.) e trava trabalho não relacionado.

## Checkpoint antes de começar

1. Non-blocking por quanto tempo antes de considerar promover a bloqueante?
2. Alguém confirma o plano da conta GitHub, pra saber se CodeQL/secret
   scanning nativo entram no roadmap ou ficam fora por custo?
3. DAST cobre só rotas públicas na Fase 3, ou vale já investir em contexto
   autenticado (registro + MFA + cookie dentro do workflow) desde o início?
