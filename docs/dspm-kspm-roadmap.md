# Roadmap de Implantação — CWPP (finalização), DSPM, KSPM

Análise do ambiente em 2026-09-04, feita lendo o código atual (não a partir
de memória de sessões anteriores). Documento de análise e roadmap.

> **Atualização 2026-09-05**: Fase K1 (RBAC namespaced) e Fase D2
> (content-scan de ConfigMap) foram implementadas, testadas, validadas ao
> vivo contra um cluster kind real e mergeadas em `main` (PR #5, commit
> `1b24fd7`). Detalhe de cada uma nas seções "Parte 2 — DSPM" e "Parte 3 —
> KSPM" abaixo. D1, K2, K3, D3 e o Trivy (CWPP Fase 1) continuam pendentes.

## Estado do ambiente agora

| Item | Estado |
|---|---|
| Branch | `main` (mergeado via PR #5 a partir de `local-dev-no-aws`) |
| Testes | 79 passed (`pytest tests/`) — 10 novos desde a análise original |
| Commits relevantes | `631a4f3` (NetworkPolicy allow-all + dead code), `901c652` (docs CWPP), `fffb564` (K1 + D2), `f3eeaa8` (fix gitleaksignore), `1b24fd7` (merge PR #5 em main) |
| App local | sobe via `uvicorn api_with_mfa:app`, `STORAGE_BACKEND=local`, sem credencial AWS |
| Ambiente AWS | **descontinuado** — `deploy.yml` falha por design (sem role IAM pra assumir), não é incidente |
| `docs/cwpp-roadmap.md` | Fase 1 (Trivy) ainda pendente; Fase 2 (NetworkPolicy) **concluída** |

---

## TL;DR — os 3 pilares

| Pilar | O que já existe (verificado no código) | Maior gap | Prioridade |
|---|---|---|---|
| **CWPP** | Postura de configuração de workload K8s completa (5 checks) | Scan de vulnerabilidade de imagem (Fase 1 do `cwpp-roadmap.md`, ainda não implementada) | Mantém a do doc anterior |
| **DSPM** | Motor de classificação + scan de segredo em conteúdo (`engine_risk.py`), usado nos 4 auditores de storage **e agora também no ConfigMap do K8s** (Fase D2 ✅) | Zero detecção de PII/dado pessoal — e o relatório já promete LGPD/GDPR sem isso existir | D1 ainda alta |
| **KSPM** | RBAC (cluster **e agora namespaced**, Fase K1 ✅), workload security, secrets, exposição de rede, auth anônima | Sem mapeamento CIS Kubernetes Benchmark, sem checagem de Pod Security Standards | K2/K3 ainda altas |

---

## Parte 1 — CWPP: o que falta finalizar

Sem repetir o `docs/cwpp-roadmap.md` (continua valendo pro detalhe técnico),
resumo do que mudou:

- ✅ **Fase 2 concluída** — `_check_network_exposure` agora detecta
  `NetworkPolicy` allow-all (`auditor_k8s_authenticated.py:314`), 3 testes
  novos, mergeado.
- ✅ **Limpeza de dead code concluída** — `auth_mfa_backup.py`,
  `auth_mfa_COM_PERSISTENCIA.py`, `api_backup.py`, `files/`, e
  `get_system_stats()` removidos.
- ⏳ **Fase 1 (Trivy) continua pendente** — é o item de maior esforço e
  ainda não tem código. Ver S1/S2 no `cwpp-roadmap.md` pra checklist
  completo (feature flag `IMAGE_SCAN_ENABLED`, dependência cross-repo pro
  binário chegar em produção).
- **Melhoria nova, encontrada nesta análise**: o `README.md` já lista
  Fase 3 (CIEM) e os itens "fora de escopo" como decisão consciente — nada
  muda aí, só reforço que continuam corretos.

Nada novo a decidir na Parte 1 além do que já estava registrado — ela entra
aqui só pra fechar o quadro antes de DSPM/KSPM.

---

## Parte 2 — DSPM

### Correção de premissa importante

O `docs/cwpp-roadmap.md` anterior dizia que DSPM "não existe, custo de scan
de conteúdo é ordem de magnitude maior". **Isso estava errado.** Existe um
motor de classificação e scan de conteúdo real em `engine_risk.py`, usado
por `auditor.py`, `auditor_gcs.py`, `auditor_azure.py`,
`auditor_s3_authenticated.py`, `auditor_gcs_authenticated.py` e
`auditor_azure_authenticated.py`:

- `classify_severity(key)` (`engine_risk.py:130`) — classifica por
  extensão (`.env`, `.pem`, `.sql`, `.bak`...) e por padrão no nome
  (`password`, `secret`, `credentials`, `token`...).
- `should_scan_content()` + `scan_content_for_secrets()`
  (`engine_risk.py:101-125`) — baixa arquivos pequenos (≤50KB, cap de 300
  por scan) que não têm "cara de sensível" pelo nome e procura, no
  **conteúdo real**: chave AWS (`AKIA...`), chave privada PEM, JWT, padrão
  de API key, e token de alta entropia (Shannon ≥ 4.0 bits/char) — pega um
  segredo escondido dentro de um `notas.txt` que passaria despercebido só
  olhando o nome.

Isso é DSPM de verdade — só que **escopado a segredos/credenciais**, não a
dado pessoal. Achado que muda o desenho da Parte 2.

### O gap real: zero detecção de PII, e o relatório já promete o que não entrega

`generate_report.py:1052` já tem uma linha de compliance:
```python
out.append({'name':'LGPD / GDPR','status':'⚠️ REVISAR','issues':'Verificar classificação de dados'})
```
E a seção de recomendações (`engine_risk.py:356-374`) já sugere "Implementar
Data Loss Prevention (DLP)" e "tags de classificação de dados" — como texto
estático, não como algo que o motor realmente verifica. Ou seja: o produto
**menciona** LGPD/GDPR e DLP no relatório executivo, mas nenhum dos 4
padrões de `SECRET_CONTENT_PATTERNS` (`engine_risk.py:82-87`) é CPF, CNPJ,
email, telefone ou cartão de crédito — é 100% voltado a credencial técnica.
Mesmo tipo de lacuna encontrada antes no CWPP (produto promete mais do que
o código faz), agora no pilar de dados.

### Gap secundário: cobertura inconsistente entre providers

`_check_secrets_configmaps` (`auditor_k8s_authenticated.py:277`) só olha o
**nome da chave** de um ConfigMap (`SENSITIVE_KEY_PATTERNS`, lista local
diferente de `engine_risk.py`) — nunca aplica o mesmo scan de
regex/entropia que os auditores de storage já rodam. Um ConfigMap com uma
chave chamada `app-config` cujo valor contém uma `AKIA...` embutida passa
invisível no K8s, mas seria pego se o mesmo conteúdo estivesse num arquivo
`.txt` no S3. Inconsistência real entre providers do mesmo produto.

### Fases

**Fase D0 — decisão prévia**: suavizar a linha de LGPD/GDPR do relatório
até D1 existir, ou já tratar como prioridade por causa da promessa
existente? Recomendo a segunda — a mesma lição do CWPP (não deixar o
relatório prometer o que o motor não verifica) se aplica aqui.

**Fase D1 — detecção de PII no conteúdo (extensão de `engine_risk.py`)**
- Adicionar padrões novos a `SECRET_CONTENT_PATTERNS` (ou lista irmã
  `PII_CONTENT_PATTERNS` pra não misturar severidade/motivo): CPF
  (`\d{3}\.?\d{3}\.?\d{3}-?\d{2}`, com validação de dígito verificador pra
  reduzir falso-positivo), CNPJ, email, cartão de crédito (regex + Luhn).
- Reusa toda a infraestrutura que já existe (`should_scan_content`, cap de
  tamanho/quantidade, chamada já cabeada nos 6 auditores de storage) —
  esforço baixo-médio porque a parte cara (decidir quando baixar, quanto
  baixar, onde plugar) já está pronta.
- Severidade sugerida: MEDIUM/HIGH pra não inflar tudo pra CRITICAL —
  1 CPF solto num CSV é diferente de um dump de milhares.
- Critério de saída: um bucket de teste com um CSV contendo CPFs reais
  (fixture, não dado real) gera finding `category="PII Exposure"`.

**Fase D2 — levar o mesmo motor pro K8s — ✅ concluída (2026-09-05)**
- `_check_secrets_configmaps` (`auditor_k8s_authenticated.py:277`) agora
  chama `scan_content_for_secrets()` no **valor** de cada chave de
  ConfigMap, não só no nome — fecha a inconsistência entre providers.
  Não precisou esperar D1: rodou com os padrões precisos que já existiam
  (AWS key, PEM, JWT, api_key), sem depender de regex de PII nova.
- **Achado só na validação ao vivo, não nos testes unitários**: rodando
  contra um cluster kind real, o fallback de entropia (token ≥20 chars,
  Shannon ≥4.0 bits/char) sozinho gerou 33 falso-positivos em ConfigMap de
  sistema — `kube-root-ca.crt` (certificado PEM, existe em todo namespace
  por padrão do Kubernetes) e regras do Prometheus/kubelet (JSON denso).
  String sintética pequena de teste unitário não reproduz esse padrão.
- Corrigido com um parâmetro novo em `engine_risk.scan_content_for_secrets`:
  `include_entropy_fallback` (default `True`, não muda os 6 call-sites de
  storage existentes). K8s passa `include_entropy_fallback=False` —
  mantém os padrões precisos, desliga só o fallback ruidoso.
- Resultado validado: 2ª rodada do scan contra o mesmo cluster foi de 148
  findings (33 falso-positivo) pra 115 findings (**zero** falso-positivo).
- 10 testes novos (`tests/test_k8s_configmap_content_scan.py`,
  `tests/test_secret_detection.py`), suíte completa 79 passed.
- Commits: `fffb564` (implementação + achado), `f3eeaa8` (fix CI
  gitleaksignore pras fixtures de teste), mergeados em `main` via PR #5.

**Fase D3 — mais distante, avaliar depois**: ingestão de tags de
classificação já existentes (S3 object tags, GCS labels, Azure Blob
metadata) pra correlacionar com achados, em vez de só recomendar que o
usuário crie essas tags. Esforço maior — API design novo, não é extensão
de código existente como D1/D2.

---

## Parte 3 — KSPM

### O que já existe (sólido, não precisa refazer)

`auditor_k8s_authenticated.py` cobre: workload security (privileged,
hostNetwork/PID/IPC, root, resource limits), RBAC de cluster, secrets em
ConfigMap/env var, exposição de rede (Service + NetworkPolicy, agora com
detecção de allow-all), e auth anônima na API server. É postura de
configuração real, não superficial.

### Gap 1 — RBAC namespaced nunca é auditado — ✅ fechado (2026-09-05)

Confirmado no código: `_check_rbac` (`auditor_k8s_authenticated.py:217`)
só chamava `self.rbac.list_cluster_role()` e
`list_cluster_role_binding()` — **nunca** `list_namespaced_role()` ou
`list_namespaced_role_binding()`. Um `Role` escopado a um namespace com
`verbs: ["*"]` sobre `secrets` (permite ler todos os segredos daquele
namespace) é tão perigoso quanto um `ClusterRole` wildcard, e era
invisível pro scanner. Foi o maior blind spot de segurança encontrado
nesta análise inteira — não era feature faltando, era lacuna de detecção
real. Fechado pela Fase K1 abaixo.

### Gap 2 — sem mapeamento pro CIS Kubernetes Benchmark

Os 3 auditores de IAM (AWS/GCP/Azure) têm coluna explícita "CIS Control"
no README, com número de controle por finding. K8s não tem — confirmei
que não existe nenhuma referência a "CIS Kubernetes" em `generate_report.py`
nem em `cve_mapping.py`. Os findings de K8s existem e são bons, mas não
citam nenhum control-ID, diferente de todo o resto do produto. Gap de
paridade, não de detecção.

### Gap 3 — sem checagem de Pod Security Standards / admission control

Nenhuma referência a `pod-security.kubernetes.io/enforce` (label de
namespace que ativa PSS nativo do K8s 1.23+), nem a OPA/Gatekeeper/Kyverno
instalado no cluster. O produto teoricamente já detecta os sintomas
(privileged, root, hostNetwork via `_check_workload_security`), mas nunca
verifica se existe uma *política* impedindo isso de acontecer de novo —
é a diferença entre reportar o incêndio e checar se o alarme existe.

### Fases

**Fase K0 — decisão prévia**: qual gap fechar primeiro. Recomendo K1
primeiro (é o mais barato e o mais grave em termos de segurança real).

**Fase K1 — auditar Role/RoleBinding namespaced — ✅ concluída (2026-09-05)**
- `_check_namespaced_rbac(namespaces)` novo (`auditor_k8s_authenticated.py`,
  logo após `_check_rbac`): itera `list_namespaced_role(ns)` por
  namespace e aplica a mesma lógica de wildcard já usada pra `ClusterRole`
  (`"*" in verbs and "*" in resources`). Role perigoso + binding entra no
  Attack Path Graph Map como nó de alto valor (`role/{ns}/{nome}`), mesmo
  padrão do check de `ClusterRole`.
- Mesmo padrão de finding, categoria "RBAC", `resource_type="Role"` pra
  diferenciar de `ClusterRole` no relatório.
- Validado ao vivo contra um cluster kind real: rodou sem erro em 8
  namespaces, zero falso-positivo (nenhum Role namespaced perigoso existe
  de fato nesse cluster de lab — confirma que o check não gera ruído em
  infra real, mesmo sem uma fixture deliberada de Role malicioso).
- 4 testes novos (`tests/test_k8s_namespaced_rbac.py`): wildcard gera
  CRITICAL, Role restritivo não gera finding, binding perigoso entra no
  grafo, falha de permissão (403) não quebra o scan.
- Commit `fffb564`, mergeado em `main` via PR #5 (commit `1b24fd7`).

**Fase K2 — mapear findings pro CIS Kubernetes Benchmark (esforço médio,
trabalho de catalogação)**
- Adicionar coluna `cis_control` no dict de cada finding (mesmo padrão que
  `cve_mapping.py` já faz pra CVE de K8s), com o número de controle da
  versão vigente do CIS Kubernetes Benchmark (v1.9 ou mais recente —
  confirmar antes de começar) pra cada um dos ~10 tipos de finding que já
  existem.
- Atualizar `README.md` com a tabela "Kubernetes — CIS Kubernetes
  Benchmark" no mesmo formato das tabelas de IAM já existentes.
- Não é código complexo — é decidir o número de controle certo pra cada
  finding e documentar. Maior parte do esforço é pesquisa, não
  implementação.

**Fase K3 — detecção de Pod Security Standards (esforço médio-alto,
avaliar depois)**
- Novo check: ler o label `pod-security.kubernetes.io/enforce` de cada
  namespace (`core.read_namespace(ns).metadata.labels`) — se ausente,
  finding MEDIUM "Namespace sem Pod Security Standard aplicado".
- Detecção de OPA/Gatekeeper/Kyverno instalado: checar se existe
  `ConstraintTemplate`/`ClusterPolicy` CRD no cluster (`list_custom_
  resource_definition` filtrando por grupo da API) — mais complexo, exige
  lidar com CRDs dinâmicas em vez dos tipos nativos que o client-go já
  tipa. Fica pra depois de K1/K2 confirmarem valor.

**Fora de escopo por agora (mesma razão já documentada no
`cwpp-roadmap.md` pra host hardening)**: etcd encryption at rest, flags do
API server além de `--anonymous-auth` (ex.: `--audit-log-path`), e
inventário de admission controllers habilitados — tudo isso exige acesso
a flags de processo do control plane que a API do Kubernetes não expõe;
precisaria de SSH/exec direto nos nós, mudança de modelo de credencial
igual à já registrada como fora de escopo no CWPP.

---

## Cronograma consolidado

| Sprint | Entregável | Depende de | Esforço | Status |
|---|---|---|---|---|
| **K1** | Role/RoleBinding namespaced no `_check_rbac` | — | Baixo | ✅ Concluído (`fffb564`) |
| **D2** | Reusar `engine_risk` nos ConfigMaps do K8s | — (não precisou de D1) | Baixo | ✅ Concluído (`fffb564`) |
| **D1** | Regex de PII em `engine_risk.py` + testes | — | Baixo-médio | Pendente |
| **CWPP S1/S2** | Scan de imagem via Trivy (já detalhado no `cwpp-roadmap.md`) | — | Médio (+ dependência cross-repo) | Pendente |
| **K2** | Mapeamento CIS Kubernetes Benchmark | K1 ✅ (mesmos findings) | Médio (catalogação) | Pendente |
| **K3** | Pod Security Standards / admission control | K1 ✅, K2 | Médio-alto | Pendente |
| **D3** | Ingestão de tags de classificação existentes | D1, D2 ✅ | Alto | Pendente |

K1 e D2 já mergeados em `main` (PR #5, commit `1b24fd7`). D1 segue
independente do Trivy — pode correr em paralelo, cada um seu PR.

## Recomendação de prioridade

1. ~~**K1**~~ — ✅ concluído. Fechou o gap de segurança mais grave
   encontrado (Role namespaced invisível).
2. ~~**D2**~~ — ✅ concluído (junto com K1, no mesmo commit). Achado extra
   na validação ao vivo (falso-positivo de entropia) corrigido antes do
   merge.
3. **D1** (próximo) — reusa infraestrutura pronta, fecha a divergência
   entre o que o relatório promete (LGPD/GDPR) e o que o motor realmente
   verifica — mesmo tipo de correção já priorizada no CWPP.
4. **CWPP Fase 1 (Trivy)** — mantém a prioridade já definida no
   `cwpp-roadmap.md`, maior esforço mas maior gap de cobertura.
5. **K2** — trabalho de catalogação, sem bloqueio técnico, fecha paridade
   com os outros 3 providers do produto.
6. **K3/D3** — ficam registrados pra não serem re-propostos do zero, mas
   exigem decisão de arquitetura maior (CRDs dinâmicas, ingestão de tags
   externas) que este documento discute mas não resolve sozinho.
