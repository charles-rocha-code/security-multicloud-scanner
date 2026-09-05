# Roadmap CWPP — security-multicloud-scanner

Documento de análise e roadmap. Decisão pendente do usuário sobre por onde
começar no que ainda falta.

> **Atualização 2026-09-04**: Fase 2 (parsing de NetworkPolicy allow-all) e a
> limpeza de código morto citada abaixo foram implementadas e mergeadas
> (commits `631a4f3`, `901c652`). Ver `docs/dspm-kspm-roadmap.md` pro roadmap
> consolidado de DSPM/KSPM e pro que resta do CWPP (Fase 1 — Trivy).

## TL;DR

| # | Pilar CWPP (Gartner/NIST) | Cobertura hoje | Gap | Esforço | Veredito |
|---|---|---|---|---|---|
| 1 | Vulnerability management (imagem/host) | CVE mapping estático de container-escape do K8s control-plane (`cve_mapping.py`, cache NVD semanal) — **não** escaneia a imagem que o pod roda | Scan real de imagem (CVE nos pacotes/camadas) | Baixo-médio | **Sim, próximo** |
| 2 | Network segmentation | ~~Só existência de `NetworkPolicy`~~ Parsing de regra allow-all implementado | — | — | **✅ Concluído** (commit `631a4f3`, `tests/test_k8s_network_policy_allow_all.py`) |
| 3 | Secrets dentro da imagem | Só secret em manifest (ConfigMap/env var) | Secret vazado dentro das camadas da imagem | Baixo (reusa o pull do item 1) | **Sim, junto do item 1** |
| 4 | CIEM fino (permissão concedida vs usada) | Checks binários (`AdministratorAccess`? wildcard?) + attack path graph | Access Analyzer / last-accessed real | Médio | Avaliar depois |
| 5 | System integrity / host hardening / app control | Nada — produto nunca toca host/VM | Exigiria agente ou scan agentless via SSM | Alto | **Não agora** |
| 6 | Runtime protection / EDR (comportamento em tempo real) | Nada | Componente always-on (Falco/eBPF) monitorando cluster | Alto | **Não agora** |
| 7 | Serverless (Lambda/Cloud Functions) | Nada — produto audita só S3/GCS/Blob/IAM/K8s | Novo tipo de recurso inteiro | Médio-alto | **Não agora** |
| 8 | DSPM (classificação de dado sensível) | Só exposição (ACL pública), não conteúdo | Scan de conteúdo pra PII/segredo | Alto | Avaliar depois |

Achado que muda o desenho: o README já se descreve como **CWPP**
(`README.md:3`), mas dos 4 pilares clássicos de CWPP — vulnerability
management, network segmentation, system integrity/app control, runtime
protection — o produto hoje só entrega o primeiro, e só na camada de
**configuração** (RBAC, pod spec, exposição de Service), não na camada de
**artefato** (a imagem em si tem CVE?) nem na camada de **comportamento**
(o que o workload faz depois de rodando?). Isso é CSPM com checks de
workload-configuration, não CWPP completo. Não é um erro pontual pra
corrigir — é a lacuna real que este roadmap endereça.

---

## Correção de premissa: o que existe hoje já é bom, só está mal rotulado

Não é que falte tudo. `auditor_k8s_authenticated.py` já cobre bem a fatia de
configuração:

- `_check_workload_security` (`auditor_k8s_authenticated.py:143`) — privileged,
  hostNetwork/PID/IPC, root, sem resource limits
- `_check_rbac` (`:217`) — ClusterRole com wildcard, bindings perigosos
- `_check_secrets_configmaps` (`:277`) — secret em ConfigMap plaintext
- `_check_network_exposure` (`:314`) — Service LoadBalancer/NodePort,
  namespace sem NetworkPolicy
- `_check_anonymous_auth` (`:345`) — acesso anônimo à API server

Isso é postura de configuração de workload (o "W" do CWPP, mas só a parte
estática) — sólido, e é o que já alimenta o Attack Path Graph Map pro
provider K8s. O gap real é que **nenhum desses checks olha pra dentro da
imagem que o container roda** — `c.image` é lido só pra listar o container,
nunca pra escanear.

---

## Fases

### Fase 0 — Decisões prévias (sem escrever código)

1. **Entrar em vulnerability scanning de imagem muda o modelo do produto.**
   Hoje todo scanner é "chama API do provider com a credencial que o usuário
   colou na tela, tudo síncrono". Escanear imagem implica *pull* de
   registry (potencialmente privado — precisa de credencial de registry
   além da de kubeconfig) e execução de um binário externo (Trivy) contra
   camadas baixadas. É mais próximo do que o `sast-dast-roadmap.md` já fez
   pra CI (`docs/sast-dast-roadmap.md`) do que do resto do scan atual — vale
   ler esse doc antes, mesmo racional de non-blocking se a ferramenta
   falhar/não estiver instalada.
2. **Onde o resultado entra no schema de finding?** Reusar
   `cve_mapping.py` (já existe `_K8S_CVE_INDEX` pra CVE de control-plane) ou
   campo novo (`category="Image Vulnerability"`) nos findings do próprio
   `auditor_k8s_authenticated.py`? Recomendo o segundo — o primeiro é sobre
   CVE de *comportamento do Kubernetes*, não de *pacote dentro da imagem do
   usuário*, categorias diferentes mesmo compartilhando o mesmo cache NVD.
3. **Limite de tempo por scan.** Imagens grandes tornam Trivy lento; um
   `POST /scan/k8s` que hoje responde em segundos não pode virar minutos sem
   aviso. Decisão: cap de N imagens únicas por scan (dedup por
   digest/tag) + timeout por imagem, com finding informativo
   ("scan de imagem pulado: timeout") em vez de falhar o scan inteiro —
   mesmo padrão já usado em `_safe`/`try/except ApiException` no arquivo.

Critério de saída: as 3 decisões acima registradas, zero linha de código
nova.

### Fase 1 — Scan de vulnerabilidade de imagem (Trivy, agentless)

- Depende da Fase 0. Reusa a enumeração de pods que `_check_workload_security`
  já faz (`auditor_k8s_authenticated.py:162`) — mesmo loop, sem nova chamada
  à API do cluster.
- `_check_image_vulnerabilities(namespaces)` novo: coleta `c.image` únicos
  de todos os pods já visitados, roda `trivy image <ref> --format json
  --severity HIGH,CRITICAL` via `subprocess` (binário não instalado hoje —
  entra em `install.sh` ou é detectado e reportado como indisponível sem
  quebrar o scan), converte cada CVE em um finding (`category="Image
  Vulnerability"`, severidade = a do Trivy, `resource_type="Container
  Image"`).
- Ganha de graça o pilar 3 (secrets na imagem): `trivy image` também roda
  detecção de segredo nas camadas por padrão — sem trabalho extra, é a
  mesma chamada.
- Critério de saída: uma imagem propositalmente desatualizada num cluster
  de teste gera finding real com CVE + severidade; scan continua normal
  (com finding informativo, não erro) quando Trivy não está no `PATH`.
- Rollback: remover a chamada ao método novo do `run()`, zero impacto no
  resto do auditor.

### Fase 2 — Network segmentation, parsing de regra (extensão barata)

- Mesmo método, `_check_network_exposure` (`auditor_k8s_authenticated.py:314`):
  hoje só verifica `if not policies.items` — um namespace com uma
  `NetworkPolicy` que tem `podSelector: {}` e `ingress: [{}]` (allow-all
  disfarçado de "tem policy") passa despercebido porque a lista não está
  vazia.
- Adicionar: pra cada policy existente, checar se `pod_selector.match_labels`
  é vazio E não há `ingress`/`policyTypes` restringindo — se sim, finding
  HIGH "NetworkPolicy presente mas equivalente a allow-all", em vez do
  atual silêncio (que hoje é tratado como "protegido" só por existir).
- Esforço muito baixo — mesmo arquivo, mesmo padrão de finding, sem
  dependência nova.

### Fase 3 — CIEM fino (avaliar, não implementar ainda)

- IAM Access Analyzer / `generate-service-last-accessed-details` (AWS) pra
  achar permissão *concedida mas nunca usada* — vai além do que os checks
  binários atuais fazem (`AdministratorAccess`? wildcard?).
- Motivo de não entrar direto no roadmap: a API de last-accessed é
  assíncrona (gera job, exige polling) — muda o modelo síncrono do scan
  atual mais do que a Fase 1. Decisão do usuário se vale abrir esse
  precedente agora ou só quando outro caso de uso já exigir polling.

### Fora de escopo por agora (decisão explícita, não esquecimento)

- **Runtime protection / EDR** (pilar 4) — exige componente always-on
  rodando dentro do cluster monitorado (Falco, eBPF), com o próprio
  monitor virando superfície de ataque e item de manutenção contínua. Foge
  do modelo "scanner sob demanda com credencial que o usuário cola na
  tela" que o produto inteiro segue hoje. Não é "não pensamos nisso" — é
  incompatível com a arquitetura atual sem uma decisão maior sobre
  manter um agente rodando 24/7 no ambiente do cliente.
- **System integrity / host hardening / application control** (pilar 3
  fora de imagem) — produto nunca teve credencial de host/VM (SSH, SSM),
  só de control-plane de provider. Adicionar exigiria um tipo de
  credencial inteiramente novo no fluxo de scan.
- **Serverless (Lambda/Cloud Functions)** — nenhum auditor cobre esse tipo
  de recurso hoje; seria um `auditor_lambda.py` do zero, não uma extensão.
- **DSPM de conteúdo** (achar PII dentro de objetos S3/GCS/Blob, não só
  ACL pública) — custo de scan de conteúdo (baixar e classificar cada
  objeto) é ordem de magnitude maior que o scan de metadata atual.

---

## Recomendação de prioridade

1. **Fase 1** (scan de imagem via Trivy) — maior gap real entre o que o
   README promete (CWPP) e o que o produto entrega hoje; esforço
   baixo-médio; reusa a enumeração de pods que já existe.
2. **Fase 2** (parsing de regra de NetworkPolicy) — esforço muito baixo,
   mesmo arquivo, resolve um falso-negativo real (policy que existe mas não
   protege nada).
3. Enquanto Fase 1/2 não saem, considerar ajustar a frase de abertura do
   README (`README.md:3`) pra não prometer os 4 pilares — ex. "CSPM com
   checks de configuração de workload" — ou aceitar o gap conscientemente
   até a Fase 1 fechar. Ambas são decisão do usuário, não uma correção que
   eu deva aplicar sozinho.
4. Fase 3 e os itens "fora de escopo" ficam registrados aqui pra não serem
   re-propostos do zero, mas não entram no roadmap imediato — cada um
   exige uma decisão de arquitetura maior que cabe nesse documento discutir
   mas não resolver sozinho.

---

## Roadmap de Implantação

Sequência concreta pra Fase 1 e Fase 2 (as únicas com veredito "sim,
próximo") — do PR até rodando em produção. Fase 3 e os itens "fora de
escopo" não entram aqui porque ainda não passaram da Fase 0 de decisão.

### Linha do tempo

| Sprint | Entregável | Arquivos principais | Depende de | Critério de saída |
|---|---|---|---|---|
| **S0** (0,5–1 dia) | 3 decisões da Fase 0 registradas | — (só decisão) | — | Decisões viram comentário/issue, zero código |
| **S1** (2–3 dias) | `_check_image_vulnerabilities` + wiring | `auditor_k8s_authenticated.py`, `install.sh`, `tests/` | S0 | PR aberto, `test.yml`/`code-review.yml`/`security-scan.yml` verdes |
| **S2** (0,5–1 dia) | Trivy no ambiente de produção | infra repo (`Terraform-Multicloud_scanner`) | S1 aprovado | Binário disponível nas instâncias do ASG antes do merge que ativa o check |
| **S3** (1 dia) | Parsing de regra allow-all em `_check_network_exposure` | `auditor_k8s_authenticated.py`, `tests/` | Independente de S1/S2 — pode rodar em paralelo | PR próprio, mesmo ciclo de gates |
| **S4** (contínuo) | Canário em produção + decisão sobre o texto do README | — | S1+S2 mergeados | `IMAGE_SCAN_ENABLED=true` numa fração de scans antes de virar padrão |

S1 e S3 são independentes entre si (arquivos diferentes dentro do mesmo
método vs. método novo) — dá pra abrir os dois PRs em paralelo. S2 é o
único item que sai deste repositório.

### S1 — Scan de imagem: checklist de implementação

1. `install.sh` — adicionar instalação do binário `trivy` (script oficial
   `aquasecurity/trivy`), documentar que é dependência de sistema, não
   `pip`.
2. `auditor_k8s_authenticated.py` — `_check_image_vulnerabilities(namespaces)`
   novo (ver Fase 1 acima): dedup de `c.image`, cap de N imagens, timeout
   por imagem, `subprocess.run(["trivy", "image", ref, "--format", "json",
   "--severity", "HIGH,CRITICAL"], timeout=...)`, parse do JSON pra
   findings (`category="Image Vulnerability"`).
3. Feature flag: `IMAGE_SCAN_ENABLED` (env var, default `false`) — mesmo
   padrão de `STORAGE_BACKEND`/`ANTHROPIC_API_KEY` já usado no projeto
   (degrada graciosamente sem a variável). Permite mergear o código antes
   de o binário estar em produção (S1 não fica bloqueado esperando S2) e
   dá um kill-switch sem redeploy se o Trivy causar lentidão/ruído.
4. `tests/` — teste novo mockando `subprocess.run` (não chama Trivy de
   verdade em CI), cobrindo: CVE encontrado vira finding, binário ausente
   não quebra o scan, timeout não quebra o scan.
5. `README.md` — atualizar a linha `Kubernetes | — | RBAC, pod security,
   network policies, secrets hygiene` da tabela de providers pra incluir
   "image vulnerability scanning".
6. Abrir PR (branch a partir de `main`, não push direto — ver preferência
   de fluxo já registrada em memória deste projeto). `test.yml` +
   `code-review.yml` + `security-scan.yml` precisam estar verdes antes do
   merge.

### S2 — Levar o Trivy pra produção (cross-repo)

O `deploy.yml` deste repo faz *rolling deploy via SSM* (código da app —
`git pull` + reinício do serviço nas instâncias do ASG), não provisiona
binário de sistema novo. Trivy precisa existir no host **antes** do merge
que ativa `IMAGE_SCAN_ENABLED=true`, então isso é uma mudança na infra
(`Terraform-Multicloud_scanner`): launch template / user-data da AMI do
ASG, não algo que este repo resolve sozinho. Ordem seguindo o gate de
deploy já documentado nesse outro repo — não usar SSM ad-hoc pra instalar
o binário fora do Git.

### S3 — Parsing de NetworkPolicy: checklist de implementação

1. `auditor_k8s_authenticated.py:314` — extensão do `_check_network_exposure`
   descrita na Fase 2 (checar `pod_selector.match_labels` vazio +
   ausência de `ingress`/`policyTypes` restritivo).
2. `tests/` — caso com NetworkPolicy allow-all disfarçada (hoje passa
   silenciosamente, depois da mudança gera finding HIGH) e caso com
   policy restritiva de verdade (não deve gerar finding novo — evita
   regressão de falso-positivo).
3. Mesmo ciclo de PR/gates do S1. Não depende de Trivy nem de infra —
   pode mergear e implantar (via `deploy.yml` normal) assim que os
   testes passarem.

### S4 — Rollout e decisão do README

- Com `IMAGE_SCAN_ENABLED` como flag, ativar primeiro num ambiente de
  teste (kind local, já usado no projeto — ver
  `security-scanner-kubeconfig-kind-microservices-lab.yaml`) antes de
  virar padrão em produção.
- Só depois de S1+S2 confirmados em produção (finding real de CVE
  aparecendo no dashboard/relatório) faz sentido revisitar a frase de
  abertura do README (`README.md:3`) — decisão do usuário, não algo a
  aplicar antes de a funcionalidade existir de verdade.
