# ai-tool-calling Specification

## Purpose

Permite que o usuário autenticado peça, em linguagem livre via `/ai/ask-tools`, para o Claude rodar uma auditoria de Kubernetes sob demanda e usar o resultado fresco na resposta, em vez de só interpretar o último scan já salvo. Auditoria de IAM fica fora de escopo enquanto não há ambiente AWS disponível para credenciais reais.

## Requirements

### Requirement: Endpoint de tool-calling isolado
O sistema SHALL expor `POST /ai/ask-tools` como endpoint autenticado (mesma sessão MFA exigida por `/ai/ask`), sem alterar o comportamento de `/ai/ask` existente.

#### Scenario: Usuário sem MFA válida
- **WHEN** uma requisição chega em `/ai/ask-tools` sem sessão MFA válida
- **THEN** o sistema responde 401/403, do mesmo jeito que `/ai/ask` responde hoje

#### Scenario: `/ai/ask` continua funcionando sem tools
- **WHEN** uma requisição chega em `/ai/ask` (endpoint existente, não o novo)
- **THEN** o comportamento é idêntico ao anterior a este change — nenhuma tool é oferecida ao modelo

### Requirement: Tool-calling restrito a auditores explicitamente habilitados
O sistema SHALL permitir que o modelo invoque apenas as tools explicitamente registradas para este endpoint — auditoria de Kubernetes autenticada — e SHALL rejeitar qualquer tentativa de invocar uma tool não registrada.

#### Scenario: Pergunta que dispara auditoria de K8s
- **WHEN** o usuário pergunta algo que requer dados atuais do cluster (ex.: "algum ClusterRole com permissão de '*' agora?")
- **THEN** o modelo pode invocar a tool de auditoria K8s e a resposta reflete o resultado dessa execução, não apenas o scan salvo anteriormente

#### Scenario: Pergunta que não requer nenhuma tool
- **WHEN** o usuário faz uma pergunta que só precisa do scan/histórico já carregado (ex.: "resuma os findings críticos do último scan")
- **THEN** o modelo pode responder sem invocar nenhuma tool, e a resposta não é bloqueada por essa ausência

### Requirement: Proteção SSRF na execução da tool de K8s
A execução da tool de auditoria K8s SHALL passar pela mesma checagem anti-SSRF que os endpoints REST equivalentes já aplicam antes de qualquer chamada real ao API server do cluster, e SHALL recusar a execução quando a checagem falhar. (Nota de implementação: essa checagem já é inerente ao construtor de `K8sAuthenticatedAuditor` — a tool wrapper não precisa reimplementá-la, só precisa tratar a exceção que ela levanta como erro de tool, não como crash.)

#### Scenario: Tool de K8s recebe kubeconfig apontando pra alvo SSRF
- **WHEN** o kubeconfig usado (do request ou o default local) resolve pra um endereço de servidor que é um alvo SSRF (ex.: endpoint de metadados interno)
- **THEN** a execução da tool é recusada antes de qualquer chamada de rede real, e o motivo da recusa é retornado como resultado de erro da tool (não como exceção não tratada)

### Requirement: Credencial do cluster nunca é parâmetro que o modelo preenche
O sistema SHALL aceitar o kubeconfig usado pela tool através do corpo da requisição HTTP (campo opcional, mesmo formato de `K8sScanIn.kubeconfig` em `/scan/k8s`) ou de um default local de teste, e SHALL NOT incluir a credencial no schema da tool nem no `tool_use.input` que o modelo produz ou vê.

#### Scenario: Requisição sem kubeconfig no body
- **WHEN** o usuário faz uma pergunta em `/ai/ask-tools` sem enviar `kubeconfig` no corpo
- **THEN** a tool, se invocada, usa o kubeconfig de teste local padrão do ambiente, sem exigir que o modelo ou o usuário informem uma credencial dentro da conversa

#### Scenario: Requisição com kubeconfig no body
- **WHEN** o usuário envia um `kubeconfig` próprio no corpo da requisição
- **THEN** a tool usa esse kubeconfig, e ele nunca aparece no schema da tool nem é passado como argumento que o modelo gera

### Requirement: Falha de tool não derruba a resposta
Quando a execução de uma tool falhar (erro do auditor, credencial ausente, SSRF recusado), o sistema SHALL devolver o erro como `tool_result` de erro para o modelo continuar o raciocínio, em vez de propagar uma exceção não tratada que derruba a requisição inteira.

#### Scenario: Auditor de K8s falha por kubeconfig ausente
- **WHEN** o modelo invoca a tool de auditoria K8s e o auditor lança uma exceção (ex.: kubeconfig ausente/inválido)
- **THEN** o usuário recebe uma resposta final coerente (ex.: "não foi possível rodar a auditoria K8s: <motivo>"), não um erro 500 genérico
