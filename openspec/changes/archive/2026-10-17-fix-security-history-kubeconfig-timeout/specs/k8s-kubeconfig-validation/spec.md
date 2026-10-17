## Purpose

Define quais kubeconfigs enviados pelo usuário o scanner aceita carregar, impedindo que o próprio ato de carregar a credencial execute código no servidor do scanner.

## ADDED Requirements

### Requirement: Kubeconfig com execução local é recusado antes de ser carregado
O sistema SHALL inspecionar todo kubeconfig recebido do usuário (`POST /scan/k8s` e o campo `kubeconfig` de `POST /ai/ask-tools`) antes de qualquer carregamento pela biblioteca do Kubernetes, e SHALL recusá-lo quando qualquer entrada em `users[].user` declarar `exec` ou `auth-provider`. Nenhum comando ou plugin declarado no kubeconfig SHALL ser executado.

#### Scenario: Kubeconfig com plugin exec em /scan/k8s
- **WHEN** um usuário autenticado envia `POST /scan/k8s` com um kubeconfig cujo `users[0].user.exec.command` é `sh`
- **THEN** a resposta é 422 (erro de validação) com uma mensagem dizendo que kubeconfig com `exec`/`auth-provider` não é aceito, e o comando não é executado

#### Scenario: Kubeconfig com auth-provider
- **WHEN** um usuário autenticado envia um kubeconfig com `users[0].user.auth-provider`
- **THEN** o scan é recusado da mesma forma, sem carregar a configuração

#### Scenario: Kubeconfig com exec via /ai/ask-tools
- **WHEN** um usuário envia `POST /ai/ask-tools` com um kubeconfig que declara `exec`
- **THEN** a resposta é 422 antes de qualquer chamada ao modelo, e o comando não é executado

#### Scenario: Kubeconfig com exec chega ao auditor por outro caminho
- **WHEN** um kubeconfig com `exec` ou `auth-provider` chega ao auditor de K8s sem ter passado pela validação do endpoint (ex.: arquivo local do servidor)
- **THEN** o auditor recusa carregá-lo com erro (que a tool de IA devolve como erro de tool, não como 500), e o comando não é executado

### Requirement: Kubeconfig com token ou certificado continua aceito
O sistema SHALL continuar aceitando kubeconfigs cujos usuários autenticam por `token`, `tokenFile`, `client-certificate(-data)`/`client-key(-data)` ou `username`/`password`.

#### Scenario: Kubeconfig de ServiceAccount com token
- **WHEN** um usuário autenticado envia `POST /scan/k8s` com um kubeconfig cujo usuário tem apenas `token`
- **THEN** o scan segue o fluxo normal (incluindo a checagem anti-SSRF existente)

### Requirement: Kubeconfig inválido é recusado sem erro 500
O sistema SHALL responder com erro de validação (422 no endpoint REST, erro de tool em `/ai/ask-tools`) quando o kubeconfig não for YAML válido ou não tiver a estrutura mínima de mapeamento, em vez de propagar exceção não tratada.

#### Scenario: Kubeconfig que não é YAML
- **WHEN** um usuário autenticado envia `POST /scan/k8s` com `kubeconfig` = `"::: não é yaml"`
- **THEN** a resposta é 422 com mensagem de kubeconfig inválido
