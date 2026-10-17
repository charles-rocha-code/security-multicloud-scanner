## Purpose

Garante que o histórico de scans de cada usuário fique isolado: nenhum parâmetro que o usuário controla consegue fazer o sistema listar, carregar ou gravar scans fora da área do próprio usuário autenticado.

## ADDED Requirements

### Requirement: Filtro de provider restrito a um identificador simples
O sistema SHALL aceitar como `provider` do histórico apenas um identificador composto por letras minúsculas, dígitos e `_`, com 1 a 32 caracteres (após converter para minúsculas). Qualquer outro valor — incluindo `/`, `\`, `.`, `..` ou caracteres de controle — SHALL ser rejeitado antes de ser usado para localizar scans.

#### Scenario: Provider válido filtra normalmente
- **WHEN** um usuário autenticado chama `GET /scan/history?provider=k8s`
- **THEN** a resposta é 200 e lista apenas os scans de `k8s` desse mesmo usuário

#### Scenario: Provider com path traversal é rejeitado
- **WHEN** um usuário autenticado chama `GET /scan/history?provider=../outro_usuario_at_corp_com`
- **THEN** a resposta é 422 (erro de validação) e nenhum scan de outro usuário é listado

#### Scenario: Provider em maiúsculas continua aceito
- **WHEN** um usuário autenticado chama `GET /scan/history?provider=AWS_IAM`
- **THEN** o valor é tratado como `aws_iam` e a resposta é 200

#### Scenario: Sem filtro de provider
- **WHEN** um usuário autenticado chama `GET /scan/history` sem `provider`
- **THEN** a resposta é 200 com os scans de todos os providers desse usuário, e de nenhum outro

### Requirement: Contexto da IA nunca inclui histórico de outro usuário
Os endpoints de IA que carregam histórico (`/ai/ask`, `/ai/ask-tools`) SHALL aplicar a mesma validação de `provider`, e SHALL NOT carregar no contexto do modelo nenhum scan que não pertença ao usuário autenticado.

#### Scenario: Provider malicioso em /ai/ask-tools
- **WHEN** um usuário autenticado envia `POST /ai/ask-tools` com `provider` = `../outro_usuario_at_corp_com`
- **THEN** a requisição é rejeitada com 422 (erro de validação), e nenhum dado de outro usuário chega ao modelo

### Requirement: Gravação de scan não escapa da área do usuário
Ao salvar um scan, o sistema SHALL normalizar o provider com a mesma regra; um provider fora do formato SHALL ser gravado como `unknown` em vez de ser usado como caminho.

#### Scenario: Resultado de scan com provider inesperado
- **WHEN** um scan termina e o provider informado pelo resultado contém `/` ou `..`
- **THEN** o scan é gravado na área do próprio usuário sob o provider `unknown`, e nenhum arquivo é criado fora dela
