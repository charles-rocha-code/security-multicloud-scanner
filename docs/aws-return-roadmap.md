# Roadmap: retorno do ambiente AWS — security-multicloud-scanner

Itens que dependem de um ambiente AWS real e por isso ficaram parados enquanto
o projeto roda 100% local (`STORAGE_BACKEND=local`). Os scripts citados aqui
foram **mantidos de propósito** na limpeza de 2026-10-17 — não remover, ajustar.

## TL;DR

| # | Item | Estado hoje | O que falta | Esforço |
|---|---|---|---|---|
| 1 | Reset de usuários (`reset_users.sh` + `reset-db.yml`) | **Quebrado nos dois modos** | Reescrever respeitando `STORAGE_BACKEND` | Baixo-médio |
| 2 | `test_graph_local.py` | Só roda contra DynamoDB `-dev` | Recriar as tabelas `-dev` e revalidar | Baixo |

## 1. Reset de usuários

### O problema

O reset zera arquivos que o app não lê mais:

```
                      o que o reset zera            onde o app lê de verdade
                      ------------------            ------------------------
reset_users.sh        ./users_db.json (raiz)        local: local_data/users.json
(local)                                                    local_data/sessions.json

reset-db.yml          ./users_db.json (instância)   aws:   DynamoDB
(AWS, via SSM)        S3 db/users_db.json                  USERS_DYNAMO_TABLE
                      S3 db/sessions_db.json               SESSIONS_DYNAMO_TABLE
                                                           PASSWORD_RESETS_DYNAMO_TABLE
```

- `reset_users.sh`: zera `users_db.json` na raiz (backend antigo) e sobe a API com
  `python3 api_with_mfa.py` em foreground. Em modo local não tem efeito nenhum
  sobre os usuários reais.
- `.github/workflows/reset-db.yml`: via SSM em cada instância do ASG, escreve `{}`
  nos JSON da raiz e em `db/users_db.json` / `db/sessions_db.json` no S3 (payload
  Python embutido em base64). **Nunca toca no DynamoDB**, que é onde `auth_mfa.py`
  persiste em `STORAGE_BACKEND=aws`.
- Detalhe que o reset novo precisa tratar: `auth_mfa.py` migra
  `db/users_db.json` do S3 pro DynamoDB quando a tabela está vazia. Zerar só o
  DynamoDB e deixar o S3 com dados faria os usuários voltarem no próximo start.

### O que fazer

1. Um único script de reset que lê `STORAGE_BACKEND`:
   - `local`: backup + limpeza de `local_data/users.json` e `local_data/sessions.json`.
   - `aws`: backup + limpeza das 3 tabelas DynamoDB e do `db/users_db.json` no S3
     (para não reativar a migração).
2. Não subir a API de dentro do script (hoje roda em foreground) — reiniciar via
   `systemctl restart security-scanner` no servidor, ou deixar com quem chamou.
3. `reset-db.yml` passa a chamar esse script via SSM em vez do payload base64.
4. Teste em `tests/` cobrindo o caminho `local` (o `aws` só valida com ambiente).

## 2. `test_graph_local.py`

Script manual de validação ponta a ponta do Mapa de Grafo de Ataque. Usa
`USERS_DYNAMO_TABLE` / `SESSIONS_DYNAMO_TABLE` / `PASSWORD_RESETS_DYNAMO_TABLE`
apontando para tabelas `-dev` (nunca produção). Fica na raiz porque depende de
`sys.path.insert(0, os.path.dirname(__file__))` para importar os módulos.

Ao ter ambiente AWS: recriar as tabelas `-dev` e rodar o script; considerar
uma versão que rode com `STORAGE_BACKEND=local` para não depender de AWS.
