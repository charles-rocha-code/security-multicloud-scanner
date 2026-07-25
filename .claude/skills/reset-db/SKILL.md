---
description: Dispara o workflow de reset do banco de usuários em todas as instâncias AWS via GitHub Actions
allowed-tools: Bash
---

Dispare o workflow `reset-db.yml` via GitHub API para resetar o banco de usuários em todas as instâncias do ASG.

Execute o seguinte comando:

```bash
curl -s -w "\nHTTP: %{http_code}" -X POST \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/charles-rocha-code/security-multicloud-scanner/actions/workflows/reset-db.yml/dispatches" \
  -d '{"ref":"main"}'
```

Se retornar `HTTP: 204` — workflow disparado com sucesso. Informe o usuário e diga para acompanhar em:
https://github.com/charles-rocha-code/security-multicloud-scanner/actions/workflows/reset-db.yml

Se retornar `401` — o GITHUB_TOKEN não está exportado. Oriente o usuário a exportar um Personal Access Token com escopo `workflow` na variável de ambiente `GITHUB_TOKEN` (nunca cole o token em arquivos versionados).

Se retornar outro erro — mostre o código e explique o problema.
