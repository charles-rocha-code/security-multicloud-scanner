---
name: waf
description: Gerencia o WAF do security-scanner — status das regras, bloqueio/desbloqueio de IPs (ex: /waf block 1.2.3.4, /waf unblock 1.2.3.4, /waf status)
allowed-tools: Bash
---

Gerencie o WAF `security-scanner-production-waf` na região `us-east-2`.

IDs fixos do ambiente:
- Web ACL ID: `7fa646b2-4cd6-4b54-abce-95a3444c41d3`
- IP Set bloqueados: `175ba253-6665-48b9-b4c3-d8a54cdaebc4` (nome: `security-scanner-production-waf-blocked-ips`)
- IP Set confiáveis: `12065527-8c83-411a-b8c1-9f4f4187e005` (nome: `security-scanner-production-waf-trusted-ips`)

## Interpretação do argumento

- **`/waf status`** ou sem argumento → mostra status completo (regras + IPs)
- **`/waf block 1.2.3.4`** → adiciona IP ao IP Set de bloqueados
- **`/waf unblock 1.2.3.4`** → remove IP do IP Set de bloqueados
- **`/waf trust 1.2.3.4`** → adiciona IP ao IP Set de confiáveis (bypass WAF)
- **`/waf untrust 1.2.3.4`** → remove IP do IP Set de confiáveis

---

## Comando: status

### Regras ativas
```bash
aws wafv2 get-web-acl \
  --name security-scanner-production-waf \
  --id 7fa646b2-4cd6-4b54-abce-95a3444c41d3 \
  --scope REGIONAL \
  --region us-east-2 \
  --query 'WebACL.Rules[*].{Prioridade:Priority,Nome:Name,Acao:Action}' \
  --output json
```

### IPs bloqueados
```bash
aws wafv2 get-ip-set \
  --name security-scanner-production-waf-blocked-ips \
  --id 175ba253-6665-48b9-b4c3-d8a54cdaebc4 \
  --scope REGIONAL \
  --region us-east-2 \
  --query 'IPSet.Addresses' \
  --output json
```

### IPs confiáveis
```bash
aws wafv2 get-ip-set \
  --name security-scanner-production-waf-trusted-ips \
  --id 12065527-8c83-411a-b8c1-9f4f4187e005 \
  --scope REGIONAL \
  --region us-east-2 \
  --query 'IPSet.Addresses' \
  --output json
```

---

## Comando: block / unblock / trust / untrust

Para modificar um IP Set é necessário o `LockToken` atual. Siga estes passos:

### Passo 1 — Obter LockToken e lista atual
```bash
aws wafv2 get-ip-set \
  --name <NOME_DO_IPSET> \
  --id <ID_DO_IPSET> \
  --scope REGIONAL \
  --region us-east-2 \
  --query '{LockToken:LockToken,Addresses:IPSet.Addresses}' \
  --output json
```

### Passo 2 — Montar nova lista e atualizar

Para **block**: adicione o IP em formato CIDR (`1.2.3.4/32`) à lista atual.
Para **unblock**: remova o IP da lista atual.

```bash
aws wafv2 update-ip-set \
  --name <NOME_DO_IPSET> \
  --id <ID_DO_IPSET> \
  --scope REGIONAL \
  --region us-east-2 \
  --addresses <LISTA_ATUALIZADA_DE_CIDRs> \
  --lock-token <LOCK_TOKEN>
```

**Importante:** `--addresses` deve conter a lista COMPLETA de IPs (não apenas o novo). Se a lista estiver vazia, use `--addresses` sem argumentos ou passe `[]`.

---

## Formato do relatório

- Liste as 17 regras com prioridade, nome e ação (Allow/Block/Count)
- Destaque regras gerenciadas pela AWS vs customizadas
- Mostre IPs bloqueados e confiáveis em formato tabela
- Confirme mudanças com ✅ e mostre o IP afetado
