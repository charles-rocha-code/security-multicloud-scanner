# 🔒 Segurança — Security Multicloud Scanner

## Visão Geral

Este documento descreve todas as medidas de segurança implementadas no ambiente de produção do **Security Multicloud Scanner**.

---

## 🏗️ Arquitetura de Segurança

```
Internet
    │
    ▼
[ALB / HTTPS 443]  ←── Certificado SSL/TLS
    │
    ▼
[AWS Security Group]  ←── Firewall de rede
    │
    ▼
[EC2 - Ubuntu]  ←── Fail2Ban + Rate Limiting
    │
    ▼
[API - FastAPI + MFA]  ←── Autenticação obrigatória
```

---

## ☁️ AWS — Security Group (Firewall)

### Regras de Entrada

| Protocolo | Porta | Origem | Finalidade |
|---|---|---|---|
| TCP | 22 (SSH) | `140.82.112.0/20` | GitHub Actions |
| TCP | 22 (SSH) | `185.199.108.0/22` | GitHub Actions |
| TCP | 22 (SSH) | `192.30.252.0/22` | GitHub Actions |
| TCP | 22 (SSH) | `143.55.64.0/20` | GitHub Actions |
| TCP | 22 (SSH) | IP do administrador | Acesso admin |
| TCP | 443 (HTTPS) | `0.0.0.0/0` | Acesso à aplicação |
| TCP | 80 (HTTP) | `0.0.0.0/0` | Redirect → HTTPS |
| TCP | 8000 | Security Group interno | App interna |

> ⚠️ A porta SSH (22) está restrita apenas aos IPs do GitHub Actions e do administrador. Nenhum acesso público é permitido.

---

## 🔐 Autenticação — MFA Obrigatório

A aplicação utiliza autenticação em dois fatores (MFA) obrigatória para todos os usuários.

### Fluxo de autenticação

```
Usuário acessa /login
    │
    ▼
Insere e-mail + senha
    │
    ▼
Insere código TOTP (Google Authenticator / Authy)
    │
    ▼
Cookie de sessão gerado (scanner_session)
    │
    ▼
Acesso liberado ao dashboard
```

### Tecnologias utilizadas

- `pyotp` — geração e validação de tokens TOTP
- `qrcode` — QR Code para configuração do autenticador
- `email-validator` + `pydantic[email]` — validação de e-mails
- Cookies de sessão com `HttpOnly` e `Secure`

---

## 🛡️ Fail2Ban — Proteção contra Ataques

O **Fail2Ban** monitora os logs e bane automaticamente IPs maliciosos.

### Configuração

| Jail | Porta | Max tentativas | Tempo de ban |
|---|---|---|---|
| `sshd` | 22 | 3 tentativas | 24 horas |
| `http-scan` | 80, 443, 8000 | 20 tentativas | 2 horas |

### Padrões detectados e banidos

- Tentativas de explorar PHPUnit (`/vendor/phpunit/...`)
- Tentativas de explorar Laravel (`/laravel/vendor/...`)
- Tentativas de acesso a `.env`, `wp-admin`, `shell`, `cmd`
- Path traversal (`../../../`)
- XML-RPC attacks

### Comandos de monitoramento

```bash
# Ver status geral
sudo fail2ban-client status

# Ver IPs banidos no jail SSH
sudo fail2ban-client status sshd

# Ver IPs banidos no jail HTTP
sudo fail2ban-client status http-scan

# Desbanir um IP manualmente
sudo fail2ban-client set http-scan unbanip <IP>
```

---

## 🚀 Deploy — GitHub Actions

O deploy em produção é 100% automatizado via **GitHub Actions**.

### Fluxo

```
git push origin main
    │
    ▼
GitHub Actions dispara
    │
    ▼
Conecta no servidor via SSH (porta 22)
usando secrets criptografados
    │
    ▼
git pull + pip install + restart da aplicação
    │
    ▼
✅ Produção atualizada em ~16 segundos
```

### Secrets configurados

| Secret | Descrição |
|---|---|
| `AWS_HOST` | IP público do servidor EC2 |
| `AWS_SSH_KEY` | Chave privada SSH (.pem) |

> Os secrets são armazenados de forma criptografada no GitHub e nunca expostos nos logs.

---

## 🔄 HTTPS — Certificado SSL/TLS

- Tráfego HTTP (porta 80) é redirecionado automaticamente para HTTPS (301)
- Certificado SSL válido em `scanner.oisolucoes.app.br`
- Comunicação cliente ↔ servidor totalmente criptografada

---

## 📋 Checklist de Segurança

- [x] MFA obrigatório para todos os usuários
- [x] SSH restrito a IPs específicos (GitHub Actions + admin)
- [x] HTTPS com certificado SSL válido
- [x] HTTP redireciona para HTTPS
- [x] Fail2Ban ativo (sshd + http-scan)
- [x] Deploy automatizado sem exposição de credenciais
- [x] Secrets criptografados no GitHub Actions
- [x] Porta 8000 acessível apenas via Security Group interno
- [ ] Rate limiting na API *(em implementação)*
- [ ] WAF (Web Application Firewall) *(planejado)*

---

## 🚨 Reporte de Vulnerabilidades

Se você encontrar alguma vulnerabilidade de segurança, **não abra uma issue pública**.

Entre em contato diretamente pelo e-mail do administrador do repositório.

---

## 📅 Histórico de Atualizações de Segurança

| Data | Descrição |
|---|---|
| 2026-03-01 | Implementação do MFA obrigatório |
| 2026-03-01 | Configuração do Fail2Ban (sshd + http-scan) |
| 2026-03-01 | Restrição da porta SSH aos IPs do GitHub Actions |
| 2026-03-01 | Deploy automático via GitHub Actions |
| 2026-03-01 | Correção de autenticação nas chamadas de scan (credentials: include) |
