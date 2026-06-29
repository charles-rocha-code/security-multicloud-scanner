---
description: Busca e analisa logs da aplicação no CloudWatch — aceita argumento de janela de tempo (ex: /logs 30m, /logs 2h)
allowed-tools: Bash
---

Busque logs da aplicação `security-scanner` no CloudWatch Logs. O log group é `/aws/ec2/security-scanner`.

## Janela de tempo

Se o usuário passou um argumento (ex: `30m`, `1h`, `2h`), use esse período. Caso contrário, use os últimos **30 minutos**.

Calcule o timestamp de início em milissegundos:
```bash
# Últimos 30 minutos (padrão)
START_TIME=$(date -v-30M +%s%3N 2>/dev/null || date -d '30 minutes ago' +%s%3N)

# Para outros períodos, ajuste conforme o argumento:
# 1h  → date -v-1H  / date -d '1 hour ago'
# 2h  → date -v-2H  / date -d '2 hours ago'
# 24h → date -v-24H / date -d '24 hours ago'
```

## 1. Logs da API (erros e exceções)

```bash
START_TIME=$(date -v-30M +%s%3N 2>/dev/null || date -d '30 minutes ago' +%s%3N)

aws logs filter-log-events \
  --log-group-name "/aws/ec2/security-scanner" \
  --log-stream-name-prefix "" \
  --filter-pattern "?ERROR ?Exception ?Traceback ?CRITICAL ?500 ?502 ?503" \
  --start-time $START_TIME \
  --region us-east-2 \
  --query 'events[*].{Hora:timestamp,Stream:logStreamName,Msg:message}' \
  --output json
```

## 2. Logs do user-data (bootstrap)

```bash
START_TIME=$(date -v-30M +%s%3N 2>/dev/null || date -d '30 minutes ago' +%s%3N)

aws logs filter-log-events \
  --log-group-name "/aws/ec2/security-scanner" \
  --log-stream-name-prefix "" \
  --filter-pattern "?ERRO ?ERROR ?failed ?Bootstrap" \
  --start-time $START_TIME \
  --region us-east-2 \
  --query 'events[*].{Hora:timestamp,Stream:logStreamName,Msg:message}' \
  --output json
```

## 3. Todos os streams disponíveis

```bash
aws logs describe-log-streams \
  --log-group-name "/aws/ec2/security-scanner" \
  --region us-east-2 \
  --order-by LastEventTime \
  --descending \
  --max-items 10 \
  --query 'logStreams[*].{Stream:logStreamName,UltimoEvento:lastEventTimestamp}' \
  --output json
```

## Formato do relatório

- Converta timestamps de milissegundos para horário legível (BRT = UTC-3)
- Agrupe por instância (logStreamName contém o instance ID)
- Destaque erros críticos com ❌ e avisos com ⚠️
- Se não houver erros: informe "✅ Nenhum erro no período"
- Mostre quantos eventos foram encontrados no total
