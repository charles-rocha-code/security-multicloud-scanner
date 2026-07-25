---
name: blue-green
description: Gerencia o deploy blue-green — mostra estado atual, promove o slot green ou faz rollback para o main (ex: /blue-green status, /blue-green promote, /blue-green rollback)
allowed-tools: Bash
---

Gerencie o deploy blue-green do `security-scanner` na região `us-east-2`.

Recursos do ambiente:
- ASG principal: `security-scanner-asg` (usa `security-scanner-lt-*`)
- ASG green: `security-scanner-asg-green` (usa `security-scanner-green-lt-*`)
- Target Group principal: `security-scanner-tg`
- Target Group green: `security-scanner-tg-green`
- Listener HTTPS ARN: obtido dinamicamente via describe-listeners
- ALB: `security-scanner-alb`

## Interpretação do argumento

- **`/blue-green status`** ou sem argumento → mostra qual slot está ativo e estado dos dois ASGs
- **`/blue-green promote`** → ativa o green (sobe instâncias green + muda listener para TG green)
- **`/blue-green rollback`** → volta ao main (muda listener para TG principal + zera ASG green)

---

## Comando: status

```bash
# Estado dos dois ASGs
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names security-scanner-asg security-scanner-asg-green \
  --region us-east-2 \
  --query 'AutoScalingGroups[*].{ASG:AutoScalingGroupName,Desired:DesiredCapacity,Min:MinSize,Max:MaxSize,Instancias:Instances[*].{Id:InstanceId,Health:HealthStatus,Lifecycle:LifecycleState}}' \
  --output json

# Qual TG o listener HTTPS está apontando
ALB_ARN=$(aws elbv2 describe-load-balancers --names security-scanner-alb --region us-east-2 --query 'LoadBalancers[0].LoadBalancerArn' --output text)
aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --region us-east-2 \
  --query 'Listeners[?Port==`443`].DefaultActions[*].{Tipo:Type,TG:TargetGroupArn}' \
  --output json
```

---

## Comando: promote (ativar green)

**Passo 1 — Confirmar com o usuário antes de alterar.** Mostre o estado atual e aguarde "sim".

**Passo 2 — Subir instâncias no ASG green**
```bash
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name security-scanner-asg-green \
  --min-size 2 \
  --max-size 4 \
  --desired-capacity 2 \
  --region us-east-2
```

**Passo 3 — Aguardar instâncias green ficarem healthy** (verifique a cada 20s, até 3 minutos):
```bash
aws elbv2 describe-target-health \
  --target-group-arn $(aws elbv2 describe-target-groups --names security-scanner-tg-green --region us-east-2 --query 'TargetGroups[0].TargetGroupArn' --output text) \
  --region us-east-2 \
  --query 'TargetHealthDescriptions[*].{Id:Target.Id,State:TargetHealth.State}' \
  --output json
```

**Passo 4 — Redirecionar listener HTTPS para TG green**
```bash
LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $(aws elbv2 describe-load-balancers --names security-scanner-alb --region us-east-2 --query 'LoadBalancers[0].LoadBalancerArn' --output text) \
  --region us-east-2 \
  --query 'Listeners[?Port==`443`].ListenerArn' --output text)

TG_GREEN_ARN=$(aws elbv2 describe-target-groups \
  --names security-scanner-tg-green \
  --region us-east-2 \
  --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 modify-listener \
  --listener-arn $LISTENER_ARN \
  --default-actions Type=forward,TargetGroupArn=$TG_GREEN_ARN \
  --region us-east-2
```

---

## Comando: rollback (voltar ao main)

**Passo 1 — Confirmar com o usuário antes de alterar.**

**Passo 2 — Redirecionar listener de volta para TG principal**
```bash
LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $(aws elbv2 describe-load-balancers --names security-scanner-alb --region us-east-2 --query 'LoadBalancers[0].LoadBalancerArn' --output text) \
  --region us-east-2 \
  --query 'Listeners[?Port==`443`].ListenerArn' --output text)

TG_MAIN_ARN=$(aws elbv2 describe-target-groups \
  --names security-scanner-tg \
  --region us-east-2 \
  --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 modify-listener \
  --listener-arn $LISTENER_ARN \
  --default-actions Type=forward,TargetGroupArn=$TG_MAIN_ARN \
  --region us-east-2
```

**Passo 3 — Zerar o ASG green**
```bash
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name security-scanner-asg-green \
  --min-size 0 \
  --max-size 4 \
  --desired-capacity 0 \
  --region us-east-2
```

---

## Formato do relatório

- Mostre claramente qual slot está recebendo tráfego (🟢 Green ativo / 🔵 Main ativo)
- Exiba quantas instâncias estão healthy em cada slot
- Após promote/rollback, confirme o switch com timestamp
