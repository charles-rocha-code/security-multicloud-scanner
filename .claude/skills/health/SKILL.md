---
description: Verifica a saúde completa do ambiente AWS — instâncias, ALB, Target Groups e alarmes CloudWatch
allowed-tools: Bash
---

Verifique a saúde do ambiente `security-scanner` na região `us-east-2`. Execute todos os comandos abaixo e apresente um relatório consolidado.

## 1. Instâncias do ASG

```bash
aws autoscaling describe-auto-scaling-groups \
  --region us-east-2 \
  --query 'AutoScalingGroups[?contains(AutoScalingGroupName, `security-scanner`)].{ASG:AutoScalingGroupName,Min:MinSize,Max:MaxSize,Desired:DesiredCapacity,Instances:Instances[*].{Id:InstanceId,Health:HealthStatus,Lifecycle:LifecycleState}}' \
  --output json
```

## 2. Estado das instâncias EC2 (IMDSv2 + tipo)

```bash
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=security-scanner-instance" "Name=instance-state-name,Values=running,stopped,pending" \
  --region us-east-2 \
  --query 'Reservations[*].Instances[*].{Id:InstanceId,State:State.Name,IMDSv2:MetadataOptions.HttpTokens,Type:InstanceType,Launch:LaunchTime}' \
  --output json
```

## 3. Saúde do Target Group principal

```bash
aws elbv2 describe-target-groups \
  --names security-scanner-tg \
  --region us-east-2 \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text | xargs -I{} aws elbv2 describe-target-health \
  --target-group-arn {} \
  --region us-east-2 \
  --query 'TargetHealthDescriptions[*].{Id:Target.Id,Port:Target.Port,State:TargetHealth.State,Reason:TargetHealth.Reason}' \
  --output json
```

## 4. Alarmes CloudWatch ativos

```bash
aws cloudwatch describe-alarms \
  --region us-east-2 \
  --state-value ALARM \
  --query 'MetricAlarms[?contains(AlarmName, `security-scanner`)].{Nome:AlarmName,Metrica:MetricName,Estado:StateValue,Motivo:StateReason}' \
  --output json
```

## 5. Endpoint da aplicação

```bash
aws elbv2 describe-load-balancers \
  --names security-scanner-alb \
  --region us-east-2 \
  --query 'LoadBalancers[0].DNSName' \
  --output text | xargs -I{} curl -sk -o /dev/null -w "HTTP %{http_code} — %{time_total}s" "https://scanner.oisolucoes.app.br/health" || echo "Endpoint não respondeu"
```

## Formato do relatório

Apresente o resultado em seções claras com emojis de status:
- ✅ Saudável / OK
- ⚠️ Atenção (degradado mas funcional)
- ❌ Crítico (fora do ar ou com falha)

Finalize com um resumo de uma linha: estado geral do ambiente.
