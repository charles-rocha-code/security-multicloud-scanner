---
name: scale
description: Escala o ASG principal do security-scanner — aceita argumentos: up, down ou número direto (ex: /scale up, /scale 3)
allowed-tools: Bash
---

Gerencie a capacidade do ASG `security-scanner-asg` na região `us-east-2`.

## 1. Verificar estado atual SEMPRE primeiro

```bash
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names security-scanner-asg \
  --region us-east-2 \
  --query 'AutoScalingGroups[0].{Min:MinSize,Max:MaxSize,Desired:DesiredCapacity,Instancias:Instances[*].{Id:InstanceId,Health:HealthStatus,Lifecycle:LifecycleState}}' \
  --output json
```

## 2. Interpretar o argumento do usuário

- **`/scale up`** → aumenta `DesiredCapacity` em +1 (respeitando o Max)
- **`/scale down`** → diminui `DesiredCapacity` em -1 (respeitando o Min)
- **`/scale N`** (número) → define `DesiredCapacity` exatamente como N
- **sem argumento** → apenas mostra o estado atual, sem alterar

**Limites obrigatórios:** Min=2, Max=4. Nunca defina Desired abaixo do Min ou acima do Max.

## 3. Confirmar com o usuário antes de alterar

Antes de executar qualquer mudança, mostre:
```
Estado atual: Desired=X, Min=Y, Max=Z
Ação proposta: Desired → N
Confirme digitando "sim" para prosseguir.
```

Aguarde confirmação explícita do usuário antes de executar o comando de escala.

## 4. Executar a escala (após confirmação)

```bash
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name security-scanner-asg \
  --desired-capacity N \
  --region us-east-2
```

## 5. Monitorar após a mudança

Após alterar, verifique o estado a cada 15 segundos por até 2 tentativas:

```bash
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names security-scanner-asg \
  --region us-east-2 \
  --query 'AutoScalingGroups[0].Instances[*].{Id:InstanceId,Health:HealthStatus,Lifecycle:LifecycleState}' \
  --output json
```

## Formato do relatório

- Mostre claramente o estado antes e depois
- Informe se instâncias novas estão em `Pending` (aguardando bootstrap)
- Estime tempo para ficarem `InService`: ~3-5 minutos por instância nova
