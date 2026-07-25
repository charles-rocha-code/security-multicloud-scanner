---
description: Detecta drift entre o Terraform e o estado real da AWS — IAM policies, Security Groups, configurações de instâncias e recursos não gerenciados
allowed-tools: Bash
---

Compare o estado real da AWS com o que está definido no Terraform para o projeto `security-scanner` na região `us-east-2`.

## 1. IAM Policies da Role

Liste as policies aplicadas à role e identifique quais existem fora do Terraform:

```bash
aws iam list-role-policies \
  --role-name security-scanner-role \
  --query 'PolicyNames' \
  --output json
```

**Policies esperadas pelo Terraform** (em `iam.tf`, `iam_drift_policies.tf` e `dynamo.tf`):
- `security-scanner-s3-readonly`
- `security-scanner-cloudwatch-logs`
- `security-scanner-ec2-describe`
- `security-scanner-ssm-parameters`
- `security-scanner-s3-db`
- `security-scanner-secrets-manager`
- `AllowReadGithubDeployToken`
- `AllowS3DB`
- `security-scanner-dynamodb-auth`

Qualquer policy listada na AWS que **não esteja** nessa lista é drift.

Para cada policy extra encontrada, mostre o conteúdo:
```bash
aws iam get-role-policy \
  --role-name security-scanner-role \
  --policy-name <NOME_DA_POLICY> \
  --query 'PolicyDocument' \
  --output json
```

## 2. Security Groups com mesmo nome

Verifique duplicatas de SG — o Terraform deve gerenciar apenas um:

```bash
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=security-scanner-ec2-sg" \
  --region us-east-2 \
  --query 'SecurityGroups[*].{Id:GroupId,Nome:GroupName,VPC:VpcId,Regras:IpPermissions[*].{Porta:FromPort,Protocolo:IpProtocol,CIDRs:IpRanges[*].CidrIp,SGSources:UserIdGroupPairs[*].GroupId}}' \
  --output json
```

**Esperado pelo Terraform:** apenas 1 SG com porta 8000 vindo do ALB SG. Qualquer SG adicional ou regra de porta 22 é drift.

## 3. IMDSv2 nos Launch Templates

```bash
aws ec2 describe-launch-templates \
  --filters "Name=launch-template-name,Values=security-scanner-*" \
  --region us-east-2 \
  --query 'LaunchTemplates[*].{Nome:LaunchTemplateName,Id:LaunchTemplateId,Versao:LatestVersionNumber}' \
  --output json
```

Para cada template, verifique as configurações de IMDS:
```bash
aws ec2 describe-launch-template-versions \
  --launch-template-id <ID> \
  --versions '$Latest' \
  --region us-east-2 \
  --query 'LaunchTemplateVersions[0].LaunchTemplateData.MetadataOptions' \
  --output json
```

**Esperado:**
- Template principal (`security-scanner-lt-*`): `HttpTokens=required`, `HopLimit=1`
- Template green (`security-scanner-green-lt-*`): `HttpTokens=required`, `HopLimit=1` — confirmado em conformidade em 2026-07-24, não é mais drift

## 4. Instâncias usando SG correto

Verifique se as instâncias rodando usam o SG gerenciado pelo Terraform:

```bash
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=security-scanner-instance" "Name=instance-state-name,Values=running" \
  --region us-east-2 \
  --query 'Reservations[*].Instances[*].{Id:InstanceId,SGs:SecurityGroups[*].GroupId}' \
  --output json
```

O SG esperado (Terraform) é `sg-02909acb222bc57f0`. Instâncias usando outro SG = drift.

## 5. Recursos AWS não rastreados pelo Terraform

Políticas managed attachadas à role além das duas esperadas:
```bash
aws iam list-attached-role-policies \
  --role-name security-scanner-role \
  --query 'AttachedPolicies[*].{Nome:PolicyName,ARN:PolicyArn}' \
  --output json
```

**Esperadas:** `CloudWatchAgentServerPolicy`, `AmazonSSMManagedInstanceCore`

## Formato do relatório

Para cada categoria, classifique:
- ✅ **Alinhado** — AWS bate com o Terraform
- ⚠️ **Drift menor** — diferença sem impacto crítico
- ❌ **Drift crítico** — recurso fora do IaC que afeta segurança ou operação

Finalize com uma tabela resumo e recomendações de correção (import ou remoção).
