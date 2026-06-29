---
description: Auditoria de segurança completa do ambiente AWS — IMDSv2, IAM, Security Groups, WAF, S3, DynamoDB e exposição de secrets
allowed-tools: Bash
---

Execute uma auditoria de segurança completa do ambiente `security-scanner` na região `us-east-2`. Verifique cada categoria e classifique por severidade.

---

## 1. IMDSv2 nas instâncias em execução

```bash
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --region us-east-2 \
  --query 'Reservations[*].Instances[*].{Id:InstanceId,Nome:Tags[?Key==`Name`]|[0].Value,IMDSv2:MetadataOptions.HttpTokens,HopLimit:MetadataOptions.HttpPutResponseHopLimit}' \
  --output json
```

✅ Esperado: `HttpTokens=required`, `HopLimit=1`
❌ Crítico se: `HttpTokens=optional` (vulnerável a SSRF → roubo de credenciais)

---

## 2. IMDSv2 nos Launch Templates

```bash
for LT_ID in $(aws ec2 describe-launch-templates --filters "Name=launch-template-name,Values=security-scanner-*" --region us-east-2 --query 'LaunchTemplates[*].LaunchTemplateId' --output text); do
  echo "=== $LT_ID ==="
  aws ec2 describe-launch-template-versions \
    --launch-template-id $LT_ID \
    --versions '$Latest' \
    --region us-east-2 \
    --query 'LaunchTemplateVersions[0].{Nome:LaunchTemplateName,IMDS:LaunchTemplateData.MetadataOptions}' \
    --output json
done
```

---

## 3. Permissões IAM — S3 excessivo

```bash
aws iam get-role-policy \
  --role-name security-scanner-role \
  --policy-name security-scanner-s3-readonly \
  --query 'PolicyDocument.Statement[*].{Sid:Sid,Actions:Action,Resource:Resource}' \
  --output json
```

❌ Crítico se: `s3:GetObject` com `Resource=arn:aws:s3:::*/*` (leitura de objetos em TODOS os buckets)

---

## 4. Policies IAM fora do Terraform

```bash
aws iam list-role-policies \
  --role-name security-scanner-role \
  --query 'PolicyNames' \
  --output json
```

Policies esperadas: `security-scanner-s3-readonly`, `security-scanner-cloudwatch-logs`, `security-scanner-ec2-describe`, `security-scanner-ssm-parameters`, `security-scanner-s3-db`, `security-scanner-secrets-manager`

Para cada policy extra, mostre as permissões:
```bash
aws iam get-role-policy --role-name security-scanner-role --policy-name <EXTRA> --query 'PolicyDocument' --output json
```

---

## 5. Security Groups — regras inbound

```bash
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=security-scanner-ec2-sg,security-scanner-alb-sg" \
  --region us-east-2 \
  --query 'SecurityGroups[*].{Id:GroupId,Nome:GroupName,Inbound:IpPermissions[*].{Porta:FromPort,Proto:IpProtocol,CIDRs:IpRanges[*].CidrIp,SGSources:UserIdGroupPairs[*].GroupId}}' \
  --output json
```

❌ Crítico se: porta 22 com `0.0.0.0/0`, ou porta da app exposta diretamente para internet

---

## 6. S3 — Public Access Block

```bash
for BUCKET in $(aws s3api list-buckets --query 'Buckets[?contains(Name, `security-scanner`)].Name' --output text); do
  echo "=== $BUCKET ==="
  aws s3api get-public-access-block --bucket $BUCKET 2>&1
  aws s3api get-bucket-encryption --bucket $BUCKET --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>&1
done
```

✅ Esperado: todos os 4 bloqueios públicos `true` e criptografia habilitada

---

## 7. DynamoDB — acesso às tabelas de autenticação

```bash
aws iam get-role-policy \
  --role-name security-scanner-role \
  --policy-name security-scanner-dynamodb-auth \
  --query 'PolicyDocument' \
  --output json 2>&1 || echo "Policy não encontrada"
```

⚠️ Se existir: verifique se `dynamodb:Scan` está habilitado na tabela `security-scanner-users` (permite dump completo de usuários)

---

## 8. WAF — modo de enforcement

```bash
aws wafv2 get-web-acl \
  --name security-scanner-production-waf \
  --id 7fa646b2-4cd6-4b54-abce-95a3444c41d3 \
  --scope REGIONAL \
  --region us-east-2 \
  --query 'WebACL.{DefaultAction:DefaultAction,Rules:Rules[*].{Nome:Name,Prioridade:Priority,Acao:Action,Override:OverrideAction}}' \
  --output json
```

✅ Esperado: DefaultAction=Allow com regras em modo Block (não Count)

---

## 9. Secrets Manager — tokens ativos

```bash
aws secretsmanager list-secrets \
  --region us-east-2 \
  --query 'SecretList[*].{Nome:Name,UltimaRotacao:LastRotatedDate,ProximaRotacao:NextRotationDate,RotacaoAtiva:RotationEnabled}' \
  --output json
```

⚠️ Se `RotationEnabled=false`: secrets sem rotação automática

---

## Formato do relatório final

Apresente uma tabela de score de segurança:

| Categoria | Status | Severidade | Detalhe |
|---|---|---|---|
| IMDSv2 instâncias | ✅/❌ | HIGH/OK | ... |
| IMDSv2 launch templates | ✅/❌ | HIGH/OK | ... |
| IAM S3 permissões | ✅/❌ | HIGH/OK | ... |
| IAM drift | ✅/❌ | MEDIUM/OK | ... |
| Security Groups | ✅/❌ | HIGH/OK | ... |
| S3 public access | ✅/❌ | HIGH/OK | ... |
| DynamoDB acesso | ✅/❌ | MEDIUM/OK | ... |
| WAF enforcement | ✅/❌ | MEDIUM/OK | ... |
| Secrets rotação | ✅/❌ | MEDIUM/OK | ... |

Finalize com: **Score de Segurança: X/9 categorias OK** e lista das ações corretivas prioritárias.
