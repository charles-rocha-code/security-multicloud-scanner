# Security Multicloud Scanner — Enterprise Edition

A production-grade **Cloud Security Posture Management (CSPM)** and **Cloud Workload Protection Platform (CWPP)** deployed on AWS with high availability. Performs deep security audits across object storage, IAM configurations, and Kubernetes clusters for AWS, Google Cloud, and Azure — with MFA-gated access, an interactive enterprise dashboard, password recovery via email, and automated executive report generation in PDF and DOCX.

---

## Features

- **IAM / CSPM scanning** — checks identity and access configuration against CIS Benchmarks for AWS, GCP, and Azure (Entra ID)
- **Storage scanning** — audits AWS S3, Google Cloud Storage, and Azure Blob Storage for public exposure, dangerous ACLs, unencrypted objects, and misconfigurations
- **Kubernetes scanning** — audits cluster RBAC, pod security, network policies, and workload configurations
- **Risk scoring** — 0–100 composite score with CRITICAL / HIGH / MEDIUM / LOW severity breakdown
- **Compliance mapping** — CIS Benchmarks, NIST SP 800-53, ISO 27001, PCI-DSS, HIPAA, AWS Well-Architected, Google Security Foundations, Microsoft Cloud Security Benchmark
- **Executive reports** — PDF and DOCX with narrative, gauges, charts, top-10 findings, and provider-specific recommendations
- **Interactive dashboard** — vulnerability heatmap, risk funnel, top findings, prioritized recommendations, sortable scan history
- **MFA authentication** — TOTP via Google Authenticator with QR code setup
- **Password recovery** — email reset flow with 30-minute signed token via SMTP / SES
- **Rate limiting** — per-IP brute-force protection on login and password reset endpoints

---

## AWS Infrastructure

![AWS Infrastructure — Security Multicloud Scanner (HA)](docs/aws-architecture.png)

> High availability in `us-east-2` · WAF v2 · ALB · Auto Scaling Group (2–4 EC2) · TLS 1.3 via ACM · Terraform IaC

### Current vs Future

![Current vs Future Architecture](docs/architecture-current-vs-future.png)

> **Current:** EC2 ASG + WAF v2 + ALB + NAT Gateways  
> **Future:** ECS Fargate + CloudFront + DynamoDB + S3 + Secrets Manager

---

## Infrastructure Agents

Autonomous agents that monitor and manage the AWS environment, triggered by Amazon EventBridge and notified via Amazon SES with one-click approval buttons.

### Architecture

```
EventBridge (rate 20 min) ──► Lambda: security-scanner-watchdog
EventBridge (cron 08h BRT) ─► Lambda: security-scanner-watchdog
                                        │
                          ┌─────────────┼──────────────┐
                          ▼             ▼              ▼
                    WatchdogAgent  IncidentAgent   DriftAgent
                    (paralelo)          │
                    5 checks       ┌────┴────────┐
                    em paralelo    ▼             ▼
                               ScalerAgent   WAFAgent
                                        │
                                   DeployAgent
                                        │
                                        ▼
                         Amazon SES ──► Email com botões
                                   [✅ APROVAR] [❌ REJEITAR]
                                        │
                         Lambda Function URL ──► Executa ação
```

### Agents

| Agent | File | Trigger | Actions |
|---|---|---|---|
| **WatchdogAgent** | `agents/watchdog.py` | EventBridge every 20 min | Monitors CPU, alarms, target health, ASG, logs — **parallel execution** |
| **IncidentAgent** | `agents/incident.py` | Called by Watchdog on anomaly | Diagnoses root cause, coordinates response |
| **ScalerAgent** | `agents/scaler.py` | Called by Incident | Scale up +1 (auto), scale down (approval required) |
| **DeployAgent** | `agents/deploy.py` | Manual | Blue-green promote and rollback (always requires approval) |
| **WAFAgent** | `agents/waf_agent.py` | Called by Incident | Auto-blocks public IPs on attack (private IPs filtered), unblock requires approval |
| **DriftAgent** | `agents/drift.py` | EventBridge daily 08h BRT | Detects IAM, SG and IMDS drift from Terraform |

### Notification Flow

| Event | Type | Channel |
|---|---|---|
| Anomaly detected | Immediate alert | Email via SES |
| Agent requires approval | **Email with ✅ APROVAR / ❌ REJEITAR buttons** | Click → Lambda Function URL → executes action |
| Action executed | Confirmation | Email via SES |
| Drift report | Daily summary 08h BRT | Email via SES |

**Sender:** `alertas@oisolucoes.app.br` (domain verified in Amazon SES `us-east-1`)  
**Reply-To:** `charles.rocha@oi.net.br` (replies stay in inbox, not bounced to sender)

### Approval Gate — one-click email

Actions requiring approval generate a UUID token stored in DynamoDB (TTL 24h) and send an email with two buttons:

```
┌─────────────────────────────────────────────────────┐
│ ⚠️ ScalerAgent aguarda aprovação                    │
│                                                     │
│ Ação: Aumentar capacidade: 2 → 3 instâncias         │
│ CPU média: 84% nos últimos 5 minutos                │
│                                                     │
│   [  ✅ APROVAR  ]      [  ❌ REJEITAR  ]           │
│                                                     │
│ Link expira em 24h · uso único                      │
└─────────────────────────────────────────────────────┘
```

Click flow:
```
Click [✅ APROVAR]
  → GET https://<lambda-url>/approve?token=<uuid>
  → DynamoDB: validate + delete token (single-use)
  → orchestrator.run("scale", "3")
  → SES: confirmation email
  → HTML page: "Ação aprovada e executada"
```

Token security:
- UUID v4 (122 bits random) — unguessable
- Single-use: deleted on first click
- Expires in 24h via DynamoDB TTL
- HTTPS only

### Running Agents Manually

```bash
cd security-multicloud-scanner

# Full health check + auto incident response
python -m agents.orchestrator watchdog

# Drift detection
python -m agents.orchestrator drift

# WAF status
python -m agents.orchestrator waf

# Scale ASG
python -m agents.orchestrator scale up
python -m agents.orchestrator scale down
python -m agents.orchestrator scale 3

# Blue-green deploy
python -m agents.orchestrator deploy status
python -m agents.orchestrator deploy promote
python -m agents.orchestrator deploy rollback
```

### Approval Gates

Actions with high blast radius require human approval via email button click:

```
AUTOMATIC (no approval needed):
  ✅ Scale up +1 when CPU > 80%
  ✅ Block IP when attack confirmed in logs
  ✅ Drift report (read-only)

REQUIRES APPROVAL (click button in email):
  🔒 Scale down
  🔒 Scale up > +1
  🔒 Blue-green promote (switches production traffic)
  🔒 Blue-green rollback
  🔒 Unblock IP from WAF
```

### AWS Resources

| Resource | Name | Spec |
|---|---|---|
| Lambda | `security-scanner-watchdog` | Python 3.12 · **128 MB** · 120s timeout |
| Lambda | `security-scanner-cve-updater` | Python 3.12 · 256 MB · 300s timeout |
| **Lambda Function URL** | `wgg2j4sakb3f46xt7i74he5rfm0urova.lambda-url.us-east-2.on.aws` | Auth: NONE (secured by token) |
| EventBridge Rule | `security-scanner-watchdog-15min` | **rate(20 minutes)** · ENABLED |
| EventBridge Rule | `security-scanner-drift-daily` | cron(0 11 * * ? *) → 08h BRT · ENABLED |
| EventBridge Rule | `security-scanner-cve-updater-weekly` | cron(0 3 ? * MON *) · ENABLED |
| DynamoDB | `security-scanner-sessions` | PAY_PER_REQUEST · TTL enabled (stores approval tokens) |
| DynamoDB | `security-scanner-users` | PAY_PER_REQUEST · PITR enabled |
| WAF | `security-scanner-production-waf` | REGIONAL · 17 rules · blocked + trusted IP sets |
| SES Identity | `oisolucoes.app.br` | Verified domain — sender |
| SES Identity | `charles.rocha@oi.net.br` | Verified recipient |
| CloudWatch Logs | `/aws/lambda/security-scanner-watchdog` | **Retention: 30 days** |
| CloudWatch Logs | `/aws/lambda/security-scanner-cve-updater` | Retention: 30 days |

---

## Performance Optimizations (2026-07-01)

Applied to reduce Lambda compute consumption and improve detection speed.

### Before vs After

| Metric | Before | After | Change |
|---|---|---|---|
| WatchdogAgent avg duration | 3.099s | ~0.8s | **−74%** |
| Monthly invocations | ~1,135 | ~850 | **−25%** |
| Lambda GB-seconds/month | 880 | ~113 | **−87%** |
| Lambda memory | 256 MB | **128 MB** | **−50%** |
| EventBridge interval | 15 min | **20 min** | **−25% invocations** |
| Log retention | None (∞) | **30 days** | **Controlled** |
| Monthly cost | $0.00 | $0.00 | Free tier |

### Opt 1 — WatchdogAgent: parallel execution

The 5 health checks now run concurrently using `ThreadPoolExecutor(max_workers=5)` instead of sequentially. The total duration is now determined by the slowest single check (~800ms) instead of the sum of all checks (~3.1s).

```python
# Before: sequential
alarms = get_alarms_in_alarm()      # 800ms
cpu    = get_cpu_average(ASG_MAIN)  # 600ms
health = get_target_health(TG_MAIN) # 600ms  → total: ~3.1s
asg    = describe_asg(ASG_MAIN)     # 600ms
errors = get_error_logs(minutes=30) # 500ms

# After: parallel
with ThreadPoolExecutor(max_workers=5) as pool:
    futures = {pool.submit(fn): name for name, fn in checks.items()}
    # all 5 run simultaneously → total: ~800ms
```

### Opt 2 — Lambda memory: 256 MB → 128 MB

Python + boto3 runtime uses ~55-80 MB. Memory reduced to 128 MB, cutting compute cost by 50% when above the free tier.

### Opt 3 — EventBridge interval: 15 min → 20 min

Reduces invocations from ~2,160 to ~1,620 per month (−25%) while maintaining fast anomaly detection.

### Opt 4 — CloudWatch Logs retention: none → 30 days

Both Lambda log groups now have a 30-day retention policy. Without it, logs from 265+ weekly executions would accumulate indefinitely.

---

## WAF Bug Fixes (2026-07-01)

Five issues found and corrected in `agents/waf_agent.py` and `agents/tools/aws.py`:

| # | Severity | Issue | Fix |
|---|---|---|---|
| 1 | **Critical** | `scan_logs_for_attacks()` regex extracted all IPs from logs — could auto-block AWS internal IPs (`169.254.169.254` IMDS, `10.x` VPC, `172.x` ALB) | Added `_is_private_ip()` filter using Python `ipaddress` module — only public routable IPs are ever blocked |
| 2 | **High** | Double email per auto-blocked IP — `block_ip()` called `notify_action_executed()` then `scan_logs_for_attacks()` called `notify_incident()` for the same event | Removed duplicate `notify_incident()` call from scan loop |
| 3 | **Medium** | `get_error_logs()` had `limit=50` — only first 50 log events analyzed regardless of attack volume | Replaced with paginated loop using `nextToken`, fetches up to 5,000 events per scan |
| 4 | **Low** | `unblock_ip()` created a DynamoDB token and sent approval email even when IP was not in the blocked list | Added pre-check: queries IP Set before creating token; returns `status: skipped` if IP not found |
| 5 | **Connection** | No error handling on AWS API calls — throttling or network failures crashed the Lambda silently | Added `_retry()` with exponential backoff (3 attempts) for `Throttling`, `ServiceUnavailable`, and `ConnectTimeout` on all WAF API calls |

---

## Claude Code Skills

Slash commands for managing the AWS environment directly from Claude Code CLI:

| Skill | Command | Description |
|---|---|---|
| WAF | `/waf status \| block <ip> \| unblock <ip>` | Manage WAFv2 rules and IP sets |
| Health | `/health` | Full environment health check (EC2, ALB, CloudWatch alarms) |
| Scale | `/scale up \| down \| <N>` | Manage ASG capacity (min 2, max 4) |
| Logs | `/logs 30m \| 1h \| 2h` | Search CloudWatch error logs |
| Drift | `/drift` | Detect drift between AWS and Terraform |
| Security Audit | `/security-audit` | Full security audit (IMDSv2, IAM, SGs, WAF, S3, Secrets) |
| Blue-Green | `/blue-green status \| promote \| rollback` | Blue-green deployment management |

Skills are stored in `.claude/skills/` and globally available at `~/.claude/skills/`.

---

## Security & Infrastructure Fixes

### 2026-06-28 — Drift Detection Fixes

| Finding | Fix | Impact |
|---|---|---|
| IMDSv2 optional on green launch template | Updated to `HttpTokens=required`, `HopLimit=1` (v14) | Zero downtime — template only |
| `dynamodb:Scan` on users table | Removed `Scan` permission from `security-scanner-dynamodb-auth` | Zero downtime |
| IAM policies outside Terraform | Documented in `iam_drift_policies.tf` with import commands | Drift remediated |
| Duplicate `aws_iam_role_policy.dynamodb_auth` in Terraform | Removed from `iam_drift_policies.tf` — already managed in `dynamo.tf` | `terraform init` unblocked |

### 2026-07-01 — Notification & Email Fixes

| Finding | Fix |
|---|---|
| Approval emails bounced (5.1.2 DNS error) when admin replied | Added `ReplyToAddresses` pointing to admin inbox — replies no longer go to SES-only sender |
| Approval text said "reply with APROVAR/REJEITAR" — no receiver existed | Replaced with Lambda Function URL buttons (✅ APROVAR / ❌ REJEITAR) with DynamoDB token gate |

---

## Supported Providers & Scan Types

| Provider | Storage Scan | IAM / CSPM Scan |
|---|---|---|
| **AWS** | S3 — public + authenticated (up to 5 000 objects) | IAM — CIS AWS Foundations Benchmark v1.4 |
| **Google Cloud** | GCS — public + authenticated | GCP IAM — CIS GCP Foundations Benchmark v2.0 |
| **Azure** | Blob Storage — public + authenticated | Azure IAM / Entra ID — CIS Azure Foundations Benchmark v2.0 |
| **Kubernetes** | — | RBAC, pod security, network policies, secrets hygiene |

---

## IAM / CSPM Checks

### AWS IAM — CIS AWS Foundations Benchmark v1.4

| Check | Severity | CIS Control |
|---|---|---|
| Root account MFA disabled | CRITICAL | 1.3 |
| Root account with active access keys | CRITICAL | 1.3 |
| Password policy: min length < 14 | MEDIUM | 1.8 |
| Password policy: no expiration (> 90 days) | MEDIUM | 1.11 |
| Password policy: no reuse prevention (< 24) | LOW | 1.10 |
| Console user without MFA | HIGH | 1.10 |
| Access key not rotated in > 90 days | HIGH | 1.14 |
| User with direct AdministratorAccess | MEDIUM | 1.16 |
| Inline policy attached directly to user | LOW | 1.16 |

### GCP IAM — CIS GCP Foundations Benchmark v2.0

| Check | Severity |
|---|---|
| Public IAM binding (`allUsers` / `allAuthenticatedUsers`) on project | CRITICAL |
| Primitive role (`roles/owner`, `roles/editor`) on service account | HIGH |
| High-risk role (`serviceAccountAdmin`, `organizationAdmin`, etc.) | HIGH |
| Excess project owners (> 2) | MEDIUM |
| SA key not rotated in > 90 days | HIGH |
| SA with more than 1 active user-managed key | MEDIUM |
| Default compute SA with `roles/editor` | HIGH |

### Azure IAM / Entra ID — CIS Azure Foundations Benchmark v2.0

| Check | Severity | CIS Control |
|---|---|---|
| No Conditional Access Policy enforcing MFA for all users | CRITICAL | 1.1 |
| Excess Global Administrators (> 4) | HIGH | 1.2 |
| Guest user with Global Admin or Privileged Role Admin role | CRITICAL | 1.3 |
| Subscription owners count > 3 | MEDIUM | 1.23 |
| Custom role with wildcard actions (`*`, `/*`, `Microsoft.Authorization/*`) | HIGH | 1.24 |
| Active Classic Administrator (Co-Admin — deprecated since 2023) | HIGH | — |
| Role assignment scoped to root or management group | HIGH | — |
| Expired Service Principal credential (client secret / certificate) | HIGH | — |
| Service Principal credential expiring in ≤ 30 days | MEDIUM | — |

---

## Dashboard

### Scan Interface
- Provider selector: AWS S3, GCS, Azure Blob, Kubernetes, AWS IAM, GCP IAM, Azure IAM / Entra ID
- Public scan mode (no credentials, URL-based auto-detection)
- Private scan mode with per-provider credential fields
- Dedicated scan buttons per IAM provider — no shared-button conflicts

### Visualizations
- **KPI cards** — total findings, exposure status, composite risk score, C/H/M/L breakdown with count-up animations and semantic color accents
- **Severity distribution chart** — animated doughnut
- **Vulnerability heatmap** — findings across severity × category grid with rich tooltips (shows object/entity names)
- **Risk Overview** — card-based layout (Prisma Cloud style) with sparkline animations
- **Prioritized findings funnel** — narrows from total → CRITICAL, sorted by risk score
- **Top findings by category** — animated horizontal bar chart
- **Security recommendations** — priority-labeled cards (Urgent / Critical / High / Info) derived from scan data
- **Scan history** — paginated table with sortable columns, severity pills, copy-path button, toast notifications, per-entry severity bar

### Export
- CSV export of all findings
- Executive report trigger (PDF + DOCX) with dynamic severity pill counts

---

## Executive Reports

Reports are generated by `generate_report.py` (ReportLab + python-docx + Matplotlib):

- **Cover page** — provider name, scan target, date, global risk gauge
- **Section 1 — Executive Summary** — provider-specific narrative, risk level, KPI metrics table
- **Section 2 — Risk Overview** — severity distribution chart, findings funnel, top-findings-by-category bar chart, full findings table with remediation
- **Section 3 — Compliance** — per-provider control mapping:
  - AWS IAM → CIS AWS v1.4, ISO 27001, NIST SP 800-53, AWS Well-Architected
  - GCP IAM → CIS GCP v2.0, ISO 27001, NIST, Google Security Foundations
  - Azure IAM → CIS Azure v2.0, ISO 27001, NIST IA-2/IA-5, Microsoft Cloud Security Benchmark
  - Storage / K8s → CIS, PCI-DSS, HIPAA, NIST
- **Section 4 — Recommendations** — prioritized actions with timelines (immediate / 30-day / 90-day)
- **Charts** — global risk gauge, up to 9 per-category gauges, category bar chart with external total labels

---

## API Reference

### Health

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check — `{"status":"ok"}` |

### Authentication

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/auth/register` | Register new user | Public |
| `POST` | `/auth/login` | Login + MFA code | Public |
| `POST` | `/auth/logout` | Invalidate session | Token |
| `POST` | `/auth/mfa/setup` | Generate TOTP secret + QR code | Token |
| `POST` | `/auth/mfa/verify` | Activate MFA with OTP | Token |
| `GET` | `/auth/mfa/status` | Check MFA enrollment | Token |
| `POST` | `/forgot-password` | Send password reset email | Public |
| `POST` | `/reset-password` | Reset password with token | Public |

### Storage Scans

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `GET` | `/scan/{target}` | Public scan — auto-detect provider from URL | MFA |
| `POST` | `/scan/public` | Public scan with explicit provider | MFA |
| `POST` | `/scan/authenticated` | Authenticated scan (S3 / GCS / Azure Blob) | MFA |

### IAM / CSPM Scans

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/scan/iam` | AWS IAM audit | MFA |
| `POST` | `/scan/iam/gcp` | GCP IAM audit | MFA |
| `POST` | `/scan/iam/azure` | Azure IAM / Entra ID audit | MFA |

### Kubernetes

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/scan/k8s` | Kubernetes cluster audit (kubeconfig) | MFA |

### Reports & Dashboard

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `GET` | `/dashboard` | Interactive web dashboard | MFA |
| `GET` | `/api/dashboard` | Current user data (JSON) | MFA |
| `POST` | `/generate-report` | Generate PDF + DOCX executive report | MFA |
| `GET` | `/download-report/{filename}` | Download generated report | MFA |

---

## Installation

```bash
git clone https://github.com/charles-rocha-code/s3_auditor_enteprise.git
cd s3_auditor_enteprise

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

Copy `.env.example` to `.env` and configure:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=xxxx xxxx xxxx xxxx
APP_BASE_URL=https://scanner.yourdomain.com
```

Start the server:

```bash
uvicorn api_with_mfa:app --host 0.0.0.0 --port 8000
```

---

## Usage Examples

### AWS IAM Scan

```bash
curl -X POST http://localhost:8000/scan/iam \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "...",
    "region_name": "us-east-1"
  }'
```

Requires `SecurityAudit` or `ReadOnlyAccess` IAM policy on the credentials.

### GCP IAM Scan

```bash
curl -X POST http://localhost:8000/scan/iam/gcp \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "service_account_key": {
      "type": "service_account",
      "project_id": "my-project",
      "private_key_id": "...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...",
      "client_email": "auditor@my-project.iam.gserviceaccount.com"
    }
  }'
```

Service account requires `roles/viewer` + `roles/iam.securityReviewer` on the project.

### Azure IAM / Entra ID Scan

```bash
curl -X POST http://localhost:8000/scan/iam/azure \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "..."
  }'
```

App Registration requires:
- Azure RBAC: `Reader` on the subscription
- Microsoft Graph (application, admin-consented): `Policy.Read.All`, `Directory.Read.All`, `RoleManagement.Read.All`

### AWS S3 Authenticated Scan

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "AWS_S3",
    "bucket": "my-bucket",
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "...",
    "region": "us-east-1",
    "max_objects": 5000
  }'
```

### GCS Authenticated Scan

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "GCS",
    "bucket": "my-gcs-bucket",
    "service_account_key": {
      "type": "service_account",
      "project_id": "my-project",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...",
      "client_email": "sa@project.iam.gserviceaccount.com"
    },
    "max_objects": 1000
  }'
```

### Azure Blob Storage Scan

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "AZURE_BLOB",
    "bucket": "myaccount.blob.core.windows.net",
    "azure_connection_string": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net",
    "max_objects": 1000
  }'
```

### Kubernetes Scan

```bash
curl -X POST http://localhost:8000/scan/k8s \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "kubeconfig": "<base64-or-raw-yaml-kubeconfig>",
    "context": "my-context",
    "namespace": "production",
    "max_resources": 1000
  }'
```

Generate kubeconfig for managed clusters:
```bash
aws eks update-kubeconfig --name my-cluster --region us-east-1   # EKS
gcloud container clusters get-credentials my-cluster --zone us-central1-a  # GKE
az aks get-credentials --resource-group my-rg --name my-cluster  # AKS
```

### Generate Executive Report

```bash
curl -X POST http://localhost:8000/generate-report \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "pdf",
    "title": "Q2 2026 Cloud Security Audit",
    "client_name": "Acme Corp"
  }'
```

---

## Kubernetes Security Checks

The auditor `auditor_k8s_authenticated.py` runs 5 check categories:

### Workload Security

| Severity | Check |
|---|---|
| CRITICAL | Container with `privileged: true` |
| HIGH | `hostNetwork: true` — shares node network namespace |
| HIGH | `hostPID: true` — accesses node processes |
| HIGH | `hostIPC: true` |
| HIGH | Container running as root (`runAsUser: 0` or missing `runAsNonRoot`) |
| MEDIUM | Container missing `resources.limits` (CPU / memory) |

### RBAC

| Severity | Check |
|---|---|
| CRITICAL | `ClusterRole` with `verbs: ["*"]` and `resources: ["*"]` |

### Secrets & ConfigMaps

| Severity | Check |
|---|---|
| CRITICAL | `ConfigMap` with plaintext sensitive keys (`password`, `secret`, `token`, `apikey`, `private_key`) |
| MEDIUM | `Secret` mounted as environment variable (can leak in logs) |

### Network Exposure

| Severity | Check |
|---|---|
| MEDIUM | `LoadBalancer` or `NodePort` service exposed externally |
| HIGH | Namespace with no `NetworkPolicy` (unrestricted pod-to-pod traffic) |

### Anonymous Authentication

| Severity | Check |
|---|---|
| CRITICAL | `ClusterRoleBinding` to `system:anonymous` or `system:unauthenticated` |

---

## Architecture

```
FastAPI (api_with_mfa.py)
│
├── Auth Layer
│   ├── auth_mfa.py                         — TOTP (pyotp) + JWT sessions
│   ├── Rate limiting                        — slowapi, per-IP throttle
│   ├── Password reset                       — SMTP / SES signed token flow
│   └── templates/login.html                — Split-panel login UI
│
├── Storage Auditors
│   ├── auditor.py                           — AWS S3 (public)
│   ├── auditor_s3_authenticated.py          — AWS S3 (authenticated, up to 5 000 objects)
│   ├── auditor_gcs.py                       — Google Cloud Storage (public)
│   ├── auditor_gcs_authenticated.py         — GCS (authenticated)
│   ├── auditor_azure.py                     — Azure Blob Storage (public)
│   └── auditor_azure_authenticated.py       — Azure Blob (authenticated)
│
├── IAM / CSPM Auditors
│   ├── auditor_iam.py                       — AWS IAM (CIS AWS v1.4)
│   ├── auditor_iam_gcp.py                   — GCP IAM (CIS GCP v2.0)
│   └── auditor_iam_azure.py                 — Azure IAM / Entra ID (CIS Azure v2.0)
│
├── Infrastructure Auditors
│   └── auditor_k8s_authenticated.py         — Kubernetes RBAC + pod security
│
├── Risk Engine
│   └── engine_risk.py                       — Composite scoring + compliance mapping
│
├── Report Generator
│   └── generate_report.py                   — PDF (ReportLab) + DOCX (python-docx) + charts (Matplotlib)
│
└── Dashboard
    └── templates/dashboard.html             — Single-page app
```

---

## File Structure

```
s3_auditor_enteprise/
├── api_with_mfa.py                     # Main server — all endpoints, auth, orchestration
├── auth_mfa.py                         # TOTP + JWT + password reset implementation
│
├── auditor.py                          # AWS S3 public auditor
├── auditor_s3_authenticated.py         # AWS S3 authenticated auditor
├── auditor_gcs.py                      # GCS public auditor
├── auditor_gcs_authenticated.py        # GCS authenticated auditor
├── auditor_azure.py                    # Azure Blob public auditor
├── auditor_azure_authenticated.py      # Azure Blob authenticated auditor
│
├── auditor_iam.py                      # AWS IAM CSPM auditor (CIS AWS v1.4)
├── auditor_iam_gcp.py                  # GCP IAM CSPM auditor (CIS GCP v2.0)
├── auditor_iam_azure.py                # Azure IAM / Entra ID auditor (CIS Azure v2.0)
│
├── auditor_k8s_authenticated.py        # Kubernetes security auditor
├── engine_risk.py                      # Risk scoring and compliance mapping
├── generate_report.py                  # PDF + DOCX executive report generator
│
├── requirements.txt                    # Python dependencies
├── deploy_mfa.sh                       # Production deploy script
├── reset_users.sh                      # Reset user database
│
└── templates/
    ├── dashboard.html                  # Main SPA dashboard
    ├── login.html                      # Split-panel login + MFA setup
    ├── mfa_setup.html                  # TOTP QR code setup page
    ├── forgot_password.html            # Password recovery form
    └── reset_password.html             # Password reset form
```

---

## Configuration

The system uses local JSON files for persistence:

| File | Description |
|---|---|
| `users_db.json` | User store (gitignored) |
| `sessions_db.json` | Active sessions (gitignored) |
| `reports_executive/` | Generated reports (gitignored) |

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `SMTP_HOST` | SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | Sender address | `you@email.com` |
| `SMTP_PASS` | App password | `xxxx xxxx xxxx xxxx` |
| `APP_BASE_URL` | Public base URL | `https://scanner.yourdomain.com` |

---

## Security Design

- **Credentials are never stored** — held in memory during the scan request only, discarded immediately after
- **MFA required** for all scan, report, and dashboard endpoints
- **JWT sessions** with 24-hour expiration
- **Rate limiting** — 1 login/min, 3 password-reset requests/hour per IP (slowapi)
- **Input validation** via Pydantic v2 on all POST endpoints
- **Password reset tokens** are single-use and expire after 30 minutes
- `.gitignore` excludes `users_db.json`, `sessions_db.json`, `reports_executive/`, `venv/`, `*.env`, `*.pem`

---

## Dependencies

```
fastapi, uvicorn, starlette             — API server
boto3                                   — AWS S3
google-cloud-storage                    — GCS
google-api-python-client                — GCP IAM APIs (Cloud Resource Manager + IAM)
google-auth-httplib2                    — GCP auth transport
azure-storage-blob                      — Azure Blob Storage
azure-identity                          — Azure ClientSecretCredential
azure-mgmt-authorization                — Azure RBAC (role assignments, definitions)
kubernetes, pyyaml                      — Kubernetes audit
pyotp, qrcode, Pillow                   — TOTP MFA + QR code generation
python-dotenv                           — Environment config
reportlab, python-docx                  — PDF and DOCX generation
matplotlib, numpy                       — Charts and gauges in reports
slowapi                                 — Rate limiting
```

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Author

Developed by **Charles Rocha** — enterprise cloud security tooling for multi-provider environments.
