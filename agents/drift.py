"""
drift.py — Detecta desvio entre AWS real e Terraform esperado.
Apenas leitura — nunca altera o ambiente.
"""
from __future__ import annotations

from datetime import datetime

import boto3

from .notifier import notify_incident, Severity

REGION    = "us-east-2"
ROLE_NAME = "security-scanner-role"

EXPECTED_INLINE = {
    "security-scanner-s3-readonly",
    "security-scanner-cloudwatch-logs",
    "security-scanner-ec2-describe",
    "security-scanner-ssm-parameters",
    "security-scanner-s3-db",
    "security-scanner-secrets-manager",
}

EXPECTED_MANAGED = {
    "CloudWatchAgentServerPolicy",
    "AmazonSSMManagedInstanceCore",
}

EXPECTED_LT_IMDS = {"HttpTokens": "required", "HttpPutResponseHopLimit": 1}


def run() -> dict:
    """Executa todas as verificações de drift e notifica se encontrar desvios."""
    findings = []
    iam      = boto3.client("iam")
    ec2      = boto3.client("ec2", region_name=REGION)

    # 1. Policies inline fora do Terraform
    inline = set(iam.list_role_policies(RoleName=ROLE_NAME)["PolicyNames"])
    extra  = inline - EXPECTED_INLINE
    if extra:
        findings.append({
            "category": "IAM Policies extras",
            "severity": "MEDIUM",
            "detail": f"Policies fora do IaC: {', '.join(extra)}",
        })

    # 2. Managed policies inesperadas
    managed = {p["PolicyName"] for p in
               iam.list_attached_role_policies(RoleName=ROLE_NAME)["AttachedPolicies"]}
    extra_managed = managed - EXPECTED_MANAGED
    if extra_managed:
        findings.append({
            "category": "Managed Policies extras",
            "severity": "MEDIUM",
            "detail": f"Managed policies fora do IaC: {', '.join(extra_managed)}",
        })

    # 3. Security Groups duplicados
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["security-scanner-ec2-sg"]}]
    )["SecurityGroups"]
    if len(sgs) > 1:
        findings.append({
            "category": "Security Groups duplicados",
            "severity": "HIGH",
            "detail": f"{len(sgs)} SGs com mesmo nome encontrados",
        })

    # 4. IMDSv2 nos Launch Templates
    lts = ec2.describe_launch_templates(
        Filters=[{"Name": "launch-template-name", "Values": ["security-scanner-*"]}]
    )["LaunchTemplates"]

    for lt in lts:
        versions = ec2.describe_launch_template_versions(
            LaunchTemplateId=lt["LaunchTemplateId"], Versions=["$Latest"]
        )["LaunchTemplateVersions"]
        if versions:
            imds = versions[0]["LaunchTemplateData"].get("MetadataOptions", {})
            if imds.get("HttpTokens") != "required" or imds.get("HttpPutResponseHopLimit") != 1:
                findings.append({
                    "category": f"IMDSv2 — {lt['LaunchTemplateName']}",
                    "severity": "HIGH",
                    "detail": f"HttpTokens={imds.get('HttpTokens')}, HopLimit={imds.get('HttpPutResponseHopLimit')}",
                })

    # Notifica se houver drift
    if findings:
        report = "\n".join(
            f"  [{f['severity']}] {f['category']}: {f['detail']}" for f in findings
        )
        notify_incident(
            agent="DriftAgent",
            description=f"Drift detectado em {datetime.utcnow().strftime('%d/%m/%Y')}:\n\n{report}\n\n"
                        f"Arquivo de referência: terraform-drift/iam_drift_policies.tf",
            severity=Severity.HIGH if any(f["severity"] == "HIGH" for f in findings) else Severity.INFO,
        )
        print(f"[DriftAgent] {len(findings)} desvio(s) encontrado(s)")
    else:
        print("[DriftAgent] Nenhum drift detectado — ambiente alinhado com Terraform")

    return {"status": "drift" if findings else "clean", "findings": findings}
