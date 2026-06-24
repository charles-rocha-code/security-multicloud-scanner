"""
cve_mapping.py — Maps security findings to CIS Benchmark, CWE, NIST 800-53, and CVE identifiers.

Cloud misconfigurations (IAM, S3, GCS, Azure) are classified via CIS Benchmark controls and CWE;
they rarely receive individual CVEs. Kubernetes container-escape vulnerabilities DO have real CVEs
(e.g., CVE-2021-25741). The k8s_cves_cache.json file (updated weekly by cve_updater.py) enriches
K8s findings with fresh CVEs from NVD.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

# ── NVD K8s CVE cache (populated by cve_updater Lambda weekly) ───────────────
_CACHE_PATH = os.path.join(os.path.dirname(__file__), "k8s_cves_cache.json")
_K8S_CVE_INDEX: Dict[str, List[str]] = {}


def _load_cve_index() -> Dict[str, List[str]]:
    # Try S3 first (written by Lambda), fall back to local file
    try:
        import boto3
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
        bucket = os.environ.get("DB_S3_BUCKET", "security-scanner-db-442042548551")
        resp = s3.get_object(Bucket=bucket, Key="cve-cache/k8s_cves_cache.json")
        return json.loads(resp["Body"].read().decode("utf-8")).get("tagged", {})
    except Exception:
        pass
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as _f:
            return json.load(_f).get("tagged", {})
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


_K8S_CVE_INDEX = _load_cve_index()

# Static CVE fallback for K8s (known at time of writing; cache supersedes these)
_K8S_STATIC_CVES: Dict[str, List[str]] = {
    "hostpath": ["CVE-2021-25741", "CVE-2017-1002101"],
    "subpath":  ["CVE-2021-25741"],
    "volume":   ["CVE-2017-1002101"],
}


def _k8s_cves(tags: List[str]) -> List[str]:
    seen: set = set()
    result: List[str] = []
    for idx in (_K8S_CVE_INDEX, _K8S_STATIC_CVES):
        for tag in tags:
            for cve in idx.get(tag, []):
                if cve not in seen:
                    seen.add(cve)
                    result.append(cve)
    return result


# ── AWS IAM Rules ─────────────────────────────────────────────────────────────
# (check_substrings, entity_type_substrings, refs_dict)
_AWS_IAM_RULES: List[tuple] = [
    (["mfa desabilitado"],                  ["root"],   {"cis": ["CIS-AWS-1.2"],  "cwe": ["CWE-308"], "nist": ["IA-2(1)", "AC-6(9)"], "cve": []}),
    (["access keys ativas"],                ["root"],   {"cis": ["CIS-AWS-1.3"],  "cwe": ["CWE-798"], "nist": ["AC-2", "IA-5"],       "cve": []}),
    (["política de senha não configurada"], [],         {"cis": ["CIS-AWS-1.4"],  "cwe": ["CWE-521"], "nist": ["IA-5(1)"],            "cve": []}),
    (["comprimento mínimo"],               [],         {"cis": ["CIS-AWS-1.8"],  "cwe": ["CWE-521"], "nist": ["IA-5(1)"],            "cve": []}),
    (["expiração de senha"],               [],         {"cis": ["CIS-AWS-1.11"], "cwe": ["CWE-521"], "nist": ["IA-5(1)"],            "cve": []}),
    (["prevenção de reuso"],               [],         {"cis": ["CIS-AWS-1.10"], "cwe": ["CWE-521"], "nist": ["IA-5(1)"],            "cve": []}),
    (["mfa não configurado"],              ["user"],   {"cis": ["CIS-AWS-1.10"], "cwe": ["CWE-308"], "nist": ["IA-2(1)"],            "cve": []}),
    (["console inativo"],                  [],         {"cis": ["CIS-AWS-1.16"], "cwe": ["CWE-613"], "nist": ["AC-2(3)"],            "cve": []}),
    (["sem rotação"],                      [],         {"cis": ["CIS-AWS-1.14"], "cwe": ["CWE-324"], "nist": ["IA-5(1)"],            "cve": []}),
    (["próxima do vencimento"],            [],         {"cis": ["CIS-AWS-1.14"], "cwe": ["CWE-324"], "nist": ["IA-5(1)"],            "cve": []}),
    (["nunca utilizada"],                  [],         {"cis": ["CIS-AWS-1.14"], "cwe": ["CWE-272"], "nist": ["AC-2", "IA-5"],       "cve": []}),
    (["inativa há"],                       [],         {"cis": ["CIS-AWS-1.14"], "cwe": ["CWE-272"], "nist": ["AC-2", "IA-5"],       "cve": []}),
    (["administratoraccess diretamente"],  ["user"],   {"cis": ["CIS-AWS-1.16"], "cwe": ["CWE-269"], "nist": ["AC-6"],               "cve": []}),
    (["wildcard total"],                   [],         {"cis": ["CIS-AWS-1.22"], "cwe": ["CWE-269"], "nist": ["AC-6(1)"],            "cve": []}),
    (["administratoraccess na role"],      ["role"],   {"cis": ["CIS-AWS-1.16"], "cwe": ["CWE-269"], "nist": ["AC-6"],               "cve": []}),
    (["principal=*"],                      [],         {"cis": ["CIS-AWS-1.16"], "cwe": ["CWE-284"], "nist": ["AC-3"],               "cve": []}),
]

# ── GCP IAM Rules ─────────────────────────────────────────────────────────────
_GCP_IAM_RULES: List[tuple] = [
    (["binding iam público"],                    [],                  {"cis": ["CIS-GCP-1.7"], "cwe": ["CWE-284"], "nist": ["AC-3"],          "cve": []}),
    (["sa com roles/owner"],                     ["service-account"], {"cis": ["CIS-GCP-1.3"], "cwe": ["CWE-269"], "nist": ["AC-6"],           "cve": []}),
    (["default service account"],                [],                  {"cis": ["CIS-GCP-4.1"], "cwe": ["CWE-269"], "nist": ["AC-6"],           "cve": []}),
    (["primitive role"],                         [],                  {"cis": ["CIS-GCP-1.3"], "cwe": ["CWE-269"], "nist": ["AC-6"],           "cve": []}),
    (["role de alto risco"],                     [],                  {"cis": ["CIS-GCP-1.3"], "cwe": ["CWE-269"], "nist": ["AC-6"],           "cve": []}),
    (["project owners"],                         [],                  {"cis": ["CIS-GCP-1.2"], "cwe": ["CWE-269"], "nist": ["AC-6"],           "cve": []}),
    (["user-managed keys ativas"],               ["service-account"], {"cis": ["CIS-GCP-4.4"], "cwe": ["CWE-324"], "nist": ["IA-5(1)"],        "cve": []}),
    (["sa key", "sem rotação"],                  [],                  {"cis": ["CIS-GCP-4.3"], "cwe": ["CWE-324"], "nist": ["IA-5(1)"],        "cve": []}),
    (["sa key", "próxima do vencimento"],        [],                  {"cis": ["CIS-GCP-4.3"], "cwe": ["CWE-324"], "nist": ["IA-5(1)"],        "cve": []}),
]

# ── Azure IAM Rules ───────────────────────────────────────────────────────────
_AZURE_IAM_RULES: List[tuple] = [
    (["guest", "role owner"],                    [],  {"cis": ["CIS-Azure-1.23"], "cwe": ["CWE-269"], "nist": ["AC-6"],          "cve": []}),
    (["escopo raiz", "management group"],        [],  {"cis": ["CIS-Azure-1.23"], "cwe": ["CWE-269"], "nist": ["AC-3"],          "cve": []}),
    (["co-administrador clássico"],              [],  {"cis": ["CIS-Azure-1.1"],  "cwe": ["CWE-308"], "nist": ["IA-2(1)"],       "cve": []}),
    (["owners na subscription"],                 [],  {"cis": ["CIS-Azure-1.23"], "cwe": ["CWE-269"], "nist": ["AC-6"],          "cve": []}),
    (["ação wildcard"],                          [],  {"cis": ["CIS-Azure-1.24"], "cwe": ["CWE-269"], "nist": ["AC-6(1)"],       "cve": []}),
    (["sem conditional access", "mfa"],          [],  {"cis": ["CIS-Azure-1.2"],  "cwe": ["CWE-308"], "nist": ["IA-2(1)"],       "cve": []}),
    (["global administrators"],                  [],  {"cis": ["CIS-Azure-1.22"], "cwe": ["CWE-269"], "nist": ["AC-6"],          "cve": []}),
    (["guest", "global administrator"],          [],  {"cis": ["CIS-Azure-1.22"], "cwe": ["CWE-269"], "nist": ["AC-6"],          "cve": []}),
    (["credencial", "expirada"],                 [],  {"cis": ["CIS-Azure-9.x"],  "cwe": ["CWE-324"], "nist": ["IA-5(1)"],       "cve": []}),
    (["credencial", "expira em"],                [],  {"cis": ["CIS-Azure-9.x"],  "cwe": ["CWE-324"], "nist": ["IA-5(1)"],       "cve": []}),
]


# ── K8s Rules ─────────────────────────────────────────────────────────────────
# (reason_keywords, cis, cwe, nist, cve_cache_tags)
_K8S_RULES: List[tuple] = [
    (["hostpath"],          "CIS-K8s-5.2.3", ["CWE-284"], ["AC-3"],          ["hostpath", "subpath"]),
    (["readwritemany"],     "CIS-K8s-5.2",   ["CWE-284"], ["AC-3"],          []),
    (["retain"],            "CIS-K8s-5.2",   ["CWE-404"], ["SC-28"],         []),
    (["secret", "sensív"],  "CIS-K8s-5.4.1", ["CWE-312"], ["SC-28", "IA-5"], ["secret"]),
    (["configmap"],         "CIS-K8s-5.4.1", ["CWE-312"], ["SC-28"],         []),
    (["storageclas"],       "CIS-K8s-5.4",   ["CWE-312"], ["SC-28"],         []),
]


# ── Storage CIS refs by provider ──────────────────────────────────────────────
_STORAGE_CIS: Dict[str, str] = {
    "GCS":   "CIS-GCP-5.1",
    "AZURE": "CIS-Azure-3.1",
}


def _storage_cis(provider: str) -> str:
    p = provider.upper()
    for k, v in _STORAGE_CIS.items():
        if k in p:
            return v
    return "CIS-AWS-2.1.1"


# ── Internal matchers ─────────────────────────────────────────────────────────

def _refs_iam(finding: dict, provider: str) -> dict:
    check = (finding.get("check") or "").lower()
    entity = (finding.get("entity_type") or "").lower()
    p = provider.upper()

    if "GCP" in p:
        rules = _GCP_IAM_RULES
    elif "AZURE" in p:
        rules = _AZURE_IAM_RULES
    else:
        rules = _AWS_IAM_RULES

    for check_kws, entity_kws, refs in rules:
        if all(kw in check for kw in check_kws):
            if not entity_kws or any(kw in entity for kw in entity_kws):
                return refs
    return {"cis": [], "cwe": [], "nist": [], "cve": []}


def _refs_k8s(finding: dict) -> dict:
    combined = ((finding.get("reason") or "") + " " + (finding.get("key") or "")).lower()
    for kws, cis, cwe, nist, cve_tags in _K8S_RULES:
        if all(kw in combined for kw in kws):
            return {"cis": [cis], "cwe": cwe, "nist": nist, "cve": _k8s_cves(cve_tags)}
    return {"cis": [], "cwe": [], "nist": [], "cve": []}


def _refs_storage(finding: dict, provider: str) -> dict:
    key = (finding.get("key") or "").lower()
    reason = (finding.get("reason") or "").lower()
    cis = _storage_cis(provider)

    def r(cwe, nist):
        return {"cis": [cis], "cwe": cwe, "nist": nist, "cve": []}

    if key.endswith(".env") or "ambiente exposto" in reason:
        return r(["CWE-312", "CWE-215"], ["SC-28", "SI-12"])
    if key.endswith(".pem") or "chave privada" in reason:
        return r(["CWE-321", "CWE-312"], ["SC-12", "SC-28"])
    if key.endswith(".key") or "chave criptográfica" in reason:
        return r(["CWE-321", "CWE-312"], ["SC-12", "SC-28"])
    if key.endswith((".p12", ".pfx")) or "pkcs#12" in reason or "certificado pfx" in reason:
        return r(["CWE-312"], ["SC-12", "SC-28"])
    if key.endswith((".crt", ".cer")) or ("certificado" in reason and "pkcs" not in reason and "pfx" not in reason):
        return r(["CWE-200"], ["SC-12"])
    if key.endswith((".sql", ".db", ".sqlite")) or "dump sql" in reason or "banco de dados" in reason:
        return r(["CWE-530"], ["SC-28"])
    if key.endswith((".bak", ".backup", ".dump")) or "backup exposto" in reason or "dump de dados" in reason:
        return r(["CWE-530"], ["SC-28"])
    if key.endswith((".config", ".conf", ".ini")) or "configuração exposto" in reason:
        return r(["CWE-200"], ["SC-28"])
    if key.endswith((".zip", ".tar", ".gz", ".rar", ".7z")) or "compactado" in reason:
        return r(["CWE-200"], ["SC-28"])
    if "password" in reason or "secret" in reason or "credenciais" in reason:
        return r(["CWE-256", "CWE-312"], ["SC-28", "IA-5"])
    if "privado" in reason or "confidencial" in reason or "interno" in reason:
        return r(["CWE-200"], ["SC-28"])
    return r(["CWE-200"], ["SC-28"])


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_finding(finding: dict, provider: str = "S3") -> dict:
    """
    Adds 'refs' dict (CIS/CWE/NIST/CVE) to a finding in-place and returns it.
    provider: 'AWS_IAM', 'GCP_IAM', 'AZURE_IAM', 'KUBERNETES', 'S3', 'GCS', 'AZURE', etc.
    """
    p = provider.upper()
    if "IAM" in p:
        finding["refs"] = _refs_iam(finding, p)
    elif "KUBE" in p or "K8S" in p:
        finding["refs"] = _refs_k8s(finding)
    else:
        finding["refs"] = _refs_storage(finding, p)
    return finding
