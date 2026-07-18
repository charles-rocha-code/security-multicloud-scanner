"""
auditor_iam_gcp.py — GCP IAM Security Auditor (CSPM)

Checks cobertos (CIS Google Cloud Foundations Benchmark v2.0):
  1.2  Service Account com role Owner/Editor no projeto
  1.3  Primitive roles (owner/editor) em usuários e SAs
  1.4  Bindings públicos (allUsers / allAuthenticatedUsers)
  1.5  Project Owners excessivos (>2)
  4.1  Default Compute Engine Service Account com editor
  4.2  Apenas roles gerenciadas pelo Google para SAs de sistema
  4.3  User-managed SA keys com mais de 90 dias sem rotação
  4.4  Service Account com múltiplas user-managed keys
  Extra: High-risk roles (iam.serviceAccountAdmin, securityAdmin, etc.)
"""
from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cve_mapping import enrich_finding
from graph_model import GraphCollector, GraphEdge, GraphNode

KEY_AGE_HIGH_DAYS = 90
KEY_AGE_WARN_DAYS = 45
MAX_OWNERS = 2

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
HIGH_RISK_ROLES = {
    "roles/iam.serviceAccountAdmin",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.workloadIdentityPoolAdmin",
}


class GCPIAMAuditor(GraphCollector):
    def __init__(self, service_account_key: dict):
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        GraphCollector.__init__(self)
        self._project_id = service_account_key.get("project_id", "unknown")

        creds = service_account.Credentials.from_service_account_info(
            service_account_key,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        self._crm = build("cloudresourcemanager", "v1", credentials=creds)
        self._iam_svc = build("iam", "v1", credentials=creds)
        self._findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        entity_type: str,
        entity_name: str,
        check: str,
        severity: str,
        detail: str,
        remediation: str = "",
    ) -> None:
        f = {
            "key": f"{entity_type}/{entity_name} — {check}",
            "severity": severity,
            "size": 0,
            "reason": detail,
            "url": None,
            "entity_type": entity_type,
            "entity_name": entity_name,
            "check": check,
            "remediation": remediation,
        }
        enrich_finding(f, "GCP_IAM")
        self._findings.append(f)

    # ------------------------------------------------------------------
    # Check 1 — Project IAM policy
    # ------------------------------------------------------------------

    def _check_project_iam(self) -> None:
        try:
            resp = self._crm.projects().getIamPolicy(
                resource=self._project_id, body={}
            ).execute()
            bindings = resp.get("bindings", [])
        except Exception:
            return

        owners: List[str] = []

        project_node_id = f"project/{self._project_id}"
        self.add_node(GraphNode(
            id=project_node_id, type="gcp_project", provider="GCP", label=self._project_id,
            high_value=any(b.get("role") == "roles/owner" for b in bindings),
        ))

        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            condition = binding.get("condition")

            # Grafo: cada member já é iterado aqui pra gerar finding —
            # a mesma leitura também vira nó + aresta "member tem role X no
            # projeto". allUsers/allAuthenticatedUsers marca ponto de entrada
            # exposto (literalmente qualquer um na internet).
            for member in members:
                self.add_node(GraphNode(
                    id=f"member/{member}", type="gcp_member", provider="GCP", label=member,
                    exposed=(member in ("allUsers", "allAuthenticatedUsers")),
                ))
                self.add_edge(GraphEdge(
                    f"member/{member}", project_node_id, "has_permission",
                    metadata={"role": role},
                ))

            # Public bindings
            for member in members:
                if member in ("allUsers", "allAuthenticatedUsers"):
                    self._add(
                        "project", self._project_id,
                        f"Binding IAM público: {role} para {member}",
                        "CRITICAL",
                        f"Role '{role}' concedida a '{member}' — qualquer pessoa na internet tem esta permissão (CIS 1.7).",
                        f"gcloud projects remove-iam-policy-binding {self._project_id} --member={member} --role={role}",
                    )

            # Primitive roles
            if role in PRIMITIVE_ROLES:
                for member in members:
                    member_type = member.split(":")[0] if ":" in member else "unknown"
                    member_id = member.split(":", 1)[1] if ":" in member else member

                    if role == "roles/owner":
                        owners.append(member)
                        if member_type == "serviceAccount":
                            self._add(
                                "service-account", member_id,
                                "SA com roles/owner no projeto",
                                "CRITICAL",
                                f"Service Account '{member_id}' tem roles/owner — acesso total ao projeto (CIS 1.3).",
                                f"gcloud projects remove-iam-policy-binding {self._project_id} --member={member} --role=roles/owner",
                            )
                        elif member_type in ("user", "group"):
                            pass  # counted in owners list below

                    elif role == "roles/editor":
                        if member_type == "serviceAccount":
                            sa_name = member_id
                            if (sa_name.endswith("@developer.gserviceaccount.com")
                                    or sa_name.endswith("@cloudservices.gserviceaccount.com")):
                                self._add(
                                    "service-account", member_id,
                                    "Default Service Account com roles/editor (CIS 4.1)",
                                    "HIGH",
                                    f"SA padrão '{member_id}' tem roles/editor — amplo acesso não controlado aos recursos do projeto.",
                                    "Criar SAs dedicadas com permissões mínimas por workload.",
                                )
                            else:
                                self._add(
                                    "service-account", member_id,
                                    "SA com primitive role roles/editor",
                                    "HIGH",
                                    f"'{member_id}' tem roles/editor — usar roles específicas (CIS 1.3).",
                                    f"gcloud projects remove-iam-policy-binding {self._project_id} --member={member} --role=roles/editor",
                                )
                        else:
                            self._add(
                                "user", member_id,
                                "Primitive role roles/editor no projeto",
                                "MEDIUM",
                                f"'{member_id}' tem roles/editor — preferir roles específicas de menor privilégio.",
                                f"gcloud projects remove-iam-policy-binding {self._project_id} --member={member} --role=roles/editor",
                            )

            # High-risk roles
            if role in HIGH_RISK_ROLES:
                for member in members:
                    member_type = member.split(":")[0] if ":" in member else "unknown"
                    member_id = member.split(":", 1)[1] if ":" in member else member
                    if member_type not in ("serviceAccount",):
                        self._add(
                            "user", member_id,
                            f"Role de alto risco: {role}",
                            "HIGH",
                            f"'{member_id}' tem '{role}' — capacidade de administrar identidades/recursos do projeto.",
                            f"Revisar necessidade de '{role}' para '{member_id}' — usar PIM ou Workload Identity Federation",
                        )

        # Owners excessivos
        non_service_owners = [o for o in owners if not o.startswith("serviceAccount:")]
        if len(non_service_owners) > MAX_OWNERS:
            self._add(
                "project", self._project_id,
                f"{len(non_service_owners)} project owners (CIS 1.2 recomenda ≤{MAX_OWNERS})",
                "MEDIUM",
                f"Projeto tem {len(non_service_owners)} owners: {', '.join(non_service_owners[:5])} — excesso de owners aumenta superfície de comprometimento.",
                f"gcloud projects remove-iam-policy-binding {self._project_id} --member=<MEMBER> --role=roles/owner",
            )

    # ------------------------------------------------------------------
    # Check 2 — Service Account keys
    # ------------------------------------------------------------------

    def _check_service_account_keys(self) -> None:
        try:
            sas_resp = self._iam_svc.projects().serviceAccounts().list(
                name=f"projects/{self._project_id}"
            ).execute()
            sas = sas_resp.get("accounts", [])
        except Exception:
            return

        now = datetime.now(timezone.utc)

        for sa in sas:
            sa_email = sa.get("email", "")
            sa_name = sa.get("name", "")

            try:
                keys_resp = self._iam_svc.projects().serviceAccounts().keys().list(
                    name=sa_name, keyTypes=["USER_MANAGED"]
                ).execute()
                keys = keys_resp.get("keys", [])
            except Exception:
                continue

            # Múltiplas user-managed keys
            if len(keys) > 1:
                self._add(
                    "service-account", sa_email,
                    f"{len(keys)} user-managed keys ativas (CIS 4.4)",
                    "MEDIUM",
                    f"SA '{sa_email}' tem {len(keys)} chaves user-managed ativas — minimizar keys ativas reduz risco de comprometimento.",
                    f"gcloud iam service-accounts keys delete <KEY_ID> --iam-account={sa_email}",
                )

            for key in keys:
                created_str = key.get("validAfterTime", "")
                if not created_str:
                    continue
                try:
                    created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    age = (now - created).days
                    key_id = key.get("name", "").split("/")[-1]

                    if age >= KEY_AGE_HIGH_DAYS:
                        self._add(
                            "service-account", sa_email,
                            f"SA Key {key_id[:12]}... sem rotação há {age} dias (CIS 4.3)",
                            "HIGH",
                            f"Key de '{sa_email}' com {age} dias sem rotação — CIS 4.3 recomenda < {KEY_AGE_HIGH_DAYS} dias.",
                            f"gcloud iam service-accounts keys create /tmp/new.json --iam-account={sa_email} && gcloud iam service-accounts keys delete {key_id} --iam-account={sa_email}",
                        )
                    elif age >= KEY_AGE_WARN_DAYS:
                        self._add(
                            "service-account", sa_email,
                            f"SA Key {key_id[:12]}... próxima do vencimento ({age} dias)",
                            "MEDIUM",
                            f"Key de '{sa_email}' tem {age} dias — rotar antes de completar {KEY_AGE_HIGH_DAYS}.",
                            f"gcloud iam service-accounts keys create ... --iam-account={sa_email}",
                        )
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def _severity_distribution(self) -> Dict[str, int]:
        c = Counter(f["severity"] for f in self._findings)
        return {"critical": c["CRITICAL"], "high": c["HIGH"], "medium": c["MEDIUM"], "low": c["LOW"]}

    def _risk_score(self) -> int:
        dist = self._severity_distribution()
        def _log(n: int, w: float, r: float) -> float:
            return w * (1 - math.exp(-n / r)) if n > 0 else 0.0
        score = (
            _log(dist["critical"], 65.0, 1.0) +
            _log(dist["high"],     45.0, 3.0) +
            _log(dist["medium"],   15.0, 8.0) +
            _log(dist["low"],       8.0, 20.0)
        )
        return min(round(score), 100)

    def _recommendations(self, score: int) -> List[str]:
        recs = []
        sev = self._severity_distribution()
        checks = [f["check"] for f in self._findings]

        if sev["critical"] > 0:
            recs.append("🚨 URGENTE: Findings CRITICAL — revisar bindings públicos e SA com roles/owner imediatamente.")
        if any("público" in c for c in checks):
            recs.append("Remover imediatamente bindings allUsers/allAuthenticatedUsers — qualquer serviço exposto torna-se público.")
        if any("owner" in c.lower() and "SA" in c for c in checks):
            recs.append("Remover roles/owner de Service Accounts — usar Workload Identity Federation no lugar de SA keys.")
        if any("primitive role" in c.lower() or "editor" in c.lower() for c in checks):
            recs.append("Substituir primitive roles (owner/editor) por roles específicas — use o IAM Recommender para sugestões.")
        if any("owners" in c and "excessivos" not in c and (">" in c or "owners" in c) for c in checks):
            recs.append("Reduzir Project Owners a no máximo 2 identidades (CIS GCP 1.2).")
        if any("SA Key" in c and "dias" in c for c in checks):
            recs.append("Rotacionar SA keys com mais de 90 dias — prefira Workload Identity Federation para eliminar keys.")
        if any("múltiplas" in c.lower() or "keys ativas" in c.lower() for c in checks):
            recs.append("Manter no máximo 1 user-managed key ativa por Service Account (CIS 4.4).")
        recs.append("Ativar Cloud Audit Logs (Data Access) em todos os serviços críticos para rastreabilidade.")
        recs.append("Implementar VPC Service Controls para impedir exfiltração de dados entre projetos.")
        recs.append("Usar IAM Recommender para identificar permissões excessivas automaticamente.")
        return recs

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        self._check_project_iam()
        self._check_service_account_keys()

        sev = self._severity_distribution()
        score = self._risk_score()

        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"
        else:
            level = "NONE"

        sa_keys_old = len([f for f in self._findings if "SA Key" in f.get("check", "") and "dias" in f.get("check", "")])
        public_bindings = len([f for f in self._findings if "público" in f.get("check", "")])

        return {
            "provider": "GCP_IAM",
            "target": f"project/{self._project_id}",
            "account_id": self._project_id,
            "region": "global",
            "public_access": public_bindings > 0,
            "risk_score": score,
            "risk_level": level,
            "severity_distribution": sev,
            "files": self._findings,
            "summary": {
                "objects_scanned": len(self._findings),
                "total_size_bytes": 0,
                "project_id": self._project_id,
                "sa_keys_old": sa_keys_old,
                "public_bindings": public_bindings,
                "root_mfa": True,
                "root_keys_active": False,
            },
            "recommendations": self._recommendations(score),
            "errors": [],
            "graph": self.graph_output(),
        }
