from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import re

from google.cloud import storage
from google.oauth2 import service_account


def _extract_bucket_name(bucket: str) -> str:
    """
    Aceita:
      - portalnovafibra-bkp
      - portalnovafibra-bkp.storage.googleapis.com
      - https://storage.googleapis.com/portalnovafibra-bkp
      - gs://portalnovafibra-bkp
    e retorna somente: portalnovafibra-bkp
    """
    b = (bucket or "").strip()

    # gs://bucket
    if b.startswith("gs://"):
        return b[5:].split("/", 1)[0]

    # https://storage.googleapis.com/bucket/...
    m = re.match(r"^https?://storage\.googleapis\.com/([^/]+)", b)
    if m:
        return m.group(1)

    # bucket.storage.googleapis.com
    if b.endswith(".storage.googleapis.com"):
        return b.split(".storage.googleapis.com")[0]

    # bucket puro
    return b


@dataclass
class GCSAuthenticatedAuditor:
    bucket_name: str
    service_account_key: Dict[str, Any]
    max_objects: int = 1000

    def _client(self) -> storage.Client:
        if not isinstance(self.service_account_key, dict) or self.service_account_key.get("type") != "service_account":
            raise ValueError("service_account_key deve ser um JSON dict de Service Account (type=service_account).")

        creds = service_account.Credentials.from_service_account_info(self.service_account_key)
        project_id = self.service_account_key.get("project_id")
        return storage.Client(project=project_id, credentials=creds)

    def run(self) -> Dict[str, Any]:
        bucket_name = _extract_bucket_name(self.bucket_name)
        client = self._client()

        bucket = client.bucket(bucket_name)

        findings: List[Dict[str, Any]] = []
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # Listar blobs (objetos). Campos comuns para score/criticidade:
        # - public access (IAM/ACL) -> normalmente seu motor calcula
        # - name, size, content_type, updated, md5_hash, storage_class
        blobs_iter = client.list_blobs(bucket, max_results=int(self.max_objects))

        for blob in blobs_iter:
            findings.append({
                "object": blob.name,
                "size": int(blob.size or 0),
                "content_type": blob.content_type,
                "updated": blob.updated.isoformat() if blob.updated else None,
                "md5_hash": blob.md5_hash,
                "storage_class": blob.storage_class,
                # placeholders para seu engine (se ele usar):
                "severity": "LOW",
                "issue": "Object enumerated (authenticated)",
                "recommendation": "Review bucket/object access policies; ensure least privilege."
            })

        # Exemplo: aqui não estamos inferindo severidade real (isso é do engine_risk),
        # mas deixamos estrutura compatível.
        # Se seu engine recalcula, tudo bem.

        summary = {
            "bucket": bucket_name,
            "provider": "GCS",
            "scanned_objects": len(findings),
            "max_objects": int(self.max_objects),
            "risk_counts": risk_counts,
        }

        return {
            "summary": summary,
            "findings": findings,
        }
