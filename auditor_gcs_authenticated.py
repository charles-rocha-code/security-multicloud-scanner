from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from google.cloud import storage
from google.oauth2 import service_account

from engine_risk import classify_severity, build_severity_distribution, calculate_advanced_risk, build_recommendations
from cve_mapping import enrich_finding


def _extract_bucket_name(bucket: str) -> str:
    b = (bucket or "").strip()
    if b.startswith("gs://"):
        return b[5:].split("/", 1)[0]
    m = re.match(r"^https?://storage\.googleapis\.com/([^/]+)", b)
    if m:
        return m.group(1)
    if b.endswith(".storage.googleapis.com"):
        return b.split(".storage.googleapis.com")[0]
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

        files: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            blobs_iter = client.list_blobs(bucket, max_results=int(self.max_objects))
            for blob in blobs_iter:
                key = blob.name or ""
                size = int(blob.size or 0)
                sev, reason = classify_severity(key)
                files.append(enrich_finding({
                    "key": key,
                    "size": size,
                    "severity": sev,
                    "reason": reason,
                    "url": f"https://storage.googleapis.com/{bucket_name}/{key}",
                }, "GCS"))
        except Exception as e:
            errors.append(str(e))

        payload: Dict[str, Any] = {
            "provider": "GCS",
            "bucket": bucket_name,
            "region": "global",
            "account_id": self.service_account_key.get("project_id", "-"),
            "public_access": False,
            "public_listing": False,
            "summary": {
                "objects_scanned": len(files),
                "total_size_bytes": sum(f.get("size", 0) for f in files),
            },
            "files": files,
            "errors": errors,
        }

        payload.update(calculate_advanced_risk(payload))
        payload["severity_distribution"] = build_severity_distribution(payload["files"])
        payload["recommendations"] = build_recommendations(payload)

        return payload
