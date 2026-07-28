from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from google.cloud import storage
from google.oauth2 import service_account

from engine_risk import (
    classify_severity,
    build_severity_distribution,
    calculate_advanced_risk,
    build_recommendations,
    should_scan_content,
    scan_content_for_secrets,
    CONTENT_SCAN_MAX_FILES,
)
from cve_mapping import enrich_finding
from graph_model import GraphCollector, GraphEdge, GraphNode


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
    max_objects: int = 10000
    _graph: GraphCollector = field(default_factory=GraphCollector, repr=False, compare=False)

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
        content_scans_done = 0

        try:
            blobs_iter = client.list_blobs(bucket, max_results=int(self.max_objects))
            for blob in blobs_iter:
                key = blob.name or ""
                size = int(blob.size or 0)
                sev, reason = classify_severity(key)

                # Inspeciona o CONTEÚDO de candidatos pequenos e sem extensão
                # sensível óbvia -- pega segredo embutido num arquivo "sem
                # cara de sensível", que a checagem por nome/extensão nunca
                # via. Mesma lógica do S3 (auditor_s3_authenticated.py).
                if content_scans_done < CONTENT_SCAN_MAX_FILES and should_scan_content(key, size, sev):
                    try:
                        body = blob.download_as_bytes()
                        content_scans_done += 1
                        text = body.decode("utf-8", errors="ignore")
                        content_hit = scan_content_for_secrets(text)
                        if content_hit:
                            sev, reason = content_hit
                    except Exception:
                        pass  # objeto ilegível/binário/sem permissão -- segue com a classificação por nome

                files.append(enrich_finding({
                    "key": key,
                    "size": size,
                    "severity": sev,
                    "reason": reason,
                    "url": f"https://storage.googleapis.com/{bucket_name}/{key}",
                }, "GCS"))
        except Exception as e:
            errors.append(str(e))

        # IAM policy do bucket — dado novo (não lido antes neste auditor).
        # Além de alimentar o grafo (Fase 4 do roadmap), corrige um bug
        # real encontrado ao adicionar isto: "public_access" estava sempre
        # hardcoded em False, nunca refletindo a policy de verdade.
        public_access = False
        bucket_node_id = f"bucket/{bucket_name}"
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            self._graph.add_node(GraphNode(
                id=bucket_node_id, type="gcs_bucket", provider="GCP", label=bucket_name,
            ))
            for binding in policy.bindings:
                role = binding.get("role", "")
                for member in binding.get("members", []):
                    exposed = member in ("allUsers", "allAuthenticatedUsers")
                    if exposed:
                        public_access = True
                    self._graph.add_node(GraphNode(
                        id=f"member/{member}", type="gcp_member", provider="GCP", label=member,
                        exposed=exposed,
                    ))
                    self._graph.add_edge(GraphEdge(
                        f"member/{member}", bucket_node_id, "has_permission",
                        metadata={"role": role},
                    ))
        except Exception as e:
            errors.append(f"Não foi possível ler IAM policy do bucket: {e}")

        payload: Dict[str, Any] = {
            "provider": "GCS",
            "bucket": bucket_name,
            "region": "global",
            "account_id": self.service_account_key.get("project_id", "-"),
            "public_access": public_access,
            "public_listing": False,
            "summary": {
                "objects_scanned": len(files),
                "total_size_bytes": sum(f.get("size", 0) for f in files),
            },
            "files": files,
            "errors": errors,
            "graph": self._graph.graph_output(),
        }

        payload.update(calculate_advanced_risk(payload))
        payload["severity_distribution"] = build_severity_distribution(payload["files"])
        payload["recommendations"] = build_recommendations(payload)

        return payload
