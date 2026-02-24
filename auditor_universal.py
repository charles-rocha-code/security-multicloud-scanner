import re
from urllib.parse import urlparse

from auditor import S3Auditor
from auditor_gcs import GCSAuditor
from auditor_azure import AzureBlobAuditor


class UniversalAuditor:
    """Roteador simples que detecta provider e delega o scan para o auditor correto."""

    def __init__(self, target: str, max_objects: int = 200, region: str = "global"):
        self.target = target
        self.max_objects = max_objects
        self.region = region

    def _normalize_target(self) -> str:
        t = (self.target or "").strip()
        if not t:
            return t
        if t.startswith("http://") or t.startswith("https://"):
            return t
        return "https://" + t

    def _detect_provider(self, normalized: str):
        """
        Retorna (provider, normalized, extra)
        """
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()

        # GCS
        if host.endswith(".storage.googleapis.com") or host == "storage.googleapis.com":
            return "GCS", normalized, None

        # AWS S3 (s3-REGION e s3.REGION e s3.amazonaws.com)
        if re.search(r"\.s3([.-][a-z0-9-]+)?\.amazonaws\.com(\.cn)?$", host):
            return "AWS_S3", normalized, None

        # Azure Blob
        if ".blob.core.windows.net" in host:
            path_parts = parsed.path.strip("/").split("/")
            container = path_parts[0] if path_parts and path_parts[0] else None
            return "AZURE_BLOB", normalized, container

        return "UNIVERSAL", normalized, None

    def run(self):
        normalized = self._normalize_target()
        provider, normalized, extra = self._detect_provider(normalized)

        if provider == "AWS_S3":
            return S3Auditor(
                bucket_or_url=normalized,
                max_objects=self.max_objects,
            ).run()

        if provider == "GCS":
            return GCSAuditor(
                bucket_or_url=normalized,
                max_objects=self.max_objects,
            ).run()

        if provider == "AZURE_BLOB":
            return AzureBlobAuditor(
                account_or_url=normalized,
                container=extra,
                max_objects=self.max_objects,
            ).run()

        return {
            "provider": "UNIVERSAL",
            "target": self.target,
            "public_access": False,
            "public_listing": False,
            "summary": {"objects_scanned": 0, "total_size_bytes": 0},
            "files": [],
            "errors": ["Provider não reconhecido para este endpoint."],
        }
