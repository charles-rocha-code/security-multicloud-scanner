"""
auditor_k8s.py - Auditor de segurança de storage em clusters Kubernetes.

Analisa:
- PersistentVolumes (PVs) e PersistentVolumeClaims (PVCs) expostos
- StorageClasses inseguros
- Secrets com credenciais de storage (AWS, GCS, Azure)
- ConfigMaps com dados sensíveis de storage
- Pods com volumes hostPath
- Namespaces com permissões excessivas em storage
"""

from __future__ import annotations

import io
import yaml
from datetime import datetime
from typing import Any, Dict, List, Optional

from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException

from cve_mapping import enrich_finding
from ssrf_guard import assert_server_not_ssrf_target


SENSITIVE_PATTERNS = [
    "aws_access_key", "aws_secret", "aws_key", "s3_key",
    "storage_account", "azure_key", "azure_connection",
    "google_credentials", "service_account", "gcs_key",
    "password", "passwd", "token", "secret", "credential",
]


def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(p in k for p in SENSITIVE_PATTERNS)


def _classify_severity(reason: str) -> str:
    reason_lower = reason.lower()
    if any(w in reason_lower for w in ["public", "exposed", "secret", "credential", "token", "key"]):
        return "CRITICAL"
    if any(w in reason_lower for w in ["hostpath", "readwritemany", "retain", "insecure"]):
        return "HIGH"
    if any(w in reason_lower for w in ["configmap", "storageclas", "annotation"]):
        return "MEDIUM"
    return "LOW"


class K8sStorageAuditor:
    """Auditor de storage Kubernetes a partir de um kubeconfig YAML."""

    def __init__(self, kubeconfig_yaml: str, max_objects: int = 1000):
        self.kubeconfig_yaml = kubeconfig_yaml
        self.max_objects = max_objects
        self._api_client: Optional[client.ApiClient] = None

    def _load_config(self) -> client.ApiClient:
        cfg_dict = yaml.safe_load(self.kubeconfig_yaml)
        loader = k8s_config.kube_config.KubeConfigLoader(config_dict=cfg_dict)
        cfg = client.Configuration()
        loader.load_and_set(cfg)
        assert_server_not_ssrf_target(cfg.host)  # bloqueia antes do 1º request real
        return client.ApiClient(configuration=cfg)

    def _safe(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ApiException:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_pvs(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_persistent_volume)
        if not resp:
            return findings

        for pv in (resp.items or []):
            name = pv.metadata.name or "-"
            spec = pv.spec or client.V1PersistentVolumeSpec()

            # ReclaimPolicy Retain mantém dados após deleção do PVC
            if getattr(spec, "persistent_volume_reclaim_policy", "") == "Retain":
                findings.append({
                    "key": f"PV/{name}",
                    "size": 0,
                    "severity": "HIGH",
                    "reason": "ReclaimPolicy=Retain: dados persistem após deleção do PVC",
                })

            # AccessMode ReadWriteMany expõe volume a múltiplos nós
            modes = getattr(spec, "access_modes", []) or []
            if "ReadWriteMany" in modes:
                findings.append({
                    "key": f"PV/{name}",
                    "size": 0,
                    "severity": "HIGH",
                    "reason": "AccessMode=ReadWriteMany: volume acessível por múltiplos nós simultaneamente",
                })

            # hostPath aponta para diretório do host
            if getattr(spec, "host_path", None):
                findings.append({
                    "key": f"PV/{name}",
                    "size": 0,
                    "severity": "CRITICAL",
                    "reason": f"hostPath={spec.host_path.path}: volume monta diretório do nó host",
                })

        return findings

    def _check_pvcs(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_persistent_volume_claim_for_all_namespaces)
        if not resp:
            return findings

        for pvc in (resp.items or []):
            name = pvc.metadata.name or "-"
            ns = pvc.metadata.namespace or "default"
            spec = pvc.spec or client.V1PersistentVolumeClaimSpec()
            modes = getattr(spec, "access_modes", []) or []

            if "ReadWriteMany" in modes:
                findings.append({
                    "key": f"PVC/{ns}/{name}",
                    "size": 0,
                    "severity": "HIGH",
                    "reason": "AccessMode=ReadWriteMany: PVC compartilhado entre múltiplos pods",
                })

        return findings

    def _check_secrets(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_secret_for_all_namespaces)
        if not resp:
            return findings

        for secret in (resp.items or []):
            name = secret.metadata.name or "-"
            ns = secret.metadata.namespace or "default"
            data = secret.data or {}

            for key in data:
                if _is_sensitive(key):
                    findings.append({
                        "key": f"Secret/{ns}/{name}[{key}]",
                        "size": len(data[key]) if data[key] else 0,
                        "severity": "CRITICAL",
                        "reason": f"Secret contém chave sensível de storage: '{key}'",
                    })
                    break  # um achado por secret é suficiente

        return findings

    def _check_configmaps(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_config_map_for_all_namespaces)
        if not resp:
            return findings

        for cm in (resp.items or []):
            name = cm.metadata.name or "-"
            ns = cm.metadata.namespace or "default"
            if ns in ("kube-system", "kube-public"):
                continue
            data = cm.data or {}

            for key in data:
                if _is_sensitive(key):
                    findings.append({
                        "key": f"ConfigMap/{ns}/{name}[{key}]",
                        "size": len(data[key]) if data[key] else 0,
                        "severity": "MEDIUM",
                        "reason": f"ConfigMap expõe dado sensível em texto plano: '{key}'",
                    })
                    break

        return findings

    def _check_storage_classes(self, storage: client.StorageV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(storage.list_storage_class)
        if not resp:
            return findings

        for sc in (resp.items or []):
            name = sc.metadata.name or "-"
            reclaim = getattr(sc, "reclaim_policy", "") or ""

            if reclaim == "Retain":
                findings.append({
                    "key": f"StorageClass/{name}",
                    "size": 0,
                    "severity": "MEDIUM",
                    "reason": "StorageClass reclaimPolicy=Retain: dados persistem após deleção",
                })

            params = getattr(sc, "parameters", {}) or {}
            for k, v in params.items():
                if _is_sensitive(k):
                    findings.append({
                        "key": f"StorageClass/{name}[{k}]",
                        "size": 0,
                        "severity": "HIGH",
                        "reason": f"StorageClass contém parâmetro sensível: '{k}'",
                    })
                    break

        return findings

    def _check_hostpath_pods(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_pod_for_all_namespaces)
        if not resp:
            return findings

        for pod in (resp.items or []):
            name = pod.metadata.name or "-"
            ns = pod.metadata.namespace or "default"
            spec = pod.spec or client.V1PodSpec(containers=[])
            volumes = getattr(spec, "volumes", []) or []

            for vol in volumes:
                if getattr(vol, "host_path", None):
                    findings.append({
                        "key": f"Pod/{ns}/{name}/volume:{vol.name}",
                        "size": 0,
                        "severity": "CRITICAL",
                        "reason": f"Pod monta hostPath={vol.host_path.path}: acesso direto ao sistema de arquivos do host",
                    })

        return findings

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        try:
            api_client = self._load_config()
        except Exception as e:
            return {
                "provider": "KUBERNETES",
                "bucket": "cluster",
                "region": "-",
                "public_access": False,
                "public_listing": False,
                "summary": {"objects_scanned": 0, "total_size_bytes": 0},
                "files": [],
                "errors": [f"Falha ao carregar kubeconfig: {e}"],
                "risk_score": 0,
                "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "recommendations": ["Verifique se o kubeconfig está correto e o cluster está acessível."],
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

        core = client.CoreV1Api(api_client)
        storage_api = client.StorageV1Api(api_client)

        findings: List[Dict] = []
        errors: List[str] = []

        for check_fn, args in [
            (self._check_pvs, (core,)),
            (self._check_pvcs, (core,)),
            (self._check_secrets, (core,)),
            (self._check_configmaps, (core,)),
            (self._check_storage_classes, (storage_api,)),
            (self._check_hostpath_pods, (core,)),
        ]:
            try:
                findings.extend(check_fn(*args))
            except Exception as e:
                errors.append(f"{check_fn.__name__}: {e}")

        findings = findings[: self.max_objects]

        for f in findings:
            f.setdefault("category", "Storage")
            enrich_finding(f, "KUBERNETES")

        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev == "CRITICAL":
                dist["critical"] += 1
            elif sev == "HIGH":
                dist["high"] += 1
            elif sev == "MEDIUM":
                dist["medium"] += 1
            else:
                dist["low"] += 1

        total = len(findings)
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_score = total * 4 if total else 1
        raw = sum(dist[k] * weights[k] for k in dist)
        risk_score = min(100, int((raw / max_score) * 100)) if total else 0

        # Cluster server para exibir como "bucket"; nome do cluster e usuário
        # do contexto ativo pra exibir como "region"/"account" na barra
        # superior -- k8s não tem esses conceitos, mas são o equivalente
        # mais próximo (cluster = onde, user do contexto = quem conecta).
        cluster_server = "-"
        cluster_name = "-"
        account_identity = "-"
        try:
            cfg_dict = yaml.safe_load(self.kubeconfig_yaml)
            clusters = cfg_dict.get("clusters", [])
            if clusters:
                cluster_server = clusters[0].get("cluster", {}).get("server", "-")
                cluster_name = clusters[0].get("name", "-")

            current_context = cfg_dict.get("current-context")
            for ctx in cfg_dict.get("contexts", []):
                if ctx.get("name") == current_context:
                    account_identity = ctx.get("context", {}).get("user", "-")
                    break
        except Exception:
            pass

        recs = []
        if dist["critical"] > 0:
            recs.append("Remova ou rotacione credenciais de storage expostas em Secrets imediatamente.")
        if dist["high"] > 0:
            recs.append("Revise PersistentVolumes com hostPath e ReclaimPolicy=Retain.")
        if dist["medium"] > 0:
            recs.append("Mova dados sensíveis de ConfigMaps para Secrets ou Vault.")
        recs.append("Use RBAC restritivo para acesso a PVs, PVCs e Secrets de storage.")
        recs.append("Habilite auditoria do Kubernetes API Server para operações em Secrets e PVs.")

        return {
            "provider": "KUBERNETES",
            "bucket": cluster_server,
            "region": cluster_name,
            "account_id": account_identity,
            "public_access": dist["critical"] > 0,
            "public_listing": False,
            "summary": {
                "objects_scanned": total,
                "total_size_bytes": sum(f.get("size", 0) for f in findings),
            },
            "files": findings,
            "errors": errors,
            "risk_score": risk_score,
            "severity_distribution": dist,
            "recommendations": recs,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
