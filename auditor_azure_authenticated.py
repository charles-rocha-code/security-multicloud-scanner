# auditor_azure_authenticated.py
"""
Auditor Azure Blob Storage - Scan autenticado (com credenciais)
Suporta:
- Connection String ou SAS Token
- Containers privados e públicos
- Configurações de segurança completas
- Encryption, versioning, soft delete
- Análise profunda de ACLs e policies
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

try:
    from azure.storage.blob import BlobServiceClient, ContainerClient, BlobClient
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False
    print("Warning: azure-storage-blob not installed. Run: pip install azure-storage-blob")

from engine_risk import classify_severity, build_severity_distribution, calculate_advanced_risk


class AzureBlobAuthenticatedAuditor:
    """
    Auditor Azure Blob Storage COM credenciais:
      - Acessa containers privados
      - Metadados completos de blobs
      - Configurações de segurança do storage account
      - Public access level
      - Encryption settings
      - CORS configuration
      - Lifecycle policies
      - Soft delete status
      - Versioning
      - Account ID e subscription
    """

    def __init__(
        self,
        account_or_url: str,
        container: Optional[str] = None,
        connection_string: Optional[str] = None,
        sas_token: Optional[str] = None,
        account_key: Optional[str] = None,
        max_objects: int = 1000,
        timeout: int = 30
    ):
        """
        Args:
            account_or_url: Nome da conta ou URL (ex: gododev.blob.core.windows.net)
            container: Nome do container específico (opcional)
            connection_string: Azure Connection String (preferencial)
            sas_token: SAS Token para autenticação
            account_key: Account Key (alternativo)
            max_objects: Número máximo de objetos a listar
            timeout: Timeout para operações
        """
        if not AZURE_SDK_AVAILABLE:
            raise ImportError("azure-storage-blob não instalado. Execute: pip install azure-storage-blob")
        
        self.input = account_or_url.strip()
        self.container = container
        self.max_objects = max_objects
        self.timeout = timeout
        
        # Parse storage account
        self.account = self._parse_account()
        
        # Inicializa cliente
        self.blob_service_client = self._init_client(
            connection_string=connection_string,
            sas_token=sas_token,
            account_key=account_key
        )
    
    def _parse_account(self) -> str:
        """Extrai o nome da storage account do input."""
        s = self.input.lower()

        if "://" in s:
            from urllib.parse import urlparse
            u = urlparse(s)
            host = u.netloc
            if ".blob.core.windows.net" in host:
                return host.split(".blob.core.windows.net")[0]
            return host.split(":")[0]

        if ".blob.core.windows.net" in s:
            return s.split(".blob.core.windows.net")[0]

        return s
    
    def _init_client(
        self,
        connection_string: Optional[str] = None,
        sas_token: Optional[str] = None,
        account_key: Optional[str] = None
    ) -> BlobServiceClient:
        """
        Inicializa BlobServiceClient com credenciais fornecidas.
        
        Ordem de preferência:
        1. Connection String (mais completo)
        2. SAS Token (temporário, limitado)
        3. Account Key (permanente)
        """
        
        # Método 1: Connection String (preferencial)
        if connection_string:
            return BlobServiceClient.from_connection_string(
                connection_string,
                timeout=self.timeout
            )
        
        # Método 2: SAS Token
        elif sas_token:
            account_url = f"https://{self.account}.blob.core.windows.net"
            if not sas_token.startswith("?"):
                sas_token = "?" + sas_token
            
            return BlobServiceClient(
                account_url=account_url + sas_token,
                timeout=self.timeout
            )
        
        # Método 3: Account Key
        elif account_key:
            account_url = f"https://{self.account}.blob.core.windows.net"
            
            from azure.storage.blob import BlobServiceClient
            return BlobServiceClient(
                account_url=account_url,
                credential=account_key,
                timeout=self.timeout
            )
        
        else:
            raise ValueError(
                "É necessário fornecer credenciais: connection_string, sas_token ou account_key"
            )
    
    def _get_account_info(self) -> Dict[str, Any]:
        """
        Obtém informações da storage account.
        
        Returns:
            Dict com account_name, sku, kind, etc
        """
        try:
            # Tenta obter properties da conta
            account_info = self.blob_service_client.get_account_information()
            
            return {
                "account_name": self.account,
                "sku_name": getattr(account_info, "sku_name", "Unknown"),
                "account_kind": getattr(account_info, "account_kind", "Unknown"),
                "is_hns_enabled": getattr(account_info, "is_hns_enabled", False),
            }
        except Exception as e:
            return {
                "account_name": self.account,
                "error": str(e)
            }
    
    def _list_containers(self) -> List[Dict[str, Any]]:
        """
        Lista todos os containers da storage account.
        
        Returns:
            Lista de containers com metadados
        """
        containers = []
        
        try:
            for container in self.blob_service_client.list_containers(include_metadata=True):
                containers.append({
                    "name": container.name,
                    "last_modified": container.last_modified.isoformat() if container.last_modified else None,
                    "public_access": container.public_access or "Private",
                    "has_immutability_policy": container.has_immutability_policy or False,
                    "has_legal_hold": container.has_legal_hold or False,
                    "metadata": container.metadata or {}
                })
        except Exception as e:
            print(f"Error listing containers: {e}")
        
        return containers
    
    def _get_container_properties(self, container_name: str) -> Dict[str, Any]:
        """
        Obtém propriedades detalhadas de um container.
        """
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            props = container_client.get_container_properties()
            
            return {
                "name": container_name,
                "last_modified": props.last_modified.isoformat() if props.last_modified else None,
                "etag": props.etag,
                "public_access": props.public_access or "Private",
                "has_immutability_policy": props.has_immutability_policy or False,
                "has_legal_hold": props.has_legal_hold or False,
                "default_encryption_scope": props.default_encryption_scope or None,
                "prevent_encryption_scope_override": props.prevent_encryption_scope_override or False,
                "metadata": props.metadata or {}
            }
        except Exception as e:
            return {
                "name": container_name,
                "error": str(e)
            }
    
    def _check_container_public_access(self, container_name: str) -> Tuple[str, bool]:
        """
        Verifica se container tem acesso público.
        
        Returns:
            (public_access_level, is_public)
        """
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            props = container_client.get_container_properties()
            
            public_access = props.public_access or "Private"
            is_public = public_access in ("Container", "Blob")
            
            return public_access, is_public
        except Exception:
            return "Unknown", False
    
    def _get_blob_service_properties(self) -> Dict[str, Any]:
        """
        Obtém propriedades do Blob Service (configurações de segurança).
        """
        properties = {}
        
        try:
            service_props = self.blob_service_client.get_service_properties()
            
            # Logging
            properties["logging"] = {
                "version": getattr(service_props.logging, "version", None),
                "delete": getattr(service_props.logging, "delete", False),
                "read": getattr(service_props.logging, "read", False),
                "write": getattr(service_props.logging, "write", False),
                "retention_policy_enabled": getattr(service_props.logging.retention_policy, "enabled", False) if hasattr(service_props.logging, "retention_policy") else False,
                "retention_days": getattr(service_props.logging.retention_policy, "days", None) if hasattr(service_props.logging, "retention_policy") else None
            }
            
            # CORS
            properties["cors"] = []
            if hasattr(service_props, "cors") and service_props.cors:
                for rule in service_props.cors:
                    properties["cors"].append({
                        "allowed_origins": getattr(rule, "allowed_origins", []),
                        "allowed_methods": getattr(rule, "allowed_methods", []),
                        "allowed_headers": getattr(rule, "allowed_headers", []),
                        "exposed_headers": getattr(rule, "exposed_headers", []),
                        "max_age_in_seconds": getattr(rule, "max_age_in_seconds", 0)
                    })
            
            # Static Website
            if hasattr(service_props, "static_website"):
                properties["static_website"] = {
                    "enabled": getattr(service_props.static_website, "enabled", False),
                    "index_document": getattr(service_props.static_website, "index_document", None),
                    "error_document_404_path": getattr(service_props.static_website, "error_document_404_path", None)
                }
            
            # Soft Delete
            if hasattr(service_props, "delete_retention_policy"):
                properties["soft_delete"] = {
                    "enabled": getattr(service_props.delete_retention_policy, "enabled", False),
                    "days": getattr(service_props.delete_retention_policy, "days", None)
                }
            
            # Versioning
            if hasattr(service_props, "is_versioning_enabled"):
                properties["versioning"] = {
                    "enabled": service_props.is_versioning_enabled
                }
        
        except Exception as e:
            properties["error"] = str(e)
        
        return properties
    
    def _list_blobs(self, container_name: str) -> List[Dict[str, Any]]:
        """
        Lista blobs de um container com metadados completos.
        """
        files = []
        
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            
            blob_count = 0
            for blob in container_client.list_blobs(include=["metadata"]):
                if blob_count >= self.max_objects:
                    break
                
                blob_name = blob.name
                
                # Classificar severidade
                sev, reason = classify_severity(blob_name)
                
                # URL do blob
                blob_url = f"https://{self.account}.blob.core.windows.net/{container_name}/{blob_name}"
                
                files.append({
                    "key": blob_name,
                    "size": blob.size or 0,
                    "severity": sev,
                    "reason": reason,
                    "url": blob_url,
                    "container": container_name,
                    "last_modified": blob.last_modified.isoformat() if blob.last_modified else None,
                    "content_type": blob.content_settings.content_type if blob.content_settings else None,
                    "etag": blob.etag,
                    "server_encrypted": blob.server_encrypted or False,
                    "encryption_scope": blob.encryption_scope or None,
                    "access_tier": blob.blob_tier or None,
                    "metadata": blob.metadata or {}
                })
                
                blob_count += 1
        
        except Exception as e:
            print(f"Error listing blobs in container {container_name}: {e}")
        
        return files
    
    def _analyze_security_config(self, containers: List[Dict[str, Any]], service_props: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analisa configurações de segurança do storage account.
        """
        security = {}
        
        # Public Access Analysis
        public_containers = [c for c in containers if c.get("public_access") not in ("Private", None)]
        security["public_containers"] = len(public_containers)
        security["public_container_names"] = [c["name"] for c in public_containers]
        
        # Logging
        logging_config = service_props.get("logging", {})
        security["logging_enabled"] = logging_config.get("read") or logging_config.get("write")
        security["logging_retention_enabled"] = logging_config.get("retention_policy_enabled", False)
        security["logging_retention_days"] = logging_config.get("retention_days")
        
        # CORS
        cors_rules = service_props.get("cors", [])
        security["cors_enabled"] = len(cors_rules) > 0
        security["cors_has_wildcards"] = any(
            "*" in str(rule.get("allowed_origins", [])) for rule in cors_rules
        )
        
        # Soft Delete
        soft_delete = service_props.get("soft_delete", {})
        security["soft_delete_enabled"] = soft_delete.get("enabled", False)
        security["soft_delete_retention_days"] = soft_delete.get("days")
        
        # Versioning
        versioning = service_props.get("versioning", {})
        security["versioning_enabled"] = versioning.get("enabled", False)
        
        # Static Website
        static_website = service_props.get("static_website", {})
        security["static_website_enabled"] = static_website.get("enabled", False)
        
        return security
    
    def run(self) -> Dict[str, Any]:
        """
        Executa auditoria autenticada da Azure Blob Storage.
        """
        # Account info
        account_info = self._get_account_info()
        
        # Service properties (configurações de segurança)
        service_props = self._get_blob_service_properties()
        
        all_files: List[Dict[str, Any]] = []
        containers_scanned: List[str] = []
        errors: List[str] = []
        
        # Se container específico foi fornecido
        if self.container:
            print(f"Scanning specific container: {self.container}")
            
            container_props = self._get_container_properties(self.container)
            files = self._list_blobs(self.container)
            
            all_files.extend(files)
            containers_scanned.append(self.container)
        
        # Senão, lista todos os containers
        else:
            print(f"Scanning all containers in storage account: {self.account}")
            
            containers = self._list_containers()
            print(f"Found {len(containers)} containers")
            
            # Limita a 20 containers
            for container in containers[:20]:
                container_name = container["name"]
                print(f"Scanning container: {container_name}")
                
                files = self._list_blobs(container_name)
                all_files.extend(files)
                containers_scanned.append(container_name)
                
                # Limita total de objetos
                if len(all_files) >= self.max_objects:
                    all_files = all_files[:self.max_objects]
                    break
        
        # Análise de segurança
        all_containers = self._list_containers()
        security_config = self._analyze_security_config(all_containers, service_props)
        
        # Public access check
        public_access = security_config["public_containers"] > 0
        
        # Monta payload final
        summary = {
            "objects_scanned": len(all_files),
            "total_size_bytes": sum(int(f.get("size", 0)) for f in all_files),
            "containers_scanned": len(containers_scanned),
            "total_containers": len(all_containers)
        }
        
        payload: Dict[str, Any] = {
            "provider": "AZURE_BLOB",
            "account": self.account,
            "account_info": account_info,
            "region": "global",
            "container": self.container or f"{len(containers_scanned)} containers",
            "containers": containers_scanned,
            "all_containers": [c["name"] for c in all_containers],
            "public_access": public_access,
            "authenticated": True,
            "summary": summary,
            "files": all_files,
            "security_config": security_config,
            "service_properties": service_props,
            "errors": errors,
        }
        
        # Score avançado + distribuição + recomendações
        payload.update(calculate_advanced_risk(payload))
        payload["severity_distribution"] = build_severity_distribution(all_files)
        payload["recommendations"] = build_recommendations_azure_authenticated(payload)
        
        return payload


def build_recommendations_azure_authenticated(payload: Dict) -> List[str]:
    """
    Gera recomendações específicas para Azure Blob Storage autenticado.
    """
    level = payload.get("risk_level", "NONE")
    security = payload.get("security_config", {})
    service_props = payload.get("service_properties", {})
    files = payload.get("files", [])
    
    # Analisa tipos de arquivos expostos
    severity_dist = build_severity_distribution(files)
    has_critical = severity_dist.get("critical", 0) > 0
    has_high = severity_dist.get("high", 0) > 0
    
    recs: List[str] = []
    
    # ============================================================
    # RECOMENDAÇÕES CRÍTICAS
    # ============================================================
    if level == "CRITICAL":
        if security.get("public_containers", 0) > 0:
            public_names = security.get("public_container_names", [])
            recs.append(f"🚨 URGENTE: {len(public_names)} container(s) com acesso público: {', '.join(public_names[:3])}")
            recs.append("Executar: az storage container set-permission --name <container> --public-access off")
        
        if has_critical:
            recs.append("🔑 CRÍTICO: Remover imediatamente arquivos .env, .pem, .key expostos.")
            recs.append("Rotacionar todas as credenciais que possam ter sido expostas.")
        
        if not security.get("logging_enabled"):
            recs.append("📝 CRÍTICO: Habilitar Storage Analytics Logging (CIS Azure 3.3).")
            recs.append("az storage logging update --services b --log rwd --retention 90")
        
        if not security.get("soft_delete_enabled"):
            recs.append("🗑️ Habilitar Soft Delete para proteção contra exclusões acidentais (CIS Azure 3.8).")
            recs.append("az storage blob service-properties delete-policy update --enable true --days-retained 7")
    
    # ============================================================
    # RECOMENDAÇÕES HIGH
    # ============================================================
    elif level == "HIGH":
        if security.get("public_containers", 0) > 0:
            recs.append("⚠️ Revisar e restringir acesso público aos containers.")
        
        if has_high:
            recs.append("Remover arquivos SQL, backups e databases expostos.")
        
        if not security.get("versioning_enabled"):
            recs.append("Habilitar Blob Versioning para proteção de dados (CIS Azure 3.11).")
        
        if security.get("cors_has_wildcards"):
            recs.append("⚠️ CORS com wildcards (*) detectado - restringir allowed_origins.")
    
    # ============================================================
    # RECOMENDAÇÕES ESPECÍFICAS DE CONFIGURAÇÃO
    # ============================================================
    
    # Logging retention
    if security.get("logging_enabled") and not security.get("logging_retention_enabled"):
        recs.append("Configurar retention policy para logs (mínimo 90 dias para compliance).")
    
    # Soft delete retention
    if security.get("soft_delete_enabled"):
        retention_days = security.get("soft_delete_retention_days", 0)
        if retention_days < 7:
            recs.append(f"Soft delete configurado com apenas {retention_days} dias - aumentar para mínimo 7 dias.")
    
    # Static website
    if security.get("static_website_enabled"):
        recs.append("Static website habilitado - revisar se necessário e aplicar HTTPS obrigatório.")
    
    # Encryption
    encrypted_count = sum(1 for f in files if f.get("server_encrypted", False))
    if encrypted_count < len(files):
        recs.append(f"⚠️ {len(files) - encrypted_count} blobs sem server-side encryption - habilitar default encryption.")
    
    # ============================================================
    # RECOMENDAÇÕES GERAIS DE SEGURANÇA
    # ============================================================
    if level in ("CRITICAL", "HIGH"):
        recs.append("Configurar 'Secure transfer required' (HTTPS obrigatório) no storage account.")
        recs.append("Implementar Network Rules para restringir acesso por IP/VNet.")
        recs.append("Habilitar Microsoft Defender for Storage para detecção de ameaças.")
        recs.append("Configurar Shared Access Signatures (SAS) com expiration curta para acesso temporário.")
        recs.append("Implementar Customer-managed keys (CMK) com Azure Key Vault para criptografia.")
        recs.append("Revisar Azure Activity Log para detectar acessos suspeitos.")
        recs.append("Aplicar Azure Policy para governança de storage accounts.")
    
    # ============================================================
    # COMPLIANCE
    # ============================================================
    compliance_issues = []
    
    if not security.get("logging_enabled"):
        compliance_issues.append("CIS Azure 3.3 (Logging)")
    
    if not security.get("soft_delete_enabled"):
        compliance_issues.append("CIS Azure 3.8 (Soft Delete)")
    
    if security.get("public_containers", 0) > 0:
        compliance_issues.append("CIS Azure 3.7 (Public Access)")
    
    if compliance_issues:
        recs.append(f"📋 Compliance gaps detectados: {', '.join(compliance_issues)}")
    
    # ============================================================
    # SEM RISCOS
    # ============================================================
    if level == "NONE":
        recs.append("✅ Nenhum risco crítico detectado.")
        recs.append("Manter monitoramento contínuo via Azure Security Center.")
    
    return recs


# Função helper para uso direto
def scan_azure_blob_authenticated(
    account_or_url: str,
    container: Optional[str] = None,
    connection_string: Optional[str] = None,
    sas_token: Optional[str] = None,
    account_key: Optional[str] = None,
    max_objects: int = 1000
) -> Dict[str, Any]:
    """
    Helper function para scan autenticado de Azure Blob Storage.
    
    Args:
        account_or_url: Nome da storage account ou URL
        container: Nome do container (opcional)
        connection_string: Azure Connection String (preferencial)
        sas_token: SAS Token
        account_key: Account Key
        max_objects: Máximo de objetos a listar
    
    Returns:
        Dict com resultado completo do scan autenticado
    """
    auditor = AzureBlobAuthenticatedAuditor(
        account_or_url=account_or_url,
        container=container,
        connection_string=connection_string,
        sas_token=sas_token,
        account_key=account_key,
        max_objects=max_objects
    )
    return auditor.run()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Uso: python auditor_azure_authenticated.py <account> <connection_string> [container]")
        print("Exemplo: python auditor_azure_authenticated.py gododev 'DefaultEndpointsProtocol=https;...'")
        sys.exit(1)
    
    account = sys.argv[1]
    connection_string = sys.argv[2]
    container = sys.argv[3] if len(sys.argv) > 3 else None
    
    print(f"Authenticated scan: {account}")
    if container:
        print(f"Container: {container}")
    
    result = scan_azure_blob_authenticated(
        account_or_url=account,
        connection_string=connection_string,
        container=container
    )
    
    print("\n" + "=" * 60)
    print(json.dumps(result, indent=2))
