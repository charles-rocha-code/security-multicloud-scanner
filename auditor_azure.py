# auditor_azure.py
"""
Auditor Azure Blob Storage - Scan público (sem credenciais)
Suporta:
- Detecção de storage account
- Listagem de containers públicos
- Listagem de blobs públicos
- Classificação de severidade
"""

from __future__ import annotations

import requests
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from engine_risk import classify_severity, build_severity_distribution, calculate_advanced_risk, build_recommendations
from cve_mapping import enrich_finding


class AzureBlobAuditor:
    """
    Auditor Azure Blob Storage sem credenciais:
      - Descobre storage account do URL
      - Testa listagem pública de containers
      - Testa listagem pública de blobs
      - Classifica severidade dos arquivos
      - Calcula score de risco
    """

    def __init__(self, account_or_url: str, container: Optional[str] = None, max_objects: int = 200, timeout: int = 10):
        """
        Args:
            account_or_url: Nome da conta ou URL (ex: gododev.blob.core.windows.net)
            container: Nome do container específico (opcional)
            max_objects: Número máximo de objetos a listar
            timeout: Timeout para requisições HTTP
        """
        self.input = account_or_url.strip()
        self.container = container
        self.max_objects = max_objects
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CloudSecurityScannerPRO/1.0",
            "x-ms-version": "2020-10-02"  # Azure Storage API version
        })

    def _parse_account(self) -> str:
        """
        Extrai o nome da storage account do input.
        
        Formatos suportados:
        - gododev.blob.core.windows.net
        - https://gododev.blob.core.windows.net
        - gododev
        """
        s = self.input.lower()

        # Se vier URL completa
        if "://" in s:
            u = urlparse(s)
            host = u.netloc
            # Remove .blob.core.windows.net
            if ".blob.core.windows.net" in host:
                return host.split(".blob.core.windows.net")[0]
            return host.split(":")[0]

        # Se vier account.blob.core.windows.net
        if ".blob.core.windows.net" in s:
            return s.split(".blob.core.windows.net")[0]

        # Se vier só o nome da conta
        return s

    def _list_containers(self, account: str) -> Tuple[bool, List[str], Optional[str]]:
        """
        Tenta listar containers da storage account.
        
        Returns:
            (public_access, containers, error)
        """
        # Endpoint de listagem de containers
        url = f"https://{account}.blob.core.windows.net/?comp=list"
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=True)
            
            # 200 = listagem pública habilitada
            if response.status_code == 200 and response.text.strip().startswith("<"):
                try:
                    root = ET.fromstring(response.text)
                    
                    # Parse XML response
                    containers = []
                    for container_elem in root.findall(".//Container"):
                        name_elem = container_elem.find("Name")
                        if name_elem is not None and name_elem.text:
                            containers.append(name_elem.text.strip())
                    
                    return True, containers, None
                
                except Exception as e:
                    return False, [], f"Erro ao parsear XML de containers: {e}"
            
            # 403/401 = acesso negado (privado)
            elif response.status_code in (403, 401):
                return False, [], None
            
            # 404 = storage account não existe
            elif response.status_code == 404:
                return False, [], f"Storage account '{account}' não encontrada (404)"
            
            else:
                return False, [], f"Resposta inesperada: HTTP {response.status_code}"
        
        except requests.exceptions.Timeout:
            return False, [], f"Timeout ao conectar com {url}"
        except requests.exceptions.ConnectionError:
            return False, [], f"Erro de conexão com {url}"
        except Exception as e:
            return False, [], f"Erro inesperado: {str(e)[:100]}"

    def _list_blobs(self, account: str, container: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Tenta listar blobs de um container.
        
        Returns:
            (public_access, files, error)
        """
        # Endpoint de listagem de blobs
        url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&maxresults={self.max_objects}"
        
        files: List[Dict[str, Any]] = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=True)
            
            # 200 = listagem pública habilitada
            if response.status_code == 200 and response.text.strip().startswith("<"):
                try:
                    root = ET.fromstring(response.text)
                    
                    # Parse XML response
                    # Namespace Azure: http://schemas.microsoft.com/windowsazure
                    ns = ""
                    if root.tag.startswith("{"):
                        ns = root.tag.split("}")[0] + "}"
                    
                    for blob_elem in root.findall(f".//{ns}Blob"):
                        name_elem = blob_elem.find(f"{ns}Name")
                        properties_elem = blob_elem.find(f"{ns}Properties")
                        
                        if name_elem is None:
                            continue
                        
                        blob_name = name_elem.text.strip()
                        
                        # Extrair tamanho
                        size = 0
                        if properties_elem is not None:
                            size_elem = properties_elem.find(f"{ns}Content-Length")
                            if size_elem is not None and size_elem.text:
                                try:
                                    size = int(size_elem.text)
                                except ValueError:
                                    pass
                        
                        # Classificar severidade
                        sev, reason = classify_severity(blob_name)

                        # URL pública do blob
                        blob_url = f"https://{account}.blob.core.windows.net/{container}/{blob_name}"

                        files.append(enrich_finding({
                            "key": blob_name,
                            "size": size,
                            "severity": sev,
                            "reason": reason,
                            "url": blob_url,
                            "container": container
                        }, "AZURE"))
                    
                    return True, files, None
                
                except Exception as e:
                    return False, [], f"Erro ao parsear XML de blobs: {e}"
            
            # 403/401 = acesso negado
            elif response.status_code in (403, 401):
                return False, [], None
            
            # 404 = container não existe
            elif response.status_code == 404:
                return False, [], f"Container '{container}' não encontrado (404)"
            
            else:
                return False, [], f"Resposta inesperada: HTTP {response.status_code}"
        
        except requests.exceptions.Timeout:
            return False, [], f"Timeout ao conectar com {url}"
        except requests.exceptions.ConnectionError:
            return False, [], f"Erro de conexão com {url}"
        except Exception as e:
            return False, [], f"Erro inesperado: {str(e)[:100]}"

    def run(self) -> Dict[str, Any]:
        """
        Executa auditoria da Azure Blob Storage.
        
        Fluxo:
        1. Parse do storage account
        2. Se container não especificado:
           - Tenta listar containers
           - Scaneia cada container público
        3. Se container especificado:
           - Scaneia apenas esse container
        """
        account = self._parse_account()
        
        all_files: List[Dict[str, Any]] = []
        errors: List[str] = []
        containers_scanned: List[str] = []
        public_access = False
        
        # Se container específico foi fornecido
        if self.container:
            print(f"Scanning specific container: {self.container}")
            public_listing, files, error = self._list_blobs(account, self.container)
            
            if error:
                errors.append(error)
            
            if public_listing:
                public_access = True
                all_files.extend(files)
                containers_scanned.append(self.container)
        
        # Senão, tenta descobrir containers
        else:
            print(f"Discovering containers in storage account: {account}")
            containers_public, containers, error = self._list_containers(account)
            
            if error:
                errors.append(error)
            
            if containers_public and containers:
                public_access = True
                print(f"Found {len(containers)} containers: {containers}")
                
                # Scaneia cada container encontrado
                for container in containers[:10]:  # Limita a 10 containers
                    print(f"Scanning container: {container}")
                    blob_public, files, blob_error = self._list_blobs(account, container)
                    
                    if blob_error:
                        errors.append(f"Container '{container}': {blob_error}")
                    
                    if blob_public:
                        all_files.extend(files)
                        containers_scanned.append(container)
                    
                    # Limita total de objetos
                    if len(all_files) >= self.max_objects:
                        all_files = all_files[:self.max_objects]
                        break
            
            elif not containers_public:
                # Tenta container padrão comum
                default_containers = ["$web", "public", "data", "files"]
                
                for container in default_containers:
                    blob_public, files, _ = self._list_blobs(account, container)
                    
                    if blob_public:
                        public_access = True
                        all_files.extend(files)
                        containers_scanned.append(container)
                        
                        if len(all_files) >= self.max_objects:
                            all_files = all_files[:self.max_objects]
                            break
        
        # Monta payload final
        summary = {
            "objects_scanned": len(all_files),
            "total_size_bytes": sum(int(f.get("size", 0)) for f in all_files),
            "containers_scanned": len(containers_scanned)
        }
        
        payload: Dict[str, Any] = {
            "provider": "AZURE_BLOB",
            "account": account,
            "region": "global",  # Azure não expõe região via API pública
            "container": self.container or f"{len(containers_scanned)} containers",
            "containers": containers_scanned,
            "public_access": public_access,
            "public_listing": public_access,
            "summary": summary,
            "files": all_files,
            "errors": errors,
        }
        
        # Score avançado + distribuição + recomendações
        payload.update(calculate_advanced_risk(payload))
        payload["severity_distribution"] = build_severity_distribution(all_files)
        payload["recommendations"] = build_recommendations_azure(payload)
        
        return payload


def build_recommendations_azure(payload: Dict) -> List[str]:
    """
    Gera recomendações específicas para Azure Blob Storage.
    """
    level = payload.get("risk_level", "NONE")
    public_access = payload.get("public_access", False)
    files = payload.get("files", [])
    
    # Analisa tipos de arquivos expostos
    severity_dist = build_severity_distribution(files)
    has_critical = severity_dist.get("critical", 0) > 0
    has_high = severity_dist.get("high", 0) > 0
    
    # Detecta tipos específicos
    critical_types = set()
    high_types = set()
    
    for f in files:
        key = f.get("key", "").lower()
        sev = f.get("severity", "LOW")
        
        if sev == "CRITICAL":
            if any(ext in key for ext in [".env", ".pem", ".key"]):
                critical_types.add("credentials")
            if "password" in key or "secret" in key:
                critical_types.add("secrets")
        elif sev == "HIGH":
            if any(ext in key for ext in [".sql", ".db", ".sqlite"]):
                high_types.add("database")
            if any(ext in key for ext in [".bak", ".backup"]):
                high_types.add("backup")
    
    recs: List[str] = []
    
    # ============================================================
    # RECOMENDAÇÕES CRÍTICAS
    # ============================================================
    if level == "CRITICAL":
        if public_access:
            recs.append("🚨 URGENTE: Desabilitar acesso público aos containers do Azure Blob Storage imediatamente.")
            recs.append("Remover permissões de 'Public access level' de todos os containers.")
            recs.append("Configurar 'Allow Blob public access' como 'Disabled' no storage account.")
        
        if "credentials" in critical_types:
            recs.append("🔑 CRÍTICO: Remover imediatamente arquivos .env, .pem, .key expostos.")
            recs.append("Rotacionar todas as credenciais que possam ter sido expostas.")
            recs.append("Verificar Azure Activity Log para detectar acessos não autorizados.")
        
        if "secrets" in critical_types:
            recs.append("🔐 CRÍTICO: Arquivos com 'password' ou 'secret' no nome foram expostos - remover e rotacionar.")
        
        if "database" in high_types:
            recs.append("💾 Remover dumps SQL e arquivos de banco de dados expostos.")
        
        if "backup" in high_types:
            recs.append("📦 Remover arquivos de backup expostos e revisar conteúdo vazado.")
        
        # Recomendações Azure específicas
        recs.append("Habilitar 'Soft delete' para blobs para recuperação de exclusões acidentais.")
        recs.append("Configurar 'Blob versioning' para proteção de dados.")
        recs.append("Implementar criptografia com Customer-managed keys (CMK) via Azure Key Vault.")
        recs.append("Habilitar 'Storage Analytics logging' para auditoria.")
    
    # ============================================================
    # RECOMENDAÇÕES HIGH
    # ============================================================
    elif level == "HIGH":
        if public_access:
            recs.append("⚠️ Desabilitar acesso público aos containers.")
            recs.append("Revisar e aplicar 'Private' access level em todos os containers.")
        
        if has_critical or has_high:
            recs.append("Revisar e remover arquivos sensíveis expostos.")
            recs.append("Implementar lifecycle management para arquivos temporários.")
        
        recs.append("Habilitar 'Diagnostic settings' para logs de requisições.")
        recs.append("Configurar 'Azure Defender for Storage' para detecção de ameaças.")
        recs.append("Implementar 'Shared Access Signatures (SAS)' para acesso temporário controlado.")
        recs.append("Habilitar 'Secure transfer required' (HTTPS obrigatório).")
    
    # ============================================================
    # RECOMENDAÇÕES MEDIUM
    # ============================================================
    elif level == "MEDIUM":
        if public_access:
            recs.append("Revisar necessidade de acesso público aos containers.")
            recs.append("Considerar uso de SAS tokens para acesso temporário controlado.")
        
        if severity_dist.get("medium", 0) > 0:
            recs.append("Restringir acesso aos arquivos de configuração expostos.")
        
        recs.append("Aplicar tags de classificação de dados nos blobs.")
        recs.append("Configurar lifecycle policies para otimização de custos (Cool/Archive tiers).")
        recs.append("Implementar CORS policies restritivas.")
    
    # ============================================================
    # RECOMENDAÇÕES LOW
    # ============================================================
    elif level == "LOW":
        recs.append("Manter monitoramento contínuo de segurança dos storage accounts.")
        recs.append("Revisar periodicamente Azure Security Center recommendations.")
        recs.append("Implementar Azure Policy para governança de storage accounts.")
    
    # ============================================================
    # SEM RISCOS
    # ============================================================
    else:
        recs.append("✅ Nenhum risco crítico detectado no momento.")
        recs.append("Manter boas práticas de segurança e monitoramento contínuo.")
        recs.append("Revisar Azure Security Center para recomendações adicionais.")
    
    # ============================================================
    # RECOMENDAÇÕES GERAIS
    # ============================================================
    if level in ("CRITICAL", "HIGH", "MEDIUM"):
        recs.append("📊 Implementar auditoria regular de permissões e acessos.")
        recs.append("🔍 Realizar varreduras de segurança periódicas (mínimo mensal).")
        recs.append("Utilizar Azure Advisor para verificações automáticas de segurança.")
        recs.append("Ativar Microsoft Defender for Cloud para detecção proativa de riscos.")
    
    return recs


# Função helper para uso direto
def scan_azure_blob(account_or_url: str, container: Optional[str] = None, max_objects: int = 200) -> Dict[str, Any]:
    """
    Helper function para scan rápido de Azure Blob Storage.
    
    Args:
        account_or_url: Nome da storage account ou URL (ex: gododev.blob.core.windows.net)
        container: Nome do container (opcional, se não especificado tenta descobrir)
        max_objects: Máximo de objetos a listar
    
    Returns:
        Dict com resultado completo do scan
    """
    auditor = AzureBlobAuditor(account_or_url, container, max_objects)
    return auditor.run()


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Uso: python auditor_azure.py <account_or_url> [container]")
        print("Exemplo: python auditor_azure.py gododev.blob.core.windows.net")
        print("Exemplo: python auditor_azure.py gododev public")
        sys.exit(1)
    
    account = sys.argv[1]
    container = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Scanning Azure Blob Storage: {account}")
    if container:
        print(f"Container: {container}")
    
    result = scan_azure_blob(account, container)
    
    print("\n" + "=" * 60)
    print(json.dumps(result, indent=2))
