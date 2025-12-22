# engine_risk.py
# ============================================================
# Advanced Risk Engine — Enterprise Edition
# Compatível com auditor.py (AWS S3) e auditor_gcs.py (GCS)
# Recomendações dinâmicas baseadas em melhores práticas
# ============================================================

from typing import Dict, List, Tuple
from collections import Counter

# ------------------------------------------------------------
# Regras de severidade por extensão / padrão
# ------------------------------------------------------------

SENSITIVE_EXTENSIONS = {
    ".env": ("CRITICAL", "Arquivo de ambiente exposto"),
    ".pem": ("CRITICAL", "Chave privada exposta"),
    ".key": ("CRITICAL", "Chave criptográfica exposta"),
    ".p12": ("CRITICAL", "Certificado PKCS#12 exposto"),
    ".pfx": ("CRITICAL", "Certificado PFX exposto"),
    ".crt": ("HIGH", "Certificado exposto"),
    ".cer": ("HIGH", "Certificado exposto"),
    ".sql": ("HIGH", "Dump SQL exposto"),
    ".db": ("HIGH", "Banco de dados exposto"),
    ".sqlite": ("HIGH", "Banco de dados SQLite exposto"),
    ".bak": ("HIGH", "Backup exposto"),
    ".backup": ("HIGH", "Backup exposto"),
    ".dump": ("HIGH", "Dump de dados exposto"),
    ".config": ("MEDIUM", "Arquivo de configuração exposto"),
    ".conf": ("MEDIUM", "Arquivo de configuração exposto"),
    ".ini": ("MEDIUM", "Arquivo de configuração exposto"),
    ".zip": ("MEDIUM", "Arquivo compactado exposto"),
    ".tar": ("MEDIUM", "Arquivo compactado exposto"),
    ".gz": ("MEDIUM", "Arquivo compactado exposto"),
    ".rar": ("MEDIUM", "Arquivo compactado exposto"),
    ".7z": ("MEDIUM", "Arquivo compactado exposto"),
    ".json": ("LOW", "Arquivo de dados exposto"),
    ".yaml": ("LOW", "Arquivo de configuração exposto"),
    ".yml": ("LOW", "Arquivo de configuração exposto"),
    ".xml": ("LOW", "Arquivo XML exposto"),
    ".csv": ("LOW", "Arquivo CSV exposto"),
}

# Padrões sensíveis em nomes de arquivos
SENSITIVE_PATTERNS = [
    ("password", "CRITICAL", "Arquivo com nome sensível (password)"),
    ("secret", "CRITICAL", "Arquivo com nome sensível (secret)"),
    ("credentials", "CRITICAL", "Arquivo com credenciais"),
    ("private", "HIGH", "Arquivo privado exposto"),
    ("confidential", "HIGH", "Arquivo confidencial exposto"),
    ("internal", "MEDIUM", "Arquivo interno exposto"),
]

SEVERITY_SCORE = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5
}

# ------------------------------------------------------------
# 1️⃣ Classificação de severidade (CONTRATO DO AUDITOR)
# ------------------------------------------------------------
def classify_severity(key: str) -> Tuple[str, str]:
    key_lower = key.lower()

    # Verifica extensões sensíveis
    for ext, (sev, reason) in SENSITIVE_EXTENSIONS.items():
        if key_lower.endswith(ext):
            return sev, reason

    # Verifica padrões sensíveis no nome
    for pattern, sev, reason in SENSITIVE_PATTERNS:
        if pattern in key_lower:
            return sev, reason

    return "LOW", "Arquivo público sem padrão sensível detectado"

# ------------------------------------------------------------
# 2️⃣ Distribuição de severidade
# ------------------------------------------------------------
def build_severity_distribution(files: List[Dict]) -> Dict[str, int]:
    counter = Counter(f.get("severity", "LOW") for f in files)
    return {
        "critical": counter.get("CRITICAL", 0),
        "high": counter.get("HIGH", 0),
        "medium": counter.get("MEDIUM", 0),
        "low": counter.get("LOW", 0),
    }

# ------------------------------------------------------------
# 3️⃣ Score avançado (CONTRATO DO AUDITOR)
#    Entrada: payload completo
#    Retorno: dict para payload.update()
# ------------------------------------------------------------
def calculate_advanced_risk(payload: Dict) -> Dict:
    files = payload.get("files", [])
    public_access = payload.get("public_access", False)

    score = 0
    details = []

    if public_access:
        score += 35
        details.append("Bucket com listagem pública habilitada (+35)")

    for f in files:
        sev = f.get("severity", "LOW")
        weight = SEVERITY_SCORE.get(sev, 0)
        score += weight

        if weight:
            details.append(
                f"{f.get('key')} classificado como {sev} (+{weight})"
            )

    score = min(score, 100)

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

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_details": details
    }

# ------------------------------------------------------------
# 4️⃣ Recomendações DINÂMICAS (CONTRATO DO AUDITOR)
# ------------------------------------------------------------
def build_recommendations(payload: Dict) -> List[str]:
    """
    Gera recomendações dinâmicas baseadas em:
    - Provider (AWS S3 vs GCS)
    - Nível de risco
    - Tipos específicos de arquivos expostos
    - Configurações de acesso público
    """
    provider = payload.get("provider", "UNIVERSAL")
    level = payload.get("risk_level", "NONE")
    public_access = payload.get("public_access", False)
    files = payload.get("files", [])
    
    # Analisa tipos de arquivos expostos
    severity_dist = build_severity_distribution(files)
    has_critical = severity_dist.get("critical", 0) > 0
    has_high = severity_dist.get("high", 0) > 0
    has_medium = severity_dist.get("medium", 0) > 0
    
    # Detecta tipos específicos de arquivos
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
            if provider == "AWS_S3":
                recs.append("🚨 URGENTE: Desabilitar listagem pública do bucket S3 imediatamente via AWS Console ou CLI.")
                recs.append("Remover todas as ACLs públicas e Bucket Policies que permitam acesso público.")
                recs.append("Habilitar 'Block Public Access' em todas as configurações do bucket.")
            elif provider == "GCS":
                recs.append("🚨 URGENTE: Desabilitar listagem pública do bucket GCS imediatamente via Cloud Console.")
                recs.append("Remover permissões 'allUsers' e 'allAuthenticatedUsers' das ACLs do bucket.")
                recs.append("Configurar IAM Conditions para restringir acesso ao bucket.")
        
        if "credentials" in critical_types:
            recs.append("🔑 CRÍTICO: Remover imediatamente arquivos .env, .pem, .key expostos.")
            recs.append("Rotacionar todas as credenciais e chaves que possam ter sido expostas.")
            if provider == "AWS_S3":
                recs.append("Verificar CloudTrail para detectar acessos não autorizados às credenciais.")
            elif provider == "GCS":
                recs.append("Verificar Cloud Audit Logs para detectar acessos não autorizados.")
        
        if "secrets" in critical_types:
            recs.append("🔐 CRÍTICO: Arquivos com 'password' ou 'secret' no nome foram expostos - remover e rotacionar.")
        
        if "database" in high_types:
            recs.append("💾 Remover dumps SQL e arquivos de banco de dados expostos.")
        
        if "backup" in high_types:
            recs.append("📦 Remover arquivos de backup expostos e revisar conteúdo vazado.")
        
        # Recomendações de segurança adicionais
        if provider == "AWS_S3":
            recs.append("Habilitar versionamento para recuperação de objetos em caso de exclusão acidental.")
            recs.append("Configurar AWS Config para monitoramento contínuo de conformidade.")
            recs.append("Implementar criptografia server-side (SSE-S3, SSE-KMS ou SSE-C).")
        elif provider == "GCS":
            recs.append("Habilitar versionamento de objetos para proteção contra exclusão acidental.")
            recs.append("Implementar criptografia gerenciada pelo cliente (CMEK) via Cloud KMS.")
            recs.append("Configurar Organization Policy Constraints para prevenir buckets públicos.")
    
    # ============================================================
    # RECOMENDAÇÕES HIGH
    # ============================================================
    elif level == "HIGH":
        if public_access:
            if provider == "AWS_S3":
                recs.append("⚠️ Desabilitar listagem pública do bucket S3.")
                recs.append("Revisar e restringir Bucket Policies para acesso mínimo necessário.")
            elif provider == "GCS":
                recs.append("⚠️ Desabilitar listagem pública do bucket GCS.")
                recs.append("Aplicar princípio do menor privilégio nas permissões IAM.")
        
        if has_critical or has_high:
            recs.append("Revisar e remover arquivos sensíveis expostos (certificados, backups, dumps SQL).")
            recs.append("Implementar política de retenção e lifecycle para arquivos temporários.")
        
        if provider == "AWS_S3":
            recs.append("Habilitar S3 Access Logging para auditoria de acessos.")
            recs.append("Configurar CloudWatch Alarms para detecção de acessos anormais.")
            recs.append("Implementar S3 Object Lock para dados críticos (WORM - Write Once Read Many).")
        elif provider == "GCS":
            recs.append("Habilitar Access Logs para auditoria de requisições ao bucket.")
            recs.append("Configurar alertas via Cloud Monitoring para acessos suspeitos.")
            recs.append("Implementar Retention Policies para proteção de dados críticos.")
    
    # ============================================================
    # RECOMENDAÇÕES MEDIUM
    # ============================================================
    elif level == "MEDIUM":
        if public_access:
            recs.append("Revisar necessidade de listagem pública do bucket.")
            recs.append("Considerar uso de URLs assinadas para acesso temporário controlado.")
        
        if has_medium:
            recs.append("Restringir acesso aos arquivos de configuração e compactados expostos.")
        
        if provider == "AWS_S3":
            recs.append("Aplicar S3 Bucket Keys para reduzir custos de criptografia KMS.")
            recs.append("Configurar S3 Inventory para rastreamento de objetos.")
            recs.append("Implementar tags de classificação de dados (Public, Internal, Confidential).")
        elif provider == "GCS":
            recs.append("Aplicar labels de classificação de dados nos objetos.")
            recs.append("Configurar Lifecycle Rules para arquivamento automático de dados antigos.")
    
    # ============================================================
    # RECOMENDAÇÕES LOW
    # ============================================================
    elif level == "LOW":
        recs.append("Manter monitoramento contínuo de segurança do bucket.")
        
        if provider == "AWS_S3":
            recs.append("Revisar periodicamente S3 Access Analyzer findings.")
            recs.append("Implementar AWS Macie para descoberta automática de dados sensíveis.")
        elif provider == "GCS":
            recs.append("Revisar periodicamente IAM Recommender para otimização de permissões.")
            recs.append("Implementar Data Loss Prevention (DLP) para proteção de dados sensíveis.")
    
    # ============================================================
    # SEM RISCOS DETECTADOS
    # ============================================================
    else:
        recs.append("✅ Nenhum risco crítico detectado no momento.")
        recs.append("Manter boas práticas de segurança e monitoramento contínuo.")
        
        if provider == "AWS_S3":
            recs.append("Revisar AWS Security Hub para recomendações adicionais de segurança.")
        elif provider == "GCS":
            recs.append("Revisar Security Command Center para insights de segurança.")
    
    # ============================================================
    # RECOMENDAÇÕES GERAIS (sempre incluídas se houver riscos)
    # ============================================================
    if level in ("CRITICAL", "HIGH", "MEDIUM"):
        recs.append("📊 Implementar auditoria regular de permissões e acessos.")
        recs.append("🔍 Realizar varreduras de segurança periódicas (mínimo mensal).")
        
        if provider == "AWS_S3":
            recs.append("Utilizar AWS Trusted Advisor para verificações automáticas de segurança.")
        elif provider == "GCS":
            recs.append("Ativar Security Health Analytics para detecção proativa de riscos.")
    
    return recs