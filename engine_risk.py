# engine_risk.py
# ============================================================
# Advanced Risk Engine — Enterprise Edition
# Compatível com auditor.py (AWS S3) e auditor_gcs.py (GCS)
# Recomendações dinâmicas baseadas em melhores práticas
# ============================================================

from typing import Dict, List, Optional, Tuple
from collections import Counter
import math
import re

# ------------------------------------------------------------
# Regras de severidade por extensão / padrão
# ------------------------------------------------------------

SENSITIVE_EXTENSIONS = {
    # CRITICAL — chaves, certificados e ambientes
    ".env":      ("CRITICAL", "Arquivo de ambiente exposto"),
    ".pem":      ("CRITICAL", "Chave privada exposta"),
    ".key":      ("CRITICAL", "Chave criptográfica exposta"),
    ".p12":      ("CRITICAL", "Certificado PKCS#12 exposto"),
    ".pfx":      ("CRITICAL", "Certificado PFX exposto"),
    ".p8":       ("CRITICAL", "Chave privada JWT/APNs exposta"),
    ".ppk":      ("CRITICAL", "Chave privada PuTTY exposta"),
    ".kdbx":     ("CRITICAL", "Banco de senhas KeePass exposto"),
    ".jks":      ("CRITICAL", "Java KeyStore exposto"),
    ".keystore": ("CRITICAL", "Java KeyStore exposto"),
    # HIGH — certificados públicos, dumps e backups
    ".crt":    ("HIGH", "Certificado exposto"),
    ".cer":    ("HIGH", "Certificado exposto"),
    ".sql":    ("HIGH", "Dump SQL exposto"),
    ".db":     ("HIGH", "Banco de dados exposto"),
    ".sqlite": ("HIGH", "Banco de dados SQLite exposto"),
    ".bak":    ("HIGH", "Backup exposto"),
    ".backup": ("HIGH", "Backup exposto"),
    ".dump":   ("HIGH", "Dump de dados exposto"),
    # MEDIUM — configurações e compactados
    ".config": ("MEDIUM", "Arquivo de configuração exposto"),
    ".conf":   ("MEDIUM", "Arquivo de configuração exposto"),
    ".ini":    ("MEDIUM", "Arquivo de configuração exposto"),
    ".zip":    ("MEDIUM", "Arquivo compactado exposto"),
    ".tar":    ("MEDIUM", "Arquivo compactado exposto"),
    ".gz":     ("MEDIUM", "Arquivo compactado exposto"),
    ".rar":    ("MEDIUM", "Arquivo compactado exposto"),
    ".7z":     ("MEDIUM", "Arquivo compactado exposto"),
    # LOW — dados estruturados
    ".json": ("LOW", "Arquivo de dados exposto"),
    ".yaml": ("LOW", "Arquivo de configuração exposto"),
    ".yml":  ("LOW", "Arquivo de configuração exposto"),
    ".xml":  ("LOW", "Arquivo XML exposto"),
    ".csv":  ("LOW", "Arquivo CSV exposto"),
}

# Padrões sensíveis em nomes de arquivos
SENSITIVE_PATTERNS = [
    ("password",    "CRITICAL", "Arquivo com nome sensível (password)"),
    ("secret",      "CRITICAL", "Arquivo com nome sensível (secret)"),
    ("credentials", "CRITICAL", "Arquivo com credenciais"),
    ("token",       "CRITICAL", "Arquivo com token/chave de API exposto"),
    ("apikey",      "CRITICAL", "Arquivo com chave de API exposta"),
    ("api_key",     "CRITICAL", "Arquivo com chave de API exposta"),
    ("private",     "HIGH",     "Arquivo privado exposto"),
    ("confidential","HIGH",     "Arquivo confidencial exposto"),
    ("internal",    "MEDIUM",   "Arquivo interno exposto"),
]

# Ranking de severidade para comparação (usado em classify_severity)
_SEV_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

# ------------------------------------------------------------
# 0️⃣ Inspeção de CONTEÚDO (complementa a classificação por nome/extensão,
#    que nunca olha o que está dentro do arquivo -- um AKIA... dentro de um
#    "notas.txt" passava invisível antes disto)
# ------------------------------------------------------------

# Só vale a pena baixar e inspecionar arquivos pequenos e prováveis de texto;
# baixar cada objeto de um bucket com milhares de arquivos não escala.
CONTENT_SCAN_MAX_BYTES = 51_200   # 50 KB
CONTENT_SCAN_MAX_FILES = 300      # limite por scan -- controla custo/tempo

SECRET_CONTENT_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL", "Chave de acesso AWS encontrada no conteúdo do arquivo"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "CRITICAL", "Chave privada encontrada no conteúdo do arquivo"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "HIGH", "Token JWT encontrado no conteúdo do arquivo"),
    (re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-/+=]{16,}"), "HIGH", "Possível chave de API encontrada no conteúdo do arquivo"),
]

_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")
_ENTROPY_THRESHOLD = 4.0  # bits/caractere -- limiar comum pra tokens base64/hex reais


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def should_scan_content(key: str, size: int, severity: str) -> bool:
    """Decide se vale a pena baixar o conteúdo deste arquivo. Extensões já
    CRITICAL (.env, .pem, etc.) não precisam -- já foram flagradas. O ponto
    cego real é arquivo "sem cara de sensível" (.txt, .log, .csv, sem
    extensão) que pode ter um segredo embutido."""
    if severity == "CRITICAL":
        return False
    if size <= 0 or size > CONTENT_SCAN_MAX_BYTES:
        return False
    return True


def scan_content_for_secrets(content: str) -> Optional[Tuple[str, str]]:
    """Retorna (severidade, motivo) se achar padrão de credencial conhecido
    ou um token de alta entropia (indício de chave/segredo real) no
    conteúdo. None se nada suspeito for encontrado."""
    for pattern, sev, reason in SECRET_CONTENT_PATTERNS:
        if pattern.search(content):
            return sev, reason

    for token in _ENTROPY_TOKEN_RE.findall(content):
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            return "HIGH", "Possível segredo de alta entropia encontrado no conteúdo do arquivo"

    return None

# ------------------------------------------------------------
# 1️⃣ Classificação de severidade (CONTRATO DO AUDITOR)
# ------------------------------------------------------------
def classify_severity(key: str) -> Tuple[str, str]:
    key_lower = key.lower()

    ext_result: Tuple[str, str] | None = None
    for ext, (sev, reason) in SENSITIVE_EXTENSIONS.items():
        if key_lower.endswith(ext):
            ext_result = (sev, reason)
            break

    pat_result: Tuple[str, str] | None = None
    for pattern, sev, reason in SENSITIVE_PATTERNS:
        if pattern in key_lower:
            pat_result = (sev, reason)
            break

    # Retorna a severidade mais alta entre extensão e padrão de nome.
    # Ex: credentials.sql → CRITICAL (padrão) > HIGH (extensão)
    if ext_result and pat_result:
        return ext_result if _SEV_RANK[ext_result[0]] >= _SEV_RANK[pat_result[0]] else pat_result
    return ext_result or pat_result or ("LOW", "Arquivo sem padrão sensível detectado")

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

    dist = build_severity_distribution(files)
    c = dist["critical"]
    h = dist["high"]
    m = dist["medium"]
    l = dist["low"]

    # Curva logarítmica: cresce rápido no início, acomoda volumes grandes.
    # ref = número de findings que atinge ~63% do peso máximo da categoria.
    def _log(count: int, weight: float, ref: float) -> float:
        return weight * (1 - math.exp(-count / ref))

    score = 0.0
    score += _log(c, 65.0, 3.0)   # 3 críticos  ≈ 65 pts
    score += _log(h, 45.0, 8.0)   # 8 altos     ≈ 28 pts; ~20 → 41 pts (MEDIUM); ~75 → 45 pts (MEDIUM)
    score += _log(m, 12.0, 15.0)  # 15 médios   ≈ 12 pts
    score += _log(l,  8.0, 50.0)  # 50 baixos   ≈  8 pts

    if public_access:
        score += 15.0

    score = min(round(score), 100)

    details = []
    if public_access:
        details.append("Bucket com listagem pública habilitada (+15)")
    if c: details.append(f"{c} arquivo(s) CRITICAL detectado(s)")
    if h: details.append(f"{h} arquivo(s) HIGH detectado(s)")
    if m: details.append(f"{m} arquivo(s) MEDIUM detectado(s)")
    if l: details.append(f"{l} arquivo(s) LOW detectado(s)")

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
            if "database" in high_types:
                recs.append("⚠️ Remover imediatamente dumps SQL e arquivos de banco de dados expostos.")
            if "backup" in high_types:
                recs.append("⚠️ Remover imediatamente arquivos de backup expostos.")
            if not high_types:
                recs.append("Revisar e remover arquivos sensíveis expostos (certificados, backups, dumps SQL).")
            recs.append("Implementar política de retenção e lifecycle para arquivos temporários e backups.")
        
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

        # Arquivos HIGH presentes mesmo com score total MEDIUM ainda requerem ação
        if has_high:
            if "database" in high_types:
                recs.append("⚠️ Remover ou mover para armazenamento seguro dumps SQL e arquivos de banco de dados expostos.")
            if "backup" in high_types:
                recs.append("⚠️ Remover arquivos de backup expostos e revisar conteúdo potencialmente sensível.")
            if not high_types:
                recs.append("Revisar e remover arquivos de alta criticidade detectados no bucket.")
            recs.append("Implementar política de retenção e lifecycle para arquivos temporários e backups.")

        if has_medium:
            recs.append("Restringir acesso aos arquivos de configuração e compactados expostos.")

        if provider == "AWS_S3":
            recs.append("Habilitar S3 Access Logging para auditoria de acessos ao bucket.")
            recs.append("Configurar S3 Inventory para rastreamento e classificação de objetos.")
            recs.append("Implementar tags de classificação de dados (Public, Internal, Confidential).")
        elif provider == "GCS":
            recs.append("Habilitar Access Logs para auditoria de requisições ao bucket.")
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