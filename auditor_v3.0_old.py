import os
import json
import datetime
import xml.etree.ElementTree as ET
import re
import hashlib
from collections import Counter, defaultdict
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse

import requests

# =========================================
# CONFIGURAÇÕES E PATHS
# =========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.path.join(BASE_DIR, "templates", "dashboard.html")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
HISTORY_FOLDER = os.path.join(REPORT_FOLDER, "history")

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(HISTORY_FOLDER, exist_ok=True)


# =========================================
# PADRÕES SENSÍVEIS EXPANDIDOS
# =========================================
SENSITIVE_PATTERNS = {
    # Chaves AWS
    "aws_access_key": re.compile(r'(AKIA[0-9A-Z]{16})', re.IGNORECASE),
    "aws_secret_key": re.compile(r'aws_secret_access_key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})', re.IGNORECASE),
    
    # Chaves privadas
    "private_key": re.compile(r'-----BEGIN.*PRIVATE KEY-----', re.IGNORECASE),
    "rsa_key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE),
    "openssh_key": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.IGNORECASE),
    
    # API Keys
    "api_key": re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    "bearer_token": re.compile(r'bearer\s+[a-zA-Z0-9_\-\.]{20,}', re.IGNORECASE),
    
    # Senhas
    "password": re.compile(r'password["\']?\s*[:=]\s*["\']?[^\s]{8,}', re.IGNORECASE),
    "db_password": re.compile(r'(DB|DATABASE)_PASSWORD["\']?\s*[:=]\s*["\']?[^\s]{8,}', re.IGNORECASE),
    
    # Tokens
    "token": re.compile(r'token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', re.IGNORECASE),
    "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', re.IGNORECASE),
    
    # Conexões de banco de dados
    "connection_string": re.compile(r'(mongodb|mysql|postgresql|postgres):\/\/[^\s]+', re.IGNORECASE),
    
    # Chaves de serviços populares
    "github_token": re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}', re.IGNORECASE),
    "slack_token": re.compile(r'xox[baprs]-[a-zA-Z0-9-]+', re.IGNORECASE),
    "stripe_key": re.compile(r'sk_live_[a-zA-Z0-9]{24,}', re.IGNORECASE),
    "google_api": re.compile(r'AIza[a-zA-Z0-9_\-]{35}', re.IGNORECASE),
}


# =========================================
# CLASSIFICAÇÃO AVANÇADA DE ARQUIVOS
# =========================================
def classify_file(key: str, size: int, etag: str = "") -> dict:
    """
    Classifica o arquivo com análise aprimorada:
    - categoria (12 categorias distintas)
    - severidade (Crítica, Alta, Média, Baixa)
    - cvss score (0.0 - 10.0)
    - recomendações específicas
    - detecção de padrões sensíveis no nome
    """
    name = key.split("/")[-1]
    path_lower = key.lower()
    name_lower = name.lower()
    
    if "." in name:
        ext = name.rsplit(".", 1)[-1].lower()
    else:
        ext = ""

    category = "Outros"
    risk = "Baixa"
    cvss = 2.0
    recommendations = []
    tags = []

    # Extensões categorizadas
    img_ext = {"jpg", "jpeg", "png", "gif", "svg", "ico", "bmp", "webp", "avif", "tiff", "heic"}
    cfg_ext = {"cfg", "conf", "config", "ini", "yaml", "yml", "json", "xml", "properties", "toml", "env"}
    key_ext = {"pem", "key", "ppk", "pfx", "p12", "crt", "cer", "der", "pub", "asc", "gpg"}
    backup_ext = {"sql", "bak", "dump", "gz", "zip", "7z", "rar", "tar", "tgz", "bz2", "backup"}
    font_ext = {"woff", "woff2", "ttf", "eot", "otf"}
    static_ext = {"css", "js", "map", "html", "htm"}
    doc_ext = {"pdf", "doc", "docx", "xls", "xlsx", "csv", "txt", "md", "odt", "ods", "ppt", "pptx"}
    code_ext = {"py", "java", "cpp", "c", "h", "rb", "php", "go", "rs", "ts", "jsx", "tsx", "vue"}
    video_ext = {"mp4", "avi", "mov", "wmv", "flv", "mkv", "webm"}
    audio_ext = {"mp3", "wav", "flac", "aac", "ogg", "m4a"}
    compressed_ext = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz"}
    
    # Arquivos críticos específicos
    critical_files = {
        ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
        "credentials", ".aws/credentials", "id_rsa", "id_ed25519", "id_ecdsa",
        ".ssh/id_rsa", "secrets.json", "secret.json", "private.key", "privatekey.pem",
        "apikeys.json", "service-account.json", "firebase-adminsdk.json",
        ".npmrc", ".pypirc", "shadow", "passwd", "htpasswd"
    }
    
    # Palavras-chave suspeitas
    suspicious_keywords = [
        "secret", "token", "password", "passwd", "pwd", "apikey", "api_key",
        "private", "credential", "auth", "bearer", "oauth"
    ]

    # ANÁLISE DE NOME DO ARQUIVO
    contains_suspicious = any(word in name_lower for word in suspicious_keywords)
    
    # ======================================
    # VERIFICAÇÃO 1: Arquivos críticos específicos (PRIORIDADE MÁXIMA)
    # ======================================
    if any(cf in path_lower for cf in critical_files):
        category = "🔴 Chaves/Credenciais"
        risk = "Crítica"
        cvss = 10.0
        tags.append("EXPOSIÇÃO_CRÍTICA")
        recommendations.extend([
            "🚨 URGENTE: Remova este arquivo IMEDIATAMENTE do bucket",
            "🔄 Rotacione TODAS as credenciais que possam estar neste arquivo",
            "📊 Audite logs de acesso (CloudTrail) para identificar acessos não autorizados",
            "🔒 Se o arquivo for necessário, mova para AWS Secrets Manager",
            "📧 Considere notificar equipe de segurança sobre exposição"
        ])

    # ======================================
    # VERIFICAÇÃO 2: Extensões de chaves/certificados
    # ======================================
    elif ext in key_ext:
        category = "🔴 Chaves/Credenciais"
        risk = "Crítica"
        cvss = 9.8
        tags.append("CHAVE_PRIVADA")
        recommendations.extend([
            "🔐 Remova chaves privadas/certificados do bucket público",
            "🔄 Rotacione as chaves comprometidas imediatamente",
            "☁️ Use AWS Secrets Manager ou Systems Manager Parameter Store",
            "📝 Documente o incidente de exposição"
        ])

    # ======================================
    # VERIFICAÇÃO 3: Nome suspeito de credenciais
    # ======================================
    elif contains_suspicious:
        category = "🔴 Chaves/Credenciais"
        risk = "Crítica"
        cvss = 9.5
        tags.append("NOME_SUSPEITO")
        recommendations.extend([
            "⚠️ Arquivo com nome indicativo de conter credenciais",
            "🔍 Faça análise do conteúdo para confirmar exposição",
            "🔄 Se confirmado, rotacione credenciais",
            "📋 Implemente varredura de secrets no CI/CD"
        ])

    # ======================================
    # VERIFICAÇÃO 4: Diretório .git exposto
    # ======================================
    elif ".git/" in path_lower or path_lower.endswith(".git"):
        category = "🔴 Repositório"
        risk = "Crítica"
        cvss = 9.0
        tags.append("GIT_EXPOSTO")
        recommendations.extend([
            "💥 Repositório .git exposto permite reconstrução completa do código",
            "🗑️ Remova TODOS os arquivos .git/ do bucket",
            "🔍 Verifique se há credenciais no histórico de commits",
            "🛡️ Configure .gitignore adequadamente"
        ])

    # ======================================
    # VERIFICAÇÃO 5: Arquivos de configuração
    # ======================================
    elif ext in cfg_ext:
        category = "⚠️ Configurações"
        risk = "Alta"
        cvss = 8.0
        tags.append("CONFIG")
        
        # Aumenta severidade para .env e similares
        if ext == "env" or ".env" in name_lower:
            risk = "Crítica"
            cvss = 9.5
            category = "🔴 Chaves/Credenciais"
            tags.append("ENV_FILE")
        
        recommendations.extend([
            "🔍 Revise o conteúdo: pode conter credenciais hardcoded",
            "🔐 Use variáveis de ambiente e serviços de secrets",
            "📝 Documente configurações sensíveis que não devem ser expostas",
            "🔒 Se necessário expor configs, remova dados sensíveis"
        ])

    # ======================================
    # VERIFICAÇÃO 6: Backups de banco de dados
    # ======================================
    elif ext in backup_ext or any(x in name_lower for x in ["backup", "bkp", "dump"]):
        category = "⚠️ Backups"
        risk = "Alta"
        cvss = 8.5
        tags.append("BACKUP")
        
        # SQL dumps são mais críticos
        if ext == "sql" or "dump" in name_lower:
            cvss = 9.0
            tags.append("SQL_DUMP")
            recommendations.append("💾 SQL dumps podem conter dados sensíveis completos")
        
        recommendations.extend([
            "🔐 Backups DEVEM ser criptografados (SSE-KMS)",
            "🔒 Mova para bucket privado com acesso restrito",
            "📅 Implemente políticas de retenção e lifecycle",
            "🗑️ Configure expurgo automático de backups antigos"
        ])

    # ======================================
    # VERIFICAÇÃO 7: Código-fonte
    # ======================================
    elif ext in code_ext:
        category = "⚠️ Código-fonte"
        risk = "Alta"
        cvss = 7.5
        tags.append("SOURCE_CODE")
        recommendations.extend([
            "💻 Código-fonte exposto revela lógica de negócio e vulnerabilidades",
            "🔍 Pode conter comentários com informações sensíveis",
            "🚫 Nunca exponha código-fonte em buckets públicos",
            "📦 Use repositórios privados (GitHub/GitLab/CodeCommit)"
        ])

    # ======================================
    # VERIFICAÇÃO 8: Arquivos comprimidos grandes
    # ======================================
    elif ext in compressed_ext:
        category = "📦 Comprimidos"
        risk = "Média"
        cvss = 6.0
        tags.append("COMPRESSED")
        
        if size > 100 * 1024 * 1024:  # > 100MB
            cvss = 7.0
            risk = "Alta"
            recommendations.append("📦 Arquivo comprimido grande pode conter múltiplos arquivos sensíveis")
        
        recommendations.extend([
            "🔍 Audite o conteúdo do arquivo comprimido",
            "🔐 Se contém dados sensíveis, criptografe e restrinja acesso"
        ])

    # ======================================
    # VERIFICAÇÃO 9: Documentos
    # ======================================
    elif ext in doc_ext:
        category = "📄 Documentos"
        risk = "Média"
        cvss = 5.5
        tags.append("DOCUMENT")
        
        # PDFs e planilhas podem conter dados sensíveis
        if ext in ["pdf", "xlsx", "xls", "csv"]:
            cvss = 6.5
            recommendations.append("📊 Documentos podem conter informações confidenciais ou PII")
        
        recommendations.extend([
            "🔍 Revise se não contém dados pessoais (LGPD/GDPR)",
            "🔒 Considere aplicar watermarks ou DRM se necessário"
        ])

    # ======================================
    # VERIFICAÇÃO 10: Source maps
    # ======================================
    elif ext == "map" or name.endswith(".map"):
        category = "⚠️ Source Maps"
        risk = "Média"
        cvss = 6.0
        tags.append("SOURCE_MAP")
        recommendations.extend([
            "🗺️ Source maps expõem código-fonte original (pré-minificação)",
            "🚫 Remova source maps de produção",
            "⚙️ Configure build para não gerar .map em produção"
        ])

    # ======================================
    # VERIFICAÇÃO 11: Vídeos e áudios
    # ======================================
    elif ext in video_ext or ext in audio_ext:
        category = "🎬 Mídia"
        risk = "Baixa"
        cvss = 2.5
        tags.append("MEDIA")
        
        if size > 500 * 1024 * 1024:  # > 500MB
            recommendations.append("💰 Arquivos grandes impactam custos de transferência/armazenamento")

    # ======================================
    # VERIFICAÇÃO 12: Fontes web
    # ======================================
    elif ext in font_ext:
        category = "🔤 Fontes"
        risk = "Baixa"
        cvss = 1.5
        tags.append("FONT")

    # ======================================
    # VERIFICAÇÃO 13: Arquivos estáticos (CSS/JS/HTML)
    # ======================================
    elif ext in static_ext:
        category = "📱 Estáticos"
        risk = "Baixa"
        cvss = 2.0
        tags.append("STATIC")
        
        # JS pode conter lógica sensível
        if ext == "js":
            cvss = 3.5
            recommendations.append("⚠️ JS pode conter lógica de negócio ou endpoints de API")

    # ======================================
    # VERIFICAÇÃO 14: Imagens
    # ======================================
    elif ext in img_ext:
        category = "🖼️ Imagens"
        risk = "Baixa"
        cvss = 2.0
        tags.append("IMAGE")

    # ======================================
    # VERIFICAÇÃO 15: Outros/Desconhecidos
    # ======================================
    else:
        category = "❓ Outros"
        risk = "Média"
        cvss = 5.0
        tags.append("UNKNOWN")
        
        if size > 100 * 1024 * 1024:  # > 100MB
            recommendations.append("💰 Arquivo grande com extensão desconhecida")
        
        recommendations.append("🔍 Verifique manualmente a natureza deste arquivo")

    # ======================================
    # ANÁLISE DE TAMANHO (todos os arquivos)
    # ======================================
    if size > 1024 * 1024 * 1024:  # > 1GB
        recommendations.append(f"💰 Arquivo muito grande ({format_size(size)}) - revise necessidade")

    # ======================================
    # VERIFICAÇÃO DE ACESSO PÚBLICO
    # ======================================
    if risk in ["Crítica", "Alta"]:
        recommendations.insert(0, "🌐 Arquivo de risco elevado acessível publicamente")

    return {
        "filename": key,
        "extension": ext,
        "size": size,
        "category": category,
        "risk": risk,
        "cvss": cvss,
        "recommendations": recommendations,
        "tags": tags,
        "etag": etag,
        "last_modified": None  # Será preenchido se disponível
    }


# =========================================
# FUNÇÕES AUXILIARES
# =========================================
def format_size(bytes_value: int) -> str:
    """Formata bytes em formato legível"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def calculate_risk_score(files: List[Dict]) -> float:
    """Calcula score de risco ponderado (0-10)"""
    if not files:
        return 0.0
    
    weights = {
        "Crítica": 10.0,
        "Alta": 7.5,
        "Média": 5.0,
        "Baixa": 2.0
    }
    
    total_weight = sum(weights.get(f["risk"], 5.0) for f in files)
    return round(total_weight / len(files), 1)


# =========================================
# AUDITOR S3 APRIMORADO
# =========================================
class S3Auditor:
    def __init__(self, bucket: str):
        self.bucket = bucket.strip()
        self.region = "unknown"
        self.public_access = False
        self.files = []
        self.critical_findings = []
        self.scan_metadata = {
            "start_time": datetime.datetime.now(),
            "end_time": None,
            "duration_seconds": 0
        }

    def log(self, msg: str, level: str = "INFO"):
        """Log com emojis e níveis"""
        emoji_map = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨",
            "SUCCESS": "✅"
        }
        print(f"{emoji_map.get(level, 'ℹ️')} {msg}")

    def _fetch(self, url: str, method: str = "GET", params=None) -> Optional[requests.Response]:
        """Requisição HTTP com tratamento robusto de erros"""
        try:
            headers = {
                'User-Agent': 'S3-Security-Auditor/3.0',
                'Accept': '*/*'
            }
            
            if method == "GET":
                return requests.get(url, params=params, headers=headers, timeout=20)
            else:
                return requests.head(url, headers=headers, timeout=15)
                
        except requests.exceptions.Timeout:
            self.log(f"Timeout ao acessar {url[:50]}...", "WARNING")
        except requests.exceptions.ConnectionError:
            self.log(f"Erro de conexão", "ERROR")
        except requests.exceptions.RequestException as e:
            self.log(f"Erro na requisição: {str(e)[:100]}", "ERROR")
        except Exception as e:
            self.log(f"Erro inesperado: {str(e)[:100]}", "ERROR")
            
        return None

    def validate_bucket_name(self) -> bool:
        """Valida nome do bucket segundo regras AWS S3"""
        # Verifica comprimento (3-63 caracteres)
        if not (3 <= len(self.bucket) <= 63):
            self.log(f"Nome do bucket deve ter entre 3-63 caracteres: {self.bucket}", "ERROR")
            return False
        
        # Padrão válido: letras minúsculas, números, hífens e pontos
        pattern = r'^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$'
        if not re.match(pattern, self.bucket):
            self.log(f"Nome de bucket com caracteres inválidos: {self.bucket}", "ERROR")
            return False
        
        # Não pode ter padrões inválidos
        if '..' in self.bucket or '.-' in self.bucket or '-.' in self.bucket:
            self.log(f"Nome contém padrões inválidos (.., .-, -.): {self.bucket}", "ERROR")
            return False
        
        # Não pode parecer um IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', self.bucket):
            self.log(f"Nome não pode ser formato de IP: {self.bucket}", "ERROR")
            return False
            
        return True

    def detect_region(self):
        """Detecta região do bucket com múltiplas tentativas"""
        self.log("Detectando região...")
        
        # Tentativa 1: HEAD request no endpoint genérico
        url = f"https://{self.bucket}.s3.amazonaws.com"
        resp = self._fetch(url, "HEAD")
        
        if resp and "x-amz-bucket-region" in resp.headers:
            self.region = resp.headers["x-amz-bucket-region"]
            self.log(f"Região detectada: {self.region}", "SUCCESS")
            return
        
        # Tentativa 2: GET request simples
        resp = self._fetch(url, "GET", params={"max-keys": "0"})
        if resp and "x-amz-bucket-region" in resp.headers:
            self.region = resp.headers["x-amz-bucket-region"]
            self.log(f"Região detectada: {self.region}", "SUCCESS")
            return
        
        # Se não conseguir detectar, usa endpoint genérico
        self.log("Não foi possível detectar a região (usando endpoint genérico)", "WARNING")
        self.region = "us-east-1"  # Fallback

    def check_public_access(self):
        """Verifica múltiplos aspectos de acesso público"""
        self.log("Verificando acesso público...")
        
        # Monta URL baseado na região
        if self.region and self.region != "unknown":
            base = f"https://{self.bucket}.s3.{self.region}.amazonaws.com"
        else:
            base = f"https://{self.bucket}.s3.amazonaws.com"

        # Tenta listar objetos
        params = {"list-type": "2", "max-keys": "1"}
        resp = self._fetch(base, "GET", params=params)

        if resp and resp.status_code == 200:
            if "<ListBucketResult" in resp.text and "AccessDenied" not in resp.text:
                self.public_access = True
                self.log("🚨 ATENÇÃO: Acesso público PERMITIDO!", "CRITICAL")
                
                self.critical_findings.append({
                    "type": "public_bucket",
                    "severity": "CRITICAL",
                    "cvss": 9.0,
                    "message": "Bucket permite listagem pública de objetos (List)",
                    "remediation": "Ative Block Public Access nas configurações do bucket"
                })
            else:
                self.public_access = False
                self.log("🔒 Acesso público: BLOQUEADO", "SUCCESS")
        else:
            self.public_access = False
            status = resp.status_code if resp else "N/A"
            self.log(f"Não foi possível verificar acesso público (HTTP {status})", "WARNING")

    def deep_scan_http(self, max_files: Optional[int] = None, check_content: bool = False):
        """
        Varredura profunda com opções avançadas
        
        Args:
            max_files: Limite de arquivos a processar (None = sem limite)
            check_content: Se True, tenta baixar e analisar conteúdo de arquivos suspeitos
        """
        if not self.public_access:
            self.log("Deep scan cancelado: bucket não permite listagem pública", "WARNING")
            return

        self.log("🔍 Executando deep scan HTTP...")

        # Determina URL base
        if self.region and self.region != "unknown":
            base = f"https://{self.bucket}.s3.{self.region}.amazonaws.com"
        else:
            base = f"https://{self.bucket}.s3.amazonaws.com"

        params = {"list-type": "2", "max-keys": "1000"}
        continuation_token = None
        total = 0
        critical_count = 0
        high_count = 0

        while True:
            # Atualiza token de continuação
            if continuation_token:
                params["continuation-token"] = continuation_token
            elif "continuation-token" in params:
                del params["continuation-token"]

            # Faz requisição
            resp = self._fetch(base, "GET", params=params)
            if not resp or resp.status_code != 200:
                self.log(f"Falha ao listar objetos (HTTP {resp.status_code if resp else 'N/A'})", "ERROR")
                break

            # Parse XML
            try:
                xml_root = ET.fromstring(resp.text)
            except ET.ParseError as e:
                self.log(f"Erro ao parsear XML: {e}", "ERROR")
                break

            # Processa objetos
            contents = xml_root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Contents")
            if not contents:
                # Tenta sem namespace
                contents = xml_root.findall(".//Contents")

            for c in contents:
                # Extrai metadados
                key_el = c.find("{http://s3.amazonaws.com/doc/2006-03-01/}Key")
                if key_el is None:
                    key_el = c.find("Key")
                
                size_el = c.find("{http://s3.amazonaws.com/doc/2006-03-01/}Size")
                if size_el is None:
                    size_el = c.find("Size")
                
                etag_el = c.find("{http://s3.amazonaws.com/doc/2006-03-01/}ETag")
                if etag_el is None:
                    etag_el = c.find("ETag")
                
                modified_el = c.find("{http://s3.amazonaws.com/doc/2006-03-01/}LastModified")
                if modified_el is None:
                    modified_el = c.find("LastModified")
                
                if key_el is None:
                    continue
                    
                key = key_el.text
                try:
                    size = int(size_el.text) if size_el is not None else 0
                except (ValueError, TypeError):
                    size = 0
                
                etag = etag_el.text.strip('"') if etag_el is not None else ""
                last_modified = modified_el.text if modified_el is not None else None

                # Classifica arquivo
                file_info = classify_file(key, size, etag)
                file_info["last_modified"] = last_modified
                
                # Adiciona URL de acesso
                file_info["url"] = f"{base}/{key}"
                
                self.files.append(file_info)
                total += 1

                # Contadores por severidade
                if file_info["risk"] == "Crítica":
                    critical_count += 1
                    self.critical_findings.append({
                        "type": "critical_file",
                        "severity": "CRITICAL",
                        "cvss": file_info["cvss"],
                        "file": key,
                        "category": file_info["category"],
                        "size": size,
                        "recommendations": file_info["recommendations"]
                    })
                    self.log(f"🚨 CRÍTICO: {key}", "CRITICAL")
                    
                elif file_info["risk"] == "Alta":
                    high_count += 1

                # Limite de arquivos
                if max_files and total >= max_files:
                    break

            # Log de progresso
            if total % 1000 == 0:
                self.log(f"📊 Processados: {total:,} arquivos ({critical_count} críticos, {high_count} altos)")

            # Verifica limite
            if max_files and total >= max_files:
                self.log(f"⚠️ Limite de {max_files:,} arquivos atingido", "WARNING")
                break

            # Verifica paginação
            is_trunc = xml_root.find(".//{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated")
            if is_trunc is None:
                is_trunc = xml_root.find(".//IsTruncated")
                
            if is_trunc is not None and is_trunc.text == "true":
                token_el = xml_root.find(".//{http://s3.amazonaws.com/doc/2006-03-01/}NextContinuationToken")
                if token_el is None:
                    token_el = xml_root.find(".//NextContinuationToken")
                    
                if token_el is not None and token_el.text:
                    continuation_token = token_el.text
                    continue
            
            # Fim da paginação
            break

        self.log(f"✅ Scan finalizado: {total:,} arquivos ({critical_count} críticos, {high_count} altos)", "SUCCESS")

    def compute_summary(self) -> dict:
        """Calcula estatísticas detalhadas do scan"""
        risk_counts = Counter(f["risk"] for f in self.files)
        category_counts = Counter(f["category"] for f in self.files)
        extension_counts = Counter(f["extension"] for f in self.files if f["extension"])
        total_files = len(self.files)

        # CVSS médio por severidade
        cvss_by_risk = defaultdict(list)
        for f in self.files:
            cvss_by_risk[f["risk"]].append(f["cvss"])
        
        avg_cvss_by_risk = {
            risk: round(sum(values) / len(values), 1) if values else 0.0
            for risk, values in cvss_by_risk.items()
        }

        # Score de risco ponderado
        risk_score = calculate_risk_score(self.files)

        # Tamanho total e por categoria
        total_size = sum(f["size"] for f in self.files)
        size_by_category = defaultdict(int)
        for f in self.files:
            size_by_category[f["category"]] += f["size"]

        # Top 10 maiores arquivos
        largest_files = sorted(self.files, key=lambda x: x["size"], reverse=True)[:10]

        # Arquivos mais críticos (top 20)
        most_critical = sorted(
            [f for f in self.files if f["risk"] in ["Crítica", "Alta"]],
            key=lambda x: x["cvss"],
            reverse=True
        )[:20]

        return {
            "total_files": total_files,
            "total_size": total_size,
            "total_size_formatted": format_size(total_size),
            "risk_counts": dict(risk_counts),
            "category_counts": dict(category_counts),
            "extension_counts": dict(extension_counts.most_common(20)),
            "avg_cvss_by_risk": avg_cvss_by_risk,
            "risk_score": risk_score,
            "critical_findings_count": len(self.critical_findings),
            "size_by_category": dict(size_by_category),
            "largest_files": [
                {"filename": f["filename"], "size": f["size"], "size_formatted": format_size(f["size"])}
                for f in largest_files
            ],
            "most_critical": [
                {"filename": f["filename"], "cvss": f["cvss"], "risk": f["risk"], "category": f["category"]}
                for f in most_critical
            ]
        }

    def update_history(self, summary: dict) -> list:
        """Mantém histórico das últimas 100 execuções com mais metadados"""
        history_file = os.path.join(HISTORY_FOLDER, f"{self.bucket}.json")
        
        try:
            if os.path.exists(history_file):
                with open(history_file, "r", encoding="utf-8") as f:
                    history = json.load(f)
            else:
                history = []
        except (json.JSONDecodeError, IOError):
            self.log("Histórico corrompido ou inacessível, criando novo", "WARNING")
            history = []

        entry = {
            "date": datetime.datetime.now().isoformat(timespec="seconds"),
            "total_files": summary["total_files"],
            "total_size": summary["total_size"],
            "risk_score": summary["risk_score"],
            "critical": summary["risk_counts"].get("Crítica", 0),
            "high": summary["risk_counts"].get("Alta", 0),
            "medium": summary["risk_counts"].get("Média", 0),
            "low": summary["risk_counts"].get("Baixa", 0),
            "duration_seconds": self.scan_metadata.get("duration_seconds", 0)
        }
        history.append(entry)
        
        # Mantém últimas 100 execuções
        history = history[-100:]

        try:
            with open(history_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except IOError as e:
            self.log(f"Erro ao salvar histórico: {e}", "ERROR")

        return history

    def generate_recommendations(self, summary: dict) -> List[str]:
        """Gera recomendações personalizadas baseadas nos achados"""
        recommendations = []
        
        critical = summary["risk_counts"].get("Crítica", 0)
        high = summary["risk_counts"].get("Alta", 0)
        
        # Recomendações baseadas em severidade
        if critical > 0:
            recommendations.append(f"🚨 **URGENTE**: {critical} arquivo(s) crítico(s) detectado(s) — Ação imediata necessária!")
            recommendations.append("🔄 Rotacione todas as credenciais potencialmente expostas")
            recommendations.append("📊 Audite CloudTrail logs para verificar acessos não autorizados")
        
        if high > 0:
            recommendations.append(f"⚠️ **ATENÇÃO**: {high} arquivo(s) de risco alto — Priorize revisão")
        
        # Recomendações gerais de segurança
        if self.public_access:
            recommendations.append("🔒 **Ative Block Public Access** no bucket (4 opções)")
        
        recommendations.extend([
            "📝 Habilite **Server Access Logging** e **AWS CloudTrail**",
            "🔐 Implemente **políticas IAM de menor privilégio**",
            "🛡️ Use **AWS Secrets Manager** para credenciais",
            "🔄 Habilite **versionamento** do bucket",
            "🔑 Configure **criptografia SSE-KMS** com chaves gerenciadas",
            "🤖 Configure **Amazon Macie** para descoberta de dados sensíveis",
            "⚙️ Implemente **políticas de lifecycle** para expurgo automático",
            "🔍 Configure **AWS Config Rules** para conformidade contínua",
            "🚨 Habilite **AWS GuardDuty** para detecção de ameaças",
            "📋 Documente todos os arquivos legítimos que devem permanecer"
        ])
        
        # Recomendações específicas por categoria
        if summary["category_counts"].get("🔴 Chaves/Credenciais", 0) > 0:
            recommendations.append("⚠️ Implante **git-secrets** e **truffleHog** no CI/CD")
        
        if summary["category_counts"].get("⚠️ Backups", 0) > 0:
            recommendations.append("💾 Mova backups para bucket dedicado com replicação cross-region")
        
        if summary["total_size"] > 100 * 1024 * 1024 * 1024:  # > 100GB
            recommendations.append("💰 Considere **S3 Intelligent-Tiering** para otimizar custos")
        
        return recommendations

    def export_json_and_html(self):
        """Exporta relatórios JSON e HTML completos"""
        # Calcula tempo de execução
        self.scan_metadata["end_time"] = datetime.datetime.now()
        self.scan_metadata["duration_seconds"] = (
            self.scan_metadata["end_time"] - self.scan_metadata["start_time"]
        ).total_seconds()
        
        summary = self.compute_summary()
        history = self.update_history(summary)
        recommendations = self.generate_recommendations(summary)

        # Estrutura do relatório
        report = {
            "bucket": self.bucket,
            "region": self.region,
            "public_access": self.public_access,
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "scan_duration_seconds": round(self.scan_metadata["duration_seconds"], 2),
            "auditor_version": "3.0",
            "files": self.files,
            "summary": summary,
            "history": history,
            "critical_findings": self.critical_findings,
            "recommendations": recommendations
        }

        # Exporta JSON
        json_name = f"{self.bucket}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_path = os.path.join(REPORT_FOLDER, json_name)

        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log(f"📄 JSON gerado: reports/{json_name}", "SUCCESS")
        except IOError as e:
            self.log(f"Erro ao salvar JSON: {e}", "ERROR")
            return

        # Gera HTML
        if not os.path.exists(TEMPLATE_FILE):
            self.log("⚠️ Template dashboard.html não encontrado; HTML não será gerado", "WARNING")
            return

        try:
            with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
                template = f.read()

            html = template.replace("__BUCKET_NAME__", self.bucket).replace("__REPORT_JSON__", json_name)

            html_name = f"{self.bucket}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            html_path = os.path.join(REPORT_FOLDER, html_name)

            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)

            self.log(f"🌐 HTML exportado: reports/{html_name}", "SUCCESS")
        except IOError as e:
            self.log(f"Erro ao gerar HTML: {e}", "ERROR")

    def print_summary(self):
        """Exibe resumo executivo detalhado no console"""
        summary = self.compute_summary()
        
        print("\n" + "="*70)
        print(f"📊 RESUMO EXECUTIVO DA AUDITORIA")
        print("="*70)
        print(f"🪣 Bucket: {self.bucket}")
        print(f"🌍 Região: {self.region}")
        print(f"🔓 Acesso público: {'SIM ⚠️' if self.public_access else 'NÃO ✅'}")
        print(f"⏱️  Duração do scan: {self.scan_metadata.get('duration_seconds', 0):.1f}s")
        print("="*70)
        
        print(f"\n📁 ARQUIVOS:")
        print(f"  Total: {summary['total_files']:,}")
        print(f"  Tamanho total: {summary['total_size_formatted']}")
        
        print(f"\n⚠️  DISTRIBUIÇÃO DE RISCO:")
        for risk in ["Crítica", "Alta", "Média", "Baixa"]:
            count = summary['risk_counts'].get(risk, 0)
            if count > 0:
                pct = (count / summary['total_files'] * 100) if summary['total_files'] > 0 else 0
                emoji = {"Crítica": "🚨", "Alta": "⚠️", "Média": "ℹ️", "Baixa": "✅"}
                print(f"  {emoji.get(risk, '•')} {risk}: {count:,} ({pct:.1f}%)")
        
        print(f"\n🎯 SCORE DE RISCO: {summary['risk_score']}/10")
        
        if self.critical_findings:
            print(f"\n🚨 DESCOBERTAS CRÍTICAS: {len(self.critical_findings)}")
            for finding in self.critical_findings[:5]:  # Mostra as 5 primeiras
                print(f"  • {finding.get('message', finding.get('file', 'Unknown'))}")
            if len(self.critical_findings) > 5:
                print(f"  ... e mais {len(self.critical_findings) - 5} descoberta(s)")
        
        print("\n" + "="*70)
        print("✅ Auditoria concluída! Relatórios exportados.")
        print("="*70 + "\n")

    def run(self, max_files: Optional[int] = None):
        """Executa auditoria completa"""
        print(f"\n{'='*70}")
        print(f"🔐 AUDITORIA DE SEGURANÇA S3 v3.0")
        print(f"{'='*70}")
        print(f"🪣 Bucket: {self.bucket}")
        print(f"📅 Data: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # Validações
        if not self.validate_bucket_name():
            self.log("❌ Auditoria abortada: nome de bucket inválido", "ERROR")
            return
        
        # Executa etapas
        self.detect_region()
        self.check_public_access()
        self.deep_scan_http(max_files=max_files)
        
        # Exporta resultados
        if self.files:
            self.export_json_and_html()
            self.print_summary()
        else:
            self.log("⚠️ Nenhum arquivo encontrado ou bucket inacessível", "WARNING")
        
        print(f"✅ Auditoria concluída em {self.scan_metadata.get('duration_seconds', 0):.1f}s\n")


# =========================================
# MAIN
# =========================================
if __name__ == "__main__":
    print("\n🔐 S3 Security Auditor v3.0 - Enterprise Edition")
    print("="*70)
    print("🛡️  Auditoria avançada de segurança para buckets AWS S3")
    print("="*70 + "\n")
    
    entry = input("🪣 Digite 1 ou mais buckets (separados por vírgula): ").strip()
    
    if not entry:
        print("❌ Nenhum bucket informado.")
        exit(1)
    
    buckets = [b.strip() for b in entry.split(",") if b.strip()]
    
    # Pergunta sobre limite
    limit_input = input(f"\n🔢 Limite de arquivos por bucket? (Enter = sem limite): ").strip()
    max_files = None
    if limit_input.isdigit():
        max_files = int(limit_input)
    
    print(f"\n📋 {len(buckets)} bucket(s) para auditar")
    if max_files:
        print(f"🔢 Limite: {max_files:,} arquivos por bucket")
    print()
    
    for i, b in enumerate(buckets, 1):
        if len(buckets) > 1:
            print(f"\n{'='*70}")
            print(f"📊 Auditando bucket {i}/{len(buckets)}")
            print(f"{'='*70}")
        
        auditor = S3Auditor(b)
        auditor.run(max_files=max_files)
        
        if i < len(buckets):
            print("\n" + "-"*70 + "\n")
    
    print(f"\n🎉 Todas as auditorias concluídas!")
    print(f"📁 Relatórios salvos em: {REPORT_FOLDER}\n")
