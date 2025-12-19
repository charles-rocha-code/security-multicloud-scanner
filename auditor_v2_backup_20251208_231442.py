#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import datetime
import xml.etree.ElementTree as ET
import re
from collections import Counter, defaultdict
from typing import Optional

import requests

# =========================================
# PATHS
# =========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.path.join(BASE_DIR, "templates", "dashboard.html")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
HISTORY_FOLDER = os.path.join(REPORT_FOLDER, "history")

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(HISTORY_FOLDER, exist_ok=True)


# =========================================
# PADRÕES SENSÍVEIS
# =========================================
SENSITIVE_PATTERNS = {
    "aws_keys": re.compile(r'(AKIA[0-9A-Z]{16})', re.IGNORECASE),
    "private_key": re.compile(r'-----BEGIN.*PRIVATE KEY-----', re.IGNORECASE),
    "api_key": re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', re.IGNORECASE),
    "password": re.compile(r'password["\']?\s*[:=]\s*["\']?[^\s]{8,}', re.IGNORECASE),
    "token": re.compile(r'token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', re.IGNORECASE),
}


# =========================================
# CLASSIFICAÇÃO MELHORADA DE ARQUIVOS
# =========================================
def classify_file(key: str, size: int) -> dict:
    """
    Classifica o arquivo por extensão e padrões em:
    - categoria (Chaves/Sigilos, Configurações, Backups, Documentos, Fontes, Imagens, Estáticos, Outros)
    - severidade (Crítica, Alta, Média, Baixa)
    - cvss aproximado
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

    # Extensões por categoria
    img_ext = {"jpg", "jpeg", "png", "gif", "svg", "ico", "bmp", "webp", "avif"}
    cfg_ext = {"cfg", "conf", "config", "ini", "yaml", "yml", "json", "xml", "properties", "toml"}
    key_ext = {"pem", "key", "ppk", "pfx", "p12", "crt", "cer", "der", "pub", "asc"}
    backup_ext = {"sql", "bak", "dump", "gz", "zip", "7z", "rar", "tar", "tgz", "bz2"}
    font_ext = {"woff", "woff2", "ttf", "eot", "otf"}
    static_ext = {"css", "js", "map", "html", "htm"}
    doc_ext = {"pdf", "doc", "docx", "xls", "xlsx", "csv", "txt", "md", "odt", "ods"}
    code_ext = {"py", "java", "cpp", "c", "h", "rb", "php", "go", "rs"}
    
    # Arquivos de ambiente críticos (exato match ou contains)
    critical_files = {
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.staging", "credentials", ".aws/credentials", "id_rsa",
        "id_ed25519", ".ssh/id_rsa", "secrets.json", "secret.json",
        "private.key", "privatekey.pem", "apikeys.json"
    }

    # VERIFICAÇÃO 1: Arquivos críticos específicos
    if any(cf in name_lower for cf in critical_files):
        category = "Chaves/Sigilos"
        risk = "Crítica"
        cvss = 9.8
        recommendations.append("URGENTE: Remova este arquivo imediatamente e rotacione as credenciais")
        recommendations.append("Revise logs de acesso para identificar possíveis acessos não autorizados")

    # VERIFICAÇÃO 2: Extensões de chaves/certificados
    elif ext in key_ext:
        category = "Chaves/Sigilos"
        risk = "Crítica"
        cvss = 9.5
        recommendations.append("Remova chaves privadas/certificados do bucket")
        recommendations.append("Use AWS Secrets Manager ou Parameter Store para credenciais")

    # VERIFICAÇÃO 3: Palavras-chave sensíveis no nome
    elif any(word in name_lower for word in ["secret", "token", "password", "passwd", "pwd", "apikey", "api_key"]):
        category = "Chaves/Sigilos"
        risk = "Crítica"
        cvss = 9.3
        recommendations.append("Arquivo com nome suspeito de conter credenciais")

    # VERIFICAÇÃO 4: Arquivos de configuração
    elif ext in cfg_ext or "config" in name_lower:
        category = "Configurações"
        risk = "Alta"
        cvss = 7.5
        recommendations.append("Revise se não há credenciais hardcoded no arquivo")
        recommendations.append("Use variáveis de ambiente para informações sensíveis")

    # VERIFICAÇÃO 5: Backups
    elif ext in backup_ext or "backup" in name_lower or "bkp" in name_lower:
        category = "Backups"
        risk = "Alta"
        cvss = 7.5
        recommendations.append("Backups devem ser criptografados e em buckets privados")
        recommendations.append("Implemente políticas de retenção e expurgo")

    # VERIFICAÇÃO 6: Código-fonte
    elif ext in code_ext or ".git" in path_lower:
        category = "Código-fonte"
        risk = "Alta"
        cvss = 7.0
        recommendations.append("Código-fonte exposto pode revelar vulnerabilidades")
        recommendations.append("Nunca exponha repositórios .git publicamente")

    # VERIFICAÇÃO 7: Documentos
    elif ext in doc_ext:
        category = "Documentos"
        risk = "Média"
        cvss = 5.5
        recommendations.append("Verifique se documentos não contêm informações confidenciais")

    # VERIFICAÇÃO 8: Fontes web
    elif ext in font_ext:
        category = "Fontes"
        risk = "Baixa"
        cvss = 1.5

    # VERIFICAÇÃO 9: Arquivos estáticos
    elif ext in static_ext:
        category = "Estáticos"
        risk = "Baixa"
        cvss = 2.0
        if ext == "map":
            recommendations.append("Source maps podem expor código-fonte original")
            cvss = 4.0
            risk = "Média"

    # VERIFICAÇÃO 10: Imagens
    elif ext in img_ext:
        category = "Imagens"
        risk = "Baixa"
        cvss = 2.0

    # VERIFICAÇÃO 11: Outros (default para desconhecidos)
    else:
        category = "Outros"
        risk = "Média"
        cvss = 5.0
        if size > 100 * 1024 * 1024:  # > 100MB
            recommendations.append("Arquivo grande pode impactar custos de transferência")

    return {
        "filename": key,
        "extension": ext,
        "size": size,
        "category": category,
        "risk": risk,
        "cvss": cvss,
        "recommendations": recommendations,
        "mime": ""
    }


# =========================================
# AUDITOR MELHORADO
# =========================================
class S3Auditor:
    def __init__(self, bucket: str):
        self.bucket = bucket.strip()
        self.region = "unknown"
        self.public_access = False
        self.files = []
        self.critical_findings = []

    def log(self, msg: str, level: str = "INFO"):
        """Log com níveis: INFO, WARNING, ERROR, CRITICAL"""
        emoji = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨"
        }
        print(f"{emoji.get(level, 'ℹ️')} {msg}")

    def _fetch(self, url: str, method: str = "GET", params=None) -> Optional[requests.Response]:
        """Requisição HTTP com tratamento de erros"""
        try:
            headers = {
                'User-Agent': 'S3-Security-Auditor/2.0'
            }
            if method == "GET":
                return requests.get(url, params=params, headers=headers, timeout=15)
            else:
                return requests.head(url, headers=headers, timeout=10)
        except requests.exceptions.Timeout:
            self.log(f"Timeout ao acessar {url}", "WARNING")
        except requests.exceptions.ConnectionError:
            self.log(f"Erro de conexão ao acessar {url}", "ERROR")
        except Exception as e:
            self.log(f"Erro inesperado: {e}", "ERROR")
        return None

    def validate_bucket_name(self) -> bool:
        """Valida nome do bucket segundo regras AWS"""
        pattern = r'^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$'
        if not re.match(pattern, self.bucket):
            self.log(f"Nome de bucket inválido: {self.bucket}", "ERROR")
            return False
        if '..' in self.bucket or '.-' in self.bucket or '-.' in self.bucket:
            self.log(f"Nome de bucket com padrões inválidos: {self.bucket}", "ERROR")
            return False
        return True

    def detect_region(self):
        """Detecta região do bucket"""
        self.log("Detectando região...")
        url = f"https://{self.bucket}.s3.amazonaws.com"
        resp = self._fetch(url, "HEAD")
        
        if resp and "x-amz-bucket-region" in resp.headers:
            self.region = resp.headers["x-amz-bucket-region"]
            self.log(f"Região detectada: {self.region}")
        else:
            self.log("Não foi possível detectar a região (usando endpoint genérico)", "WARNING")

    def check_public_access(self):
        """Verifica se bucket permite listagem pública"""
        self.log("Verificando acesso público...")
        
        if self.region != "unknown":
            base = f"https://{self.bucket}.s3.{self.region}.amazonaws.com"
        else:
            base = f"https://{self.bucket}.s3.amazonaws.com"

        params = {"list-type": "2", "max-keys": "1"}
        resp = self._fetch(base, "GET", params=params)

        if resp and resp.status_code == 200:
            if "<ListBucketResult" in resp.text and "AccessDenied" not in resp.text:
                self.public_access = True
                self.log("ATENÇÃO: Acesso público permitido!", "CRITICAL")
                self.critical_findings.append({
                    "type": "public_bucket",
                    "severity": "CRITICAL",
                    "message": "Bucket permite listagem pública de objetos"
                })
            else:
                self.public_access = False
                self.log("Acesso público: Não permitido")
        else:
            self.public_access = False
            self.log("Não foi possível verificar acesso público", "WARNING")

    def deep_scan_http(self, max_files: Optional[int] = None):
        """
        Faz listagem profunda via HTTP API
        max_files: limite de arquivos (None = sem limite)
        """
        if not self.public_access:
            self.log("Deep scan pulado: bucket não permite listagem pública", "WARNING")
            return

        self.log("Executando deep scan HTTP...")

        if self.region != "unknown":
            base = f"https://{self.bucket}.s3.{self.region}.amazonaws.com"
        else:
            base = f"https://{self.bucket}.s3.amazonaws.com"

        params = {"list-type": "2", "max-keys": "1000"}
        continuation_token = None
        total = 0
        critical_count = 0

        while True:
            if continuation_token:
                params["continuation-token"] = continuation_token
            elif "continuation-token" in params:
                del params["continuation-token"]

            resp = self._fetch(base, "GET", params=params)
            if not resp or resp.status_code != 200:
                self.log("Falha ao listar objetos (abortando scan)", "ERROR")
                break

            try:
                xml_root = ET.fromstring(resp.text)
            except ET.ParseError as e:
                self.log(f"Erro ao parsear XML: {e}", "ERROR")
                break

            contents = xml_root.findall(".//{*}Contents")

            for c in contents:
                key_el = c.find("{*}Key")
                size_el = c.find("{*}Size")
                
                if key_el is None:
                    continue
                    
                key = key_el.text
                try:
                    size = int(size_el.text) if size_el is not None else 0
                except (ValueError, TypeError):
                    size = 0

                file_info = classify_file(key, size)
                self.files.append(file_info)
                total += 1

                # Alerta para arquivos críticos
                if file_info["risk"] == "Crítica":
                    critical_count += 1
                    self.critical_findings.append({
                        "type": "critical_file",
                        "severity": "CRITICAL",
                        "file": key,
                        "category": file_info["category"],
                        "cvss": file_info["cvss"]
                    })
                    self.log(f"🚨 CRÍTICO: {key}", "CRITICAL")

                if max_files and total >= max_files:
                    break

            if total % 1000 == 0:
                self.log(f"Processados: {total} arquivos ({critical_count} críticos)")

            if max_files and total >= max_files:
                break

            # Verifica paginação
            is_trunc = xml_root.find(".//{*}IsTruncated")
            if is_trunc is not None and is_trunc.text == "true":
                token_el = xml_root.find(".//{*}NextContinuationToken")
                if token_el is not None and token_el.text:
                    continuation_token = token_el.text
                    continue
            break

        self.log(f"Deep scan finalizado: {total} arquivos ({critical_count} críticos)")

    def compute_summary(self) -> dict:
        """Calcula métricas do scan"""
        risk_counts = Counter(f["risk"] for f in self.files)
        category_counts = Counter(f["category"] for f in self.files)
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
        if self.files:
            risk_score = round(sum(f["cvss"] for f in self.files) / len(self.files), 1)
        else:
            risk_score = 0.0

        # Tamanho total
        total_size = sum(f["size"] for f in self.files)

        return {
            "total_files": total_files,
            "total_size": total_size,
            "risk_counts": dict(risk_counts),
            "category_counts": dict(category_counts),
            "avg_cvss_by_risk": avg_cvss_by_risk,
            "risk_score": risk_score,
            "critical_findings_count": len(self.critical_findings)
        }

    def update_history(self, summary: dict) -> list:
        """Mantém histórico das últimas 50 execuções"""
        history_file = os.path.join(HISTORY_FOLDER, f"{self.bucket}.json")
        
        try:
            if os.path.exists(history_file):
                with open(history_file, "r", encoding="utf-8") as f:
                    history = json.load(f)
            else:
                history = []
        except json.JSONDecodeError:
            self.log("Histórico corrompido, criando novo", "WARNING")
            history = []

        entry = {
            "date": datetime.datetime.now().isoformat(timespec="seconds"),
            "total_files": summary["total_files"],
            "risk_score": summary["risk_score"],
            "critical": summary["risk_counts"].get("Crítica", 0),
            "high": summary["risk_counts"].get("Alta", 0),
            "medium": summary["risk_counts"].get("Média", 0),
            "low": summary["risk_counts"].get("Baixa", 0),
        }
        history.append(entry)
        
        # Mantém últimas 50 execuções
        history = history[-50:]

        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

        return history

    def export_json_and_html(self):
        """Exporta relatórios JSON e HTML"""
        summary = self.compute_summary()
        history = self.update_history(summary)

        report = {
            "bucket": self.bucket,
            "region": self.region,
            "public_access": self.public_access,
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "files": self.files,
            "summary": summary,
            "history": history,
            "critical_findings": self.critical_findings
        }

        json_name = f"{self.bucket}.json"
        json_path = os.path.join(REPORT_FOLDER, json_name)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"JSON gerado: reports/{json_name}")

        # Gera HTML
        if not os.path.exists(TEMPLATE_FILE):
            self.log("Template dashboard.html não encontrado; HTML não será gerado", "WARNING")
            return

        with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
            template = f.read()

        html = template.replace("__BUCKET_NAME__", self.bucket).replace("__REPORT_JSON__", json_name)

        html_name = f"{self.bucket}.html"
        html_path = os.path.join(REPORT_FOLDER, html_name)

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.log(f"HTML exportado: reports/{html_name}")

    def print_summary(self):
        """Exibe resumo no console"""
        summary = self.compute_summary()
        
        print("\n" + "="*60)
        print(f"📊 RESUMO DA AUDITORIA - {self.bucket}")
        print("="*60)
        print(f"Total de arquivos: {summary['total_files']}")
        print(f"Tamanho total: {self._format_size(summary['total_size'])}")
        print(f"Score de risco: {summary['risk_score']}/10")
        print(f"\nDistribuição de severidade:")
        for risk in ["Crítica", "Alta", "Média", "Baixa"]:
            count = summary['risk_counts'].get(risk, 0)
            if count > 0:
                pct = (count / summary['total_files'] * 100) if summary['total_files'] > 0 else 0
                print(f"  {risk}: {count} ({pct:.1f}%)")
        
        if self.critical_findings:
            print(f"\n🚨 ATENÇÃO: {len(self.critical_findings)} descobertas críticas!")
        print("="*60 + "\n")

    @staticmethod
    def _format_size(bytes: int) -> str:
        """Formata tamanho em bytes para formato legível"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024.0:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.2f} PB"

    def run(self):
        """Executa auditoria completa"""
        print(f"\n{'='*60}")
        print(f"🚀 AUDITORIA DE SEGURANÇA S3")
        print(f"{'='*60}")
        print(f"Bucket: {self.bucket}")
        print(f"Data: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        if not self.validate_bucket_name():
            self.log("Auditoria abortada: nome de bucket inválido", "ERROR")
            return
        
        self.detect_region()
        self.check_public_access()
        self.deep_scan_http()
        self.export_json_and_html()
        self.print_summary()
        
        print(f"✅ Auditoria concluída!")


# =========================================
# MAIN
# =========================================
if __name__ == "__main__":
    print("\n🔐 S3 Security Auditor v2.0")
    print("="*60)
    
    entry = input("Digite 1 bucket ou vários separados por vírgula: ").strip()
    
    if not entry:
        print("❌ Nenhum bucket informado.")
        exit(1)
    
    buckets = [b.strip() for b in entry.split(",") if b.strip()]
    
    print(f"\n📋 {len(buckets)} bucket(s) para auditar\n")
    
    for b in buckets:
        auditor = S3Auditor(b)
        auditor.run()
        print("\n" + "-"*60 + "\n")