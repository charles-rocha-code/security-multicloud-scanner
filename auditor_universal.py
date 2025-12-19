# auditor_universal.py
# Auditor HTTP Universal → Serve para QUALQUER domínio público
# Compatível com dashboard, API e JSON unificado dos outros auditores

import os
import re
import json
import math
import logging
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from auditor import human_size, classify_file, calc_risk_score

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UniversalAuditor")


# ============================================================
# UTILIDADES
# ============================================================

def normalize_target(value: str) -> str:
    """
    Aceita:
        cdn.minhaempresa.com
        https://cdn.minhaempresa.com
        meusite.com/arquivos/
    Sempre retorna domínio base sem protocolo.
    """
    v = value.strip().lower()

    # remover protocolo
    if v.startswith("http://") or v.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(v)
        return parsed.netloc or parsed.path

    return v


def url_join(base: str, path: str) -> str:
    if base.endswith("/"):
        return base + path
    return base + "/" + path


def extract_links_from_html(html: str) -> List[str]:
    """
    Extrai possíveis arquivos contidos em HTML (caso o alvo liste diretórios).
    Ex.: href="file.js", src="img.png", etc.
    """
    links = re.findall(r'href=["\'](.*?)["\']', html, flags=re.IGNORECASE)
    links += re.findall(r'src=["\'](.*?)["\']', html, flags=re.IGNORECASE)
    links = [l.strip() for l in links if not l.startswith("#")]
    return links


# ============================================================
# UniversalAuditor
# ============================================================

class UniversalAuditor:
    """
    Auditor universal: funciona com QUALQUER domínio/host.
    Estratégia:
      - Tenta acessar / (raiz) → verificar se é listável
      - Procura arquivos sensíveis usando heurísticas
      - Testa HEAD/GET em arquivos suspeitos
      - Retorna JSON padronizado
    """

    COMMON_SENSITIVE_FILES = [
        "config.json",
        "config.yaml",
        "config.yml",
        "settings.json",
        "settings.py",
        "application.properties",
        "application.yml",
        ".env",
        "credentials",
        "secrets",
        "id_rsa",
        "id_rsa.pub",
        "private.key",
        "secret.key",
        "dump.sql",
        "db.sql",
        "backup.sql",
        "backup.zip",
        "archive.zip",
        "source.map",
        "main.js.map",
        "index.js.map",
    ]

    def __init__(self, target: str):
        self.original_input = target.strip()
        self.domain = normalize_target(target)
        self.base_url = f"https://{self.domain}"

        self.provider = "UNIVERSAL"
        self.region = "-"
        self.account_id = "-"

    # --------------------------------------------------------
    # SCAN PRINCIPAL
    # --------------------------------------------------------

    def _http_get(self, url: str) -> Optional[requests.Response]:
        try:
            return requests.get(url, timeout=10)
        except Exception:
            return None

    def _http_head(self, url: str) -> Optional[requests.Response]:
        try:
            return requests.head(url, timeout=10)
        except Exception:
            return None

    # --------------------------------------------------------
    # DETECTAR ARQUIVOS
    # --------------------------------------------------------

    def _discover_files(self) -> List[str]:
        """
        1) Tenta baixar a raiz do domínio:
            https://dominio/
        2) Procura links dentro do HTML
        3) Testa HEAD para arquivos sensíveis padrão
        """
        discovered = set()

        # Tenta baixar raiz
        resp = self._http_get(self.base_url)
        if resp and resp.status_code == 200:
            html = resp.text
            links = extract_links_from_html(html)
            for l in links:
                if not l.startswith("http"):
                    discovered.add(url_join(self.base_url, l))
                else:
                    discovered.add(l)

        # Testa arquivos sensíveis comuns
        for fname in self.COMMON_SENSITIVE_FILES:
            url = url_join(self.base_url, fname)
            resp = self._http_head(url)
            if resp and resp.status_code in (200, 403):  
                discovered.add(url)

        return list(discovered)

    # --------------------------------------------------------
    # ANALISAR ARQUIVOS
    # --------------------------------------------------------

    def _analyze_files(self, urls: List[str]) -> Dict[str, Any]:
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts = {}
        sensitive_counts = {"creds": 0, "backups": 0, "sourcemaps": 0, "configs": 0}
        files_out = []
        critical_findings = []

        for full_url in urls:
            filename = full_url.split("/")[-1] or full_url
            cat, risk = classify_file(filename)

            # Tenta obter tamanho mínimo (HEAD)
            size = 0
            head = self._http_head(full_url)
            if head and "Content-Length" in head.headers:
                try:
                    size = int(head.headers["Content-Length"])
                except:
                    size = 0

            risk_counts[risk] += 1
            category_counts[cat] = category_counts.get(cat, 0) + 1

            if cat == "credentials":
                sensitive_counts["creds"] += 1
            if cat == "backup":
                sensitive_counts["backups"] += 1
            if cat == "sourcemap":
                sensitive_counts["sourcemaps"] += 1
            if cat == "config":
                sensitive_counts["configs"] += 1

            entry = {
                "key": filename,
                "filename": filename,
                "url": full_url,
                "size": size,
                "size_formatted": human_size(size),
                "category": cat,
                "risk": risk,
            }
            files_out.append(entry)

            if risk in ("critical", "high"):
                critical_findings.append(entry)

        result = {
            "risk_counts": risk_counts,
            "category_counts": category_counts,
            "sensitive_categories": sensitive_counts,
            "files": files_out,
            "critical_findings": critical_findings,
            "total_files": len(files_out),
            "total_size_bytes": sum(f["size"] for f in files_out),
        }

        return result

    # --------------------------------------------------------
    # EXECUÇÃO PRINCIPAL
    # --------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        try:
            file_urls = self._discover_files()
            public_access = len(file_urls) > 0

            analysis = self._analyze_files(file_urls)
            score = calc_risk_score(analysis["risk_counts"])

            summary = {
                "bucket": self.domain,        # dashboard usa "bucket", mantemos padronizado
                "provider": "UNIVERSAL",
                "region": self.region,
                "account_id": self.account_id,
                "total_files": analysis["total_files"],
                "total_size_bytes": analysis["total_size_bytes"],
                "risk_score": score,
                "risk_counts": analysis["risk_counts"],
                "category_counts": analysis["category_counts"],
                "sensitive_categories": analysis["sensitive_categories"],
                "public_access": public_access,
                "policy_public": public_access,
                "acl_public": public_access,
                "versioning": False,
                "encryption": False,
            }

            report = {
                "bucket": self.domain,
                "provider": "UNIVERSAL",
                "region": self.region,
                "account_id": self.account_id,
                "summary": summary,
                "files": analysis["files"],
                "critical_findings": analysis["critical_findings"],
                "public_access": public_access,
            }

            self._save_report(report)
            return report

        except Exception as e:
            logger.exception(f"Erro ao auditar domínio {self.domain}: {e}")
            return {"error": str(e)}

    # --------------------------------------------------------
    # SALVAR RELATÓRIO
    # --------------------------------------------------------

    def _save_report(self, data: Dict[str, Any]):
        try:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            fname = f"{ts}_{self.domain}_UNIVERSAL.json"
            path = REPORTS_DIR / fname
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"Relatório Universal salvo em {path}")
        except Exception as e:
            logger.warning(f"Erro ao salvar relatório universal: {e}")
