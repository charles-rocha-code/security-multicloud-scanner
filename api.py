# api.py
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Optional, Dict, Any

from auditor import S3Auditor
from auditor_gcs import GCSAuditor
from auditor_azure import AzureBlobAuditor

# Import para geração de relatórios
try:
    from generate_report import generate_executive_report
    REPORTS_AVAILABLE = True
    print("✅ generate_report.py carregado com sucesso!")
except ImportError as e:
    REPORTS_AVAILABLE = False
    print(f"⚠️  generate_report.py não encontrado: {e}")

app = FastAPI(
    title="Security Multicloud Storage API",
    description="Auditoria avançada de buckets AWS S3, Google Cloud Storage e Azure Blob Storage",
    version="2.0.0"
)

# ============================================================
# Paths
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
DASHBOARD_FILE = TEMPLATES_DIR / "dashboard.html"

# ============================================================
# MODELS
# ============================================================
class AuthenticatedScanRequest(BaseModel):
    bucket: str
    max_objects: int = 1000
    # AWS S3
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    region: Optional[str] = None
    # GCS
    service_account_key: Optional[Dict[str, Any]] = None
    # Azure
    azure_connection_string: Optional[str] = None
    azure_sas_token: Optional[str] = None
    azure_account_key: Optional[str] = None
    azure_container: Optional[str] = None

class ReportRequest(BaseModel):
    """Model para requisição de relatório executivo"""
    scan_data: Dict[str, Any]
    client_name: Optional[str] = None
    client_contact: Optional[str] = None
    output_format: str = 'both'  # 'pdf', 'docx', ou 'both'

# ============================================================
# HEALTH CHECK
# ============================================================
@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0", "providers": ["AWS_S3", "GCS", "AZURE_BLOB"]}

# ============================================================
# DASHBOARD (HTML)
# ============================================================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    if not DASHBOARD_FILE.exists():
        return HTMLResponse(
            content="<h2>dashboard.html não encontrado em /templates</h2>",
            status_code=404
        )

    return HTMLResponse(
        content=DASHBOARD_FILE.read_text(encoding="utf-8")
    )

# ============================================================
# SCAN PÚBLICO (sem credenciais)
# ============================================================
@app.get("/scan/{bucket}")
def scan_bucket(bucket: str):
    """
    Detecta automaticamente o provider:
    - Azure Blob Storage: blob.core.windows.net
    - Google Cloud Storage: storage.googleapis.com
    - AWS S3 (default): todos os outros
    
    Executa auditoria pública (sem credenciais)
    Retorna payload completo para o dashboard
    """
    bucket_lower = bucket.lower()

    try:
        # ----------------------------------------------------
        # Detecta AZURE BLOB STORAGE
        # ----------------------------------------------------
        if "blob.core.windows.net" in bucket_lower:
            print(f"[AZURE] Detected Azure Blob Storage: {bucket}")
            auditor = AzureBlobAuditor(bucket, max_objects=200)
            result = auditor.run()
            return JSONResponse(content=result)

        # ----------------------------------------------------
        # Detecta GCS
        # ----------------------------------------------------
        elif (
            "storage.googleapis.com" in bucket_lower
            or bucket_lower.endswith(".storage.googleapis.com")
        ):
            print(f"[GCS] Detected Google Cloud Storage: {bucket}")
            auditor = GCSAuditor(bucket, max_objects=200)
            result = auditor.run()
            return JSONResponse(content=result)

        # ----------------------------------------------------
        # Default: AWS S3
        # ----------------------------------------------------
        else:
            print(f"[S3] Detected AWS S3: {bucket}")
            auditor = S3Auditor(bucket, max_objects=200)
            result = auditor.run()
            return JSONResponse(content=result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao executar scan: {str(e)}"
        )

# ============================================================
# SCAN AUTENTICADO (com credenciais)
# ============================================================
@app.post("/scan/authenticated")
def scan_authenticated(req: AuthenticatedScanRequest):
    """
    Scan autenticado com credenciais
    
    Providers:
    - Azure: connection_string, sas_token ou account_key
    - GCS: service_account_key (JSON)
    - S3: aws_access_key_id + aws_secret_access_key
    """
    bucket = req.bucket
    bucket_lower = bucket.lower()
    
    try:
        # ----------------------------------------------------
        # AZURE BLOB STORAGE AUTENTICADO
        # ----------------------------------------------------
        if "blob.core.windows.net" in bucket_lower or req.azure_connection_string or req.azure_sas_token or req.azure_account_key:
            print(f"[AZURE AUTH] Authenticated scan: {bucket}")
            
            try:
                from auditor_azure_authenticated import AzureBlobAuthenticatedAuditor
                
                auditor = AzureBlobAuthenticatedAuditor(
                    account_or_url=bucket,
                    container=req.azure_container,
                    connection_string=req.azure_connection_string,
                    sas_token=req.azure_sas_token,
                    account_key=req.azure_account_key,
                    max_objects=req.max_objects
                )
                result = auditor.run()
                return JSONResponse(content=result)
            
            except ImportError as e:
                print(f"Warning: Azure authenticated auditor not available: {e}")
                print("Falling back to public scan")
                auditor = AzureBlobAuditor(bucket, container=req.azure_container, max_objects=req.max_objects)
                result = auditor.run()
                return JSONResponse(content=result)
        
        # ----------------------------------------------------
        # GCS AUTENTICADO
        # ----------------------------------------------------
        elif "storage.googleapis.com" in bucket_lower or req.service_account_key:
            print(f"[GCS AUTH] Authenticated scan: {bucket}")
            
            from auditor_gcs_authenticated import GCSAuthenticatedAuditor
            
            auditor = GCSAuthenticatedAuditor(
                bucket_name=bucket,
                service_account_key=req.service_account_key,
                max_objects=req.max_objects
            )
            result = auditor.run()
            return JSONResponse(content=result)
        
        # ----------------------------------------------------
        # AWS S3 AUTENTICADO (default)
        # ----------------------------------------------------
        else:
            print(f"[S3 AUTH] Authenticated scan: {bucket}")
            
            from auditor_s3_authenticated import S3AuthenticatedAuditor
            
            auditor = S3AuthenticatedAuditor(
                bucket_name=bucket,
                aws_access_key_id=req.aws_access_key_id,
                aws_secret_access_key=req.aws_secret_access_key,
                aws_session_token=req.aws_session_token,
                region_name=req.region,
                max_objects=req.max_objects
            )
            result = auditor.run()
            return JSONResponse(content=result)
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao executar scan autenticado: {str(e)}"
        )

# ============================================================
# RELATÓRIOS EXECUTIVOS
# ============================================================
@app.post("/generate-report")
def generate_report_endpoint(req: ReportRequest):
    """
    Gera relatório executivo em PDF e/ou DOCX
    
    Body:
    {
        "scan_data": {...},
        "client_name": "Empresa XYZ",
        "client_contact": "contato@empresa.com",
        "output_format": "both"
    }
    """
    if not REPORTS_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Gerador de relatórios não disponível. Instale: pip install reportlab python-docx"
        )
    
    try:
        client_info = {
            'name': req.client_name or 'Cliente não informado',
            'contact': req.client_contact or 'Não informado'
        }
        
        print(f"📊 Gerando relatório para: {client_info['name']}")
        
        results = generate_executive_report(
            scan_data=req.scan_data,
            client_info=client_info,
            output_format=req.output_format
        )
        
        if not results:
            raise HTTPException(status_code=500, detail="Erro ao gerar relatórios")
        
        print(f"✅ Relatórios gerados: {results}")
        
        return {
            "success": True,
            "files": results,
            "message": "Relatórios gerados com sucesso"
        }
        
    except Exception as e:
        print(f"❌ Erro ao gerar relatório: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro: {str(e)}")


@app.get("/download-report/{filename}")
def download_report(filename: str):
    """
    Download de relatório gerado
    
    Exemplo: GET /download-report/relatorio_growbiz_2024-12-22.pdf
    """
    try:
        report_path = Path("./reports_executive") / filename
        
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Relatório não encontrado")
        
        # Detectar tipo de arquivo
        if filename.endswith('.pdf'):
            media_type = 'application/pdf'
        elif filename.endswith('.docx'):
            media_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        else:
            media_type = 'application/octet-stream'
        
        return FileResponse(
            path=str(report_path),
            filename=filename,
            media_type=media_type
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Erro ao baixar relatório: {e}")
        raise HTTPException(status_code=500, detail=f"Erro: {str(e)}")


@app.get("/reports/list")
def list_reports():
    """
    Lista todos os relatórios gerados
    """
    try:
        reports_dir = Path("./reports_executive")
        reports_dir.mkdir(exist_ok=True)
        
        reports = []
        for file_path in reports_dir.glob("relatorio_*"):
            reports.append({
                "filename": file_path.name,
                "size": file_path.stat().st_size,
                "created": file_path.stat().st_mtime,
                "url": f"/download-report/{file_path.name}"
            })
        
        reports.sort(key=lambda x: x['created'], reverse=True)
        
        return {
            "success": True,
            "count": len(reports),
            "reports": reports
        }
        
    except Exception as e:
        print(f"❌ Erro ao listar relatórios: {e}")
        raise HTTPException(status_code=500, detail=f"Erro: {str(e)}")

# ============================================================
# INFO
# ============================================================
@app.get("/")
def root():
    return {
        "service": "Security Multicloud Storage API",
        "version": "2.0.0",
        "providers": [
            {
                "name": "AWS S3",
                "scan_types": ["public", "authenticated"],
                "example": "my-bucket.s3.amazonaws.com"
            },
            {
                "name": "Google Cloud Storage",
                "scan_types": ["public", "authenticated"],
                "example": "my-bucket.storage.googleapis.com"
            },
            {
                "name": "Azure Blob Storage",
                "scan_types": ["public", "authenticated"],
                "example": "gododev.blob.core.windows.net"
            }
        ],
        "endpoints": {
            "health": "/health",
            "dashboard": "/dashboard",
            "scan_public": "/scan/{bucket}",
            "scan_authenticated": "/scan/authenticated",
            "generate_report": "/generate-report",
            "download_report": "/download-report/{filename}",
            "list_reports": "/reports/list"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
