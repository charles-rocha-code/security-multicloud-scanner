# api.py
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Optional, Dict, Any

from auditor import S3Auditor
from auditor_gcs import GCSAuditor
from auditor_azure import AzureBlobAuditor

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
            "scan_authenticated": "/scan/authenticated"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
