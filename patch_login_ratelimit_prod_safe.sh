#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$APP_DIR/venv"
TARGET_FILE="$APP_DIR/api_with_mfa.py"

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${TARGET_FILE}.bak.${TS}"
TMP_FILE="${TARGET_FILE}.tmp.${TS}"

echo "========================================"
echo " Patch seguro de rate limit no login real"
echo " Diretório base: $APP_DIR"
echo " Arquivo: $TARGET_FILE"
echo "========================================"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[ERRO] Virtualenv não encontrado: $VENV_DIR"
  exit 1
fi

source "$VENV_DIR/bin/activate"

echo "[1/8] Validando ambiente..."
which python
which pip

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "[ERRO] Arquivo não encontrado: $TARGET_FILE"
  exit 1
fi

echo "[2/8] Validando sintaxe atual..."
python -m py_compile "$TARGET_FILE"

echo "[3/8] Criando backup..."
cp "$TARGET_FILE" "$BACKUP_FILE"
echo "[OK] Backup: $BACKUP_FILE"

restore_backup() {
  echo "[ROLLBACK] Restaurando arquivo original..."
  cp "$BACKUP_FILE" "$TARGET_FILE"
}

trap 'echo "[ERRO] Falha detectada."; restore_backup' ERR

echo "[4/8] Aplicando patch..."
python - "$TARGET_FILE" "$TMP_FILE" <<'PY'
import re
import sys
from pathlib import Path

src_path = Path(sys.argv[1])
tmp_path = Path(sys.argv[2])

text = src_path.read_text(encoding="utf-8")

def ensure_import(line: str, text: str) -> str:
    if line in text:
        return text
    lines = text.splitlines()
    insert_at = 0
    for i, ln in enumerate(lines[:180]):
        if ln.startswith("import ") or ln.startswith("from "):
            insert_at = i + 1
    if insert_at == 0:
        lines.insert(0, line)
    else:
        lines.insert(insert_at, line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")

imports = [
    "from slowapi import Limiter",
    "from slowapi.middleware import SlowAPIMiddleware",
    "from slowapi.errors import RateLimitExceeded",
    "from fastapi.responses import JSONResponse",
]
for imp in imports:
    text = ensure_import(imp, text)

fastapi_import_match = re.search(r"^from fastapi import ([^\n]+)$", text, flags=re.M)
if fastapi_import_match:
    imported = [x.strip() for x in fastapi_import_match.group(1).split(",")]
    if "Request" not in imported:
        imported.append("Request")
        new_line = "from fastapi import " + ", ".join(dict.fromkeys(imported))
        text = re.sub(r"^from fastapi import ([^\n]+)$", new_line, text, count=1, flags=re.M)
else:
    text = ensure_import("from fastapi import Request", text)

if "def get_client_ip(request: Request) -> str:" not in text:
    helper = '''

def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
'''
    m = re.search(r"^app\s*=\s*FastAPI\s*(?:\([^\n]*\))?\s*$", text, flags=re.M)
    if not m:
        raise SystemExit("Não encontrei 'app = FastAPI(...)' de forma segura. Abortando.")
    text = text[:m.start()] + helper + "\n" + text[m.start():]

if "Limiter(key_func=get_client_ip)" not in text:
    pattern = r"^(app\s*=\s*FastAPI\s*(?:\([^\n]*\))?\s*)$"
    repl = (
        r"\1\n"
        "limiter = Limiter(key_func=get_client_ip)\n"
        "app.state.limiter = limiter\n"
        "app.add_middleware(SlowAPIMiddleware)"
    )
    text, count = re.subn(pattern, repl, text, count=1, flags=re.M)
    if count == 0:
        raise SystemExit("Não consegui inserir configuração do limiter com segurança. Abortando.")

if "@app.exception_handler(RateLimitExceeded)" not in text:
    handler = '''

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Try again later."}
    )
'''
    text += handler

auth_login_pattern = re.compile(
    r'(^[ \t]*@app\.post\(\s*[\'"]/auth/login[\'"]\s*\)\n)'
    r'(?P<defline>^[ \t]*(?:async[ \t]+)?def[ \t]+auth_login[ \t]*\((?P<sig>.*?)\)\s*:)',
    flags=re.M | re.S
)

m = auth_login_pattern.search(text)
if not m:
    raise SystemExit("Endpoint '@app.post(\"/auth/login\")' não encontrado de forma segura. Abortando.")

defline = m.group("defline")
sig = m.group("sig").strip()

if "request: Request" not in sig and "request : Request" not in sig:
    new_sig = f"request: Request, {sig}" if sig else "request: Request"
    new_defline = defline.replace(f"({sig})", f"({new_sig})", 1)
    text = text[:m.start("defline")] + new_defline + text[m.end("defline"):]

auth_block_pattern = re.compile(
    r'(?P<decorators>(?:^[ \t]*@.*\n)*)'
    r'^[ \t]*@app\.post\(\s*[\'"]/auth/login[\'"]\s*\)\n'
    r'(?P<func>^[ \t]*(?:async[ \t]+)?def[ \t]+auth_login[ \t]*\((?P<sig>.*?)\)\s*:)',
    flags=re.M | re.S
)

m = auth_block_pattern.search(text)
if not m:
    raise SystemExit("Bloco do endpoint '/auth/login' não encontrado após ajuste. Abortando.")

decorators = m.group("decorators") or ""
func = m.group("func")

to_add = []
if '@limiter.limit("10/hour")' not in decorators and "@limiter.limit('10/hour')" not in decorators:
    to_add.append('@limiter.limit("10/hour")')
if '@limiter.limit("3/minute")' not in decorators and "@limiter.limit('3/minute')" not in decorators:
    to_add.append('@limiter.limit("3/minute")')

replacement = decorators
if to_add:
    replacement += "\n".join(to_add) + "\n"
replacement += '@app.post("/auth/login")\n' + func

text = text[:m.start()] + replacement + text[m.end():]

required = [
    "from slowapi import Limiter",
    "from slowapi.middleware import SlowAPIMiddleware",
    "from slowapi.errors import RateLimitExceeded",
    "from fastapi.responses import JSONResponse",
    "def get_client_ip(request: Request) -> str:",
    "limiter = Limiter(key_func=get_client_ip)",
    "@app.exception_handler(RateLimitExceeded)",
    '@limiter.limit("10/hour")',
    '@limiter.limit("3/minute")',
    '@app.post("/auth/login")',
]
for item in required:
    if item not in text:
        raise SystemExit(f"Falha de validação interna: {item}")

tmp_path.write_text(text, encoding="utf-8")
print("Patch aplicado em arquivo temporário com sucesso.")
PY

echo "[5/8] Validando sintaxe do patched..."
python -m py_compile "$TMP_FILE"

echo "[6/8] Substituindo arquivo original..."
mv "$TMP_FILE" "$TARGET_FILE"

echo "[7/8] Validando sintaxe final..."
python -m py_compile "$TARGET_FILE"

echo "[8/8] Mostrando linhas alteradas..."
grep -n 'limiter.limit\|auth/login\|get_client_ip\|RateLimitExceeded\|def auth_login' "$TARGET_FILE" || true

trap - ERR

echo "========================================"
echo " Patch finalizado com sucesso"
echo "========================================"
