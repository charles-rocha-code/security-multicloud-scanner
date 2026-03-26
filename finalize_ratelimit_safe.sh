#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
FILE="$APP_DIR/api_with_mfa.py"
BACKUP="$FILE.bak.prod.$(date +%Y%m%d_%H%M%S)"

echo "========================================"
echo " Finalizando rate limit para produção"
echo "========================================"

[[ -f "$FILE" ]] || { echo "[ERRO] Arquivo não encontrado: $FILE"; exit 1; }

cp "$FILE" "$BACKUP"
echo "[OK] Backup: $BACKUP"

python - "$FILE" <<'PY'
from pathlib import Path
import re
import sys

p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8")

# 1) Remove rota temporária /ratelimit-test
text = re.sub(
    r'\n@app\.get\("/ratelimit-test"\)\n@limiter\.limit\("3/minute"\)\ndef ratelimit_test\(request: Request\):\n    return \{"ok": True\}\n?',
    '\n',
    text,
    flags=re.M
)

# 2) Corrige bloco do /auth/login para produção
text = re.sub(
    r'@app\.post\("/auth/login"\)\n(?:@limiter\.limit\([^\n]+\)\n)+',
    '@app.post("/auth/login")\n@limiter.limit("10/hour")\n@limiter.limit("3/minute")\n',
    text,
    count=1,
    flags=re.M
)

# 3) Garante limite no /login logo abaixo do decorator
text = re.sub(
    r'@app\.get\("/login", response_class=HTMLResponse, include_in_schema=False\)\n(?!@limiter\.limit\("30/minute"\))',
    '@app.get("/login", response_class=HTMLResponse, include_in_schema=False)\n@limiter.limit("30/minute")\n',
    text,
    count=1,
    flags=re.M
)

p.write_text(text, encoding="utf-8")
print("Patch final aplicado.")
PY

python -m py_compile "$FILE"
echo "[OK] Sintaxe validada"

echo
echo "[INFO] Verificação:"
grep -n 'ratelimit-test\|@app.post("/auth/login")\|@app.get("/login"\|@limiter.limit' "$FILE" || true

echo
echo "========================================"
echo " Finalização concluída"
echo "========================================"
