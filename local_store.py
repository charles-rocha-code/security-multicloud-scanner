"""
local_store.py — Persistência local em JSON usada por auth_mfa.py e
scan_history.py quando STORAGE_BACKEND=local (padrão para desenvolvimento
sem AWS). Mesmo papel que DynamoDB/S3 cumprem em STORAGE_BACKEND=aws, sem
depender de nenhum serviço externo.

fcntl.flock evita corrupção quando o uvicorn atende requisições concorrentes
(múltiplas threads/workers escrevendo o mesmo arquivo).
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.environ.get("LOCAL_DATA_DIR", Path(__file__).resolve().parent / "local_data"))


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with open(path, "r", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            f.truncate()
            json.dump(data, f, indent=2, default=str)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
