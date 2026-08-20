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
from typing import Any, Callable, Tuple

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


def update_json(path: Path, mutate: Callable[[Any], Tuple[Any, Any]]) -> Any:
    """Lê, aplica `mutate(data) -> (novo_data, resultado)` e escreve -- tudo
    sob uma única lock exclusiva. read_json()+write_json() em duas chamadas
    separadas deixa uma janela entre a leitura e a escrita onde outra
    requisição pode escrever no meio, perdendo a atualização de uma das
    duas (ex.: logout de um token e criação de outra sessão em paralelo).
    Usar sempre que a operação for "ler o estado atual, decidir o que fazer,
    escrever" -- não só "sobrescrever com um valor novo conhecido"."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            raw = f.read()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                data = {}
            new_data, result = mutate(data)
            f.seek(0)
            f.truncate()
            json.dump(new_data, f, indent=2, default=str)
            return result
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
