"""
logging_setup.py - Logging estruturado (JSON) com correlação por request_id.

Antes, a aplicação usava print() com prefixos de emoji (✅/⚠️/❌) para sinalizar
nível -- sem estrutura, sem como correlacionar linhas de uma mesma requisição
no CloudWatch Logs Insights. Aqui cada linha vira um objeto JSON com nível,
logger, mensagem e o request_id da requisição que a gerou (via contextvar,
setado pelo middleware em api_with_mfa.py).
"""

import json
import logging
import sys
import uuid
from contextvars import ContextVar

_request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def set_request_id(value: str) -> None:
    _request_id_ctx.set(value)


def get_request_id() -> str:
    return _request_id_ctx.get()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": _request_id_ctx.get(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    app_logger = logging.getLogger("scanner")
    app_logger.handlers = [handler]
    app_logger.setLevel(level)
    app_logger.propagate = False


def get_logger(name: str = "scanner") -> logging.Logger:
    return logging.getLogger(f"scanner.{name}" if name != "scanner" else "scanner")
