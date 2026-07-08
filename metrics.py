"""
metrics.py - Métricas customizadas da aplicação no CloudWatch.

Antes, só existia métrica de infraestrutura (CPU, memória, disco) -- nada
sobre o comportamento real da aplicação: quanto tempo cada tipo de
varredura leva, taxa de falha, latência de chamada ao Bedrock/Claude.

Não requer nenhuma permissão IAM nova -- cloudwatch:PutMetricData já vem
da CloudWatchAgentServerPolicy anexada à role da instância.
"""

import os
import time
from contextlib import contextmanager
from typing import Optional

import boto3

from logging_setup import get_logger

logger = get_logger("metrics")

NAMESPACE = "SecurityScanner/App"
_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")
_cw = boto3.client("cloudwatch", region_name=_REGION)


def put_metric(name: str, value: float, unit: str = "Count", dimensions: Optional[dict] = None) -> None:
    try:
        _cw.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=[{
                "MetricName": name,
                "Value": value,
                "Unit": unit,
                "Dimensions": [{"Name": k, "Value": str(v)} for k, v in (dimensions or {}).items()],
            }],
        )
    except Exception as e:
        # Métrica nunca deve derrubar a requisição -- só registra e segue
        logger.warning(f"⚠️ put_metric_data error ({name}): {e}")


@contextmanager
def timed_metric(name: str, dimensions: Optional[dict] = None):
    """Publica a duração (ms) do bloco `with` como métrica ao final,
    independentemente de sucesso ou exceção."""
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed_ms = (time.monotonic() - start) * 1000
        put_metric(name, elapsed_ms, unit="Milliseconds", dimensions=dimensions)
