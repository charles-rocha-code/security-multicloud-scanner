"""
graph_model.py — Schema comum de grafo (nós e arestas) para modelar RELAÇÕES
entre recursos multi-cloud, não só achados isolados. Fase 0 do roadmap de
Mapa de Grafo de Ataque.

Aditivo, não substitui nada: cada auditor continua emitindo findings normais
(retrocompatibilidade total) e passa a também emitir nós/arestas quando a
relação já é conhecida pelo próprio check — ex: auditor_iam.py já lê a trust
policy de cada role hoje só para gerar 1 finding isolado ("Principal=*");
aqui essa mesma leitura também vira uma aresta "quem pode assumir o quê".

- Nó: um recurso (role, usuário, bucket, etc.) — `exposed` marca ponto de
  entrada possível (ex: acessível pela internet); `high_value` marca alvo
  de interesse (ex: acesso administrativo).
- Aresta: uma relação direcionada entre dois nós (ex: "role X pode ser
  assumida por usuário Y").

Fase 1 (motor de grafo, networkx) consome esse formato depois — este módulo
só coleta e serializa, não faz busca de caminho.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class GraphNode:
    id: str
    type: str
    provider: str
    label: str
    exposed: bool = False
    high_value: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "provider": self.provider,
            "label": self.label,
            "exposed": self.exposed,
            "high_value": self.high_value,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "metadata": self.metadata,
        }


class GraphCollector:
    """Mixin: qualquer auditor herda isto pra acumular nós/arestas junto dos
    findings, sem precisar reimplementar deduplicação de nó em cada um."""

    def __init__(self) -> None:
        self._graph_nodes: List[GraphNode] = []
        self._graph_edges: List[GraphEdge] = []
        self._seen_node_ids: Set[str] = set()

    def add_node(self, node: GraphNode) -> None:
        """Idempotente — adicionar o mesmo id duas vezes não duplica."""
        if node.id in self._seen_node_ids:
            return
        self._seen_node_ids.add(node.id)
        self._graph_nodes.append(node)

    def mark_high_value(self, node_id: str) -> None:
        """Promove um nó já adicionado a alvo de alto valor (ex: ganhou
        AdministratorAccess depois de já ter sido criado como nó comum)."""
        for n in self._graph_nodes:
            if n.id == node_id:
                n.high_value = True
                return

    def add_edge(self, edge: GraphEdge) -> None:
        self._graph_edges.append(edge)

    def graph_output(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self._graph_nodes],
            "edges": [e.to_dict() for e in self._graph_edges],
        }
