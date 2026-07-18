"""
graph_engine.py — Motor de grafo em memória (Fase 1 do roadmap de Mapa de
Grafo de Ataque). Consome o formato de nós/arestas emitido por
graph_output() (ver graph_model.py) e usa networkx pra achar caminhos de
ataque: de um nó exposto (entrada) até um nó de alto valor (alvo).

Decisão: networkx em memória, não um banco de grafo dedicado (Neo4j/Neptune)
-- mesmo raciocínio já usado em rag.py deste projeto (sem OpenSearch
Serverless): o volume de nós de uma auditoria de conta não justifica o
custo/operação de manter um banco especializado no ar. Revisitar só se isso
virar gargalo real de performance.
"""
from __future__ import annotations

from typing import Any, Dict, List

import networkx as nx


def build_graph(graph_data: Dict[str, Any]) -> nx.DiGraph:
    """Monta um grafo direcionado a partir do formato {nodes, edges} de
    graph_output() — guarda os atributos de cada nó (exposed, high_value,
    etc.) pra uso na busca de caminho."""
    g = nx.DiGraph()
    for node in graph_data.get("nodes", []):
        g.add_node(node["id"], **node)
    for edge in graph_data.get("edges", []):
        g.add_edge(edge["source"], edge["target"], relation=edge["relation"], metadata=edge.get("metadata", {}))
    return g


def find_attack_paths(graph_data: Dict[str, Any], max_paths: int = 20, max_length: int = 6) -> List[Dict[str, Any]]:
    """Acha caminhos de qualquer nó exposto (entrada) até qualquer nó de
    alto valor (alvo). Todo caminho completo encontrado é CRITICAL por
    definição — independente da severidade de cada elo isolado no meio do
    caminho — é exatamente esse encadeamento que o relatório de findings
    soltos não mostra."""
    g = build_graph(graph_data)

    entry_nodes = [n for n, d in g.nodes(data=True) if d.get("exposed")]
    target_nodes = [n for n, d in g.nodes(data=True) if d.get("high_value")]

    paths: List[Dict[str, Any]] = []
    for entry in entry_nodes:
        for target in target_nodes:
            if entry == target:
                continue
            try:
                for raw_path in nx.all_simple_paths(g, source=entry, target=target, cutoff=max_length):
                    path_nodes = [dict(g.nodes[n]) for n in raw_path]
                    path_edges = [
                        {
                            "source": raw_path[i],
                            "target": raw_path[i + 1],
                            "relation": g.edges[raw_path[i], raw_path[i + 1]]["relation"],
                        }
                        for i in range(len(raw_path) - 1)
                    ]
                    paths.append({
                        "entry": entry,
                        "target": target,
                        "length": len(raw_path),
                        "severity": "CRITICAL",
                        "nodes": path_nodes,
                        "edges": path_edges,
                    })
                    if len(paths) >= max_paths:
                        return paths
            except nx.NodeNotFound:
                continue
    return paths


def graph_summary(graph_data: Dict[str, Any]) -> Dict[str, Any]:
    """Estatísticas rápidas do grafo — útil pra API/dashboard mostrar
    contexto mesmo quando não há caminho de ataque completo encontrado
    (ex: conta sem trust policy aberta, mas ainda com nós de alto valor
    mapeados)."""
    g = build_graph(graph_data)
    return {
        "total_nodes": g.number_of_nodes(),
        "total_edges": g.number_of_edges(),
        "exposed_nodes": sum(1 for _, d in g.nodes(data=True) if d.get("exposed")),
        "high_value_nodes": sum(1 for _, d in g.nodes(data=True) if d.get("high_value")),
    }
