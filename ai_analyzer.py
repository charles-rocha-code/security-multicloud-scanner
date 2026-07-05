"""
ai_analyzer.py — Análise de scans de segurança usando Claude (Anthropic).
Não usa RAG: o scan JSON é passado diretamente como contexto ao modelo.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import anthropic

MODEL   = "claude-sonnet-4-6"

# Prompt de sistema com referência explícita dos frameworks de compliance —
# não é preenchimento: o conteúdo abaixo é usado de verdade pelo modelo para
# mapear findings às categorias de controle certas, em vez de depender só do
# que foi aprendido em treino. Como bônus, ficou grande o suficiente (>1024
# tokens) para qualificar para prompt caching da Anthropic — como é idêntico
# em analyze()/compare()/ask(), o cache vale para as três chamadas.
SYSTEM = """Você é um especialista sênior em segurança cloud (CSPM) com profundo conhecimento em CIS Benchmarks, ISO 27001, NIST 800-53, AWS Well-Architected, GCP Security Foundations e Microsoft Cloud Security Benchmark (MCSB). Responda sempre em português. Seja técnico, direto e orientado a ação.

Use as referências abaixo para mapear findings às categorias de controle corretas.

## CIS AWS Foundations Benchmark
1. IAM — uso da conta root, MFA obrigatório, rotação de access keys, política de senha, credenciais não usadas há 90+ dias, suporte a hardware MFA para root.
2. Storage — S3 Block Public Access, criptografia em repouso, versionamento, logging de acesso ao bucket.
3. Logging — CloudTrail multi-região habilitado, validação de integridade do log, logging do próprio bucket do CloudTrail, VPC Flow Logs habilitados.
4. Monitoring — alarmes CloudWatch para uso da conta root, chamadas de API não autorizadas, login no console sem MFA, mudanças de policy IAM, mudanças no CloudTrail, mudanças em bucket policy do S3.
5. Networking — security group default restringindo todo tráfego, sem 0.0.0.0/0 liberado para portas 22/3389, VPC Flow Logging habilitado em todas as VPCs.

## ISO/IEC 27001:2022 — Anexo A (4 temas, 93 controles)
- Organizacionais (37): políticas de segurança da informação, papéis e responsabilidades, segregação de funções, inteligência de ameaças, controle de acesso, relacionamento com fornecedores, gestão de incidentes, continuidade de negócio, conformidade legal/regulatória.
- Pessoas (8): triagem/verificação de antecedentes, termos de contratação, conscientização e treinamento, processo disciplinar, trabalho remoto, acordos de confidencialidade.
- Físicos (14): perímetros de segurança física, controle de entrada, proteção contra ameaças ambientais, manutenção de equipamentos, descarte seguro de mídia.
- Tecnológicos (34): dispositivos endpoint, direitos de acesso privilegiado, restrição de acesso à informação, criptografia, desenvolvimento seguro, logging e monitoramento, segurança de rede, segurança de aplicação, prevenção de vazamento de dados.

## NIST 800-53 Rev. 5 — famílias de controle
AC (Controle de Acesso) · AT (Conscientização e Treinamento) · AU (Auditoria e Responsabilização) · CA (Avaliação e Autorização) · CM (Gestão de Configuração) · CP (Planejamento de Contingência) · IA (Identificação e Autenticação) · IR (Resposta a Incidentes) · MA (Manutenção) · MP (Proteção de Mídia) · PE (Proteção Física e Ambiental) · PL (Planejamento) · PM (Gestão de Programa) · PS (Segurança de Pessoal) · PT (Processamento de PII e Transparência) · RA (Avaliação de Risco) · SA (Aquisição de Sistemas e Serviços) · SC (Proteção de Sistemas e Comunicações) · SI (Integridade de Sistemas e Informação) · SR (Risco da Cadeia de Suprimentos).

## AWS Well-Architected Framework — 6 pilares
Excelência Operacional · Segurança · Confiabilidade · Eficiência de Performance · Otimização de Custos · Sustentabilidade.

## GCP Security Foundations Guide — áreas-chave
Hierarquia de organização/recursos · gestão de identidade · deployment de recursos · segurança de rede · controles detectivos · proteção contra exfiltração de dados · segurança de workload.

## Microsoft Cloud Security Benchmark (MCSB) — domínios de controle
Segurança de Rede · Gestão de Identidade · Acesso Privilegiado · Proteção de Dados · Gestão de Ativos · Logging e Detecção de Ameaças · Resposta a Incidentes · Postura e Gestão de Vulnerabilidades · Segurança de Endpoint · Backup e Recuperação · Segurança de DevOps · Governança e Estratégia."""


def _client() -> anthropic.Anthropic:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY não configurada no ambiente.")
    return anthropic.Anthropic(api_key=key)


def _cached_system() -> list[dict]:
    """System prompt como bloco cacheável — idêntico em analyze/compare/ask,
    então o cache (5 min, renovável a cada uso) vale nas três chamadas."""
    return [{"type": "text", "text": SYSTEM, "cache_control": {"type": "ephemeral"}}]


def _scan_summary(scan: dict) -> dict:
    """Extrai campos relevantes para reduzir tokens."""
    r = scan.get("result", scan)
    return {
        "provider":              r.get("provider", "?"),
        "target":                r.get("bucket") or r.get("target") or r.get("account_id", "?"),
        "timestamp":             scan.get("timestamp", r.get("generated_at", "?")),
        "total_findings":        len(r.get("files", [])),
        "severity_distribution": r.get("severity_distribution", {}),
        "risk_score":            r.get("risk_score", 0),
        "summary":               r.get("summary", {}),
        "top_findings":          r.get("files", [])[:15],
    }


def analyze(scan: dict) -> str:
    """
    Análise executiva do scan atual.
    Retorna texto Markdown com avaliação, prioridades e timeline.
    """
    summary  = _scan_summary(scan)
    provider = summary["provider"]
    total    = summary["total_findings"]
    sd       = summary["severity_distribution"]

    prompt = f"""Analise este resultado de scan de segurança cloud e forneça uma análise executiva completa.

**Provider:** {provider}
**Alvo:** {summary['target']}
**Total de findings:** {total}
**Severidade:** CRÍTICO={sd.get('critical',0)} | ALTO={sd.get('high',0)} | MÉDIO={sd.get('medium',0)} | BAIXO={sd.get('low',0)}
**Risk Score:** {summary['risk_score']}/100

**Summary do scan:**
{json.dumps(summary['summary'], indent=2, default=str, ensure_ascii=False)}

**Top findings:**
{json.dumps(summary['top_findings'], indent=2, default=str, ensure_ascii=False)}

---
Forneça:

## 1. Avaliação Executiva
(Estado geral da postura de segurança — 2 a 3 parágrafos)

## 2. Top 5 Ações Prioritárias
(Ordenadas por risco, com comandos específicos quando possível)

## 3. Timeline de Remediação
- **0–24 horas:** ações críticas
- **7 dias:** ações de alto risco
- **30 dias:** melhorias estruturais

## 4. Impacto em Conformidade
(CIS Benchmark, ISO 27001, NIST 800-53 — o que está sendo violado)
"""

    resp = _client().messages.create(
        model=MODEL,
        max_tokens=2500,
        system=_cached_system(),
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def compare(current: dict, history: list[dict]) -> str:
    """
    Compara o scan atual com scans anteriores.
    Identifica novos findings, findings remediados e tendência.
    """
    if not history:
        return "Sem histórico disponível para comparação. Realize mais scans ao longo do tempo."

    current_summary   = _scan_summary(current)
    history_summaries = [_scan_summary(h) for h in history]

    prompt = f"""Compare a postura de segurança entre o scan atual e os scans anteriores.

**SCAN ATUAL ({current_summary['timestamp']}):**
{json.dumps(current_summary, indent=2, default=str, ensure_ascii=False)}

**HISTÓRICO ({len(history_summaries)} scan(s) anterior(es)):**
{json.dumps(history_summaries, indent=2, default=str, ensure_ascii=False)}

---
Forneça:

## 1. Evolução da Postura
(Melhorou, piorou ou estável? Com números concretos)

## 2. Novos Findings
(Findings que apareceram no scan atual e não existiam antes)

## 3. Findings Remediados
(Findings que existiam antes e não aparecem mais — positivo!)

## 4. Tendência
(Se continuar assim, qual o risco estimado em 30 dias?)

## 5. Próximos Passos
(Ações baseadas na tendência observada)
"""

    resp = _client().messages.create(
        model=MODEL,
        max_tokens=2000,
        system=_cached_system(),
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def ask(question: str, scan: dict, history: Optional[list[dict]] = None) -> str:
    """
    Responde uma pergunta livre sobre o scan e/ou histórico.
    Ex: 'Qual finding é mais urgente?' ou 'Quais usuários estão sem MFA?'
    """
    current_summary = _scan_summary(scan)

    context = f"**Scan atual:**\n{json.dumps(current_summary, indent=2, default=str, ensure_ascii=False)}"

    if history:
        hist_summaries = [_scan_summary(h) for h in history[:3]]
        context += f"\n\n**Histórico ({len(hist_summaries)} scan(s)):**\n{json.dumps(hist_summaries, indent=2, default=str, ensure_ascii=False)}"

    # RAG: busca scans historicamente relevantes PRA ESSA pergunta específica —
    # diferente do histórico acima, que só traz os N mais recentes, não os mais
    # relevantes. Nunca quebra a resposta: falha aqui só omite a seção.
    try:
        import rag
        hits = rag.retrieve(question, k=3, category="scan")
        if hits:
            rag_text = "\n".join(f"- {h['text']}" for h in hits)
            context += f"\n\n**Scans relacionados encontrados por busca semântica:**\n{rag_text}"
    except Exception as e:
        print(f"⚠️ ai_analyzer.ask RAG error: {e}")

    prompt = f"""{context}

---
**Pergunta:** {question}"""

    resp = _client().messages.create(
        model=MODEL,
        max_tokens=1500,
        system=_cached_system(),
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text
