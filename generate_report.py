"""
generate_report_NBR10719.py - Gerador de Relatórios Técnicos NBR 10719
Relatório técnico-científico seguindo normas ABNT NBR 10719
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, 
    PageBreak, KeepTogether, Image, TableOfContents
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from datetime import datetime
from pathlib import Path
import locale

# Configurar locale para português
try:
    locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_TIME, 'Portuguese_Brazil.1252')
    except:
        pass

# Para DOCX
try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import RGBColor, Pt, Cm
    from docx.oxml.ns import qn
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


class NBR10719ReportGenerator:
    """
    Gerador de Relatórios Técnicos conforme NBR 10719
    
    Estrutura conforme ABNT:
    - Capa
    - Folha de rosto
    - Resumo
    - Lista de tabelas
    - Sumário
    - 1. Introdução
    - 2. Metodologia
    - 3. Resultados e Análise
    - 4. Conclusões e Recomendações
    - Referências
    - Anexos
    """
    
    def __init__(self, scan_data: dict, client_info: dict = None):
        self.scan_data = scan_data
        self.client_info = client_info or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_date = datetime.now()
        
        # Criar diretório de saída
        self.output_dir = Path("./reports_executive")
        self.output_dir.mkdir(exist_ok=True)
        
        # Análise
        self.vulnerabilities = self._analyze_vulnerabilities()
        self.recommendations = self._generate_recommendations()
        self.risk_assessment = self._assess_risk()
        
        # Numeração de tabelas e figuras
        self.table_counter = 0
        self.figure_counter = 0
    
    def _analyze_vulnerabilities(self) -> dict:
        """Analisa vulnerabilidades encontradas"""
        files = self.scan_data.get('files', [])
        severity_dist = self.scan_data.get('severity_distribution', {})
        
        categories = {
            'credentials': {'name': 'Credenciais e Autenticação', 'items': []},
            'databases': {'name': 'Bancos de Dados', 'items': []},
            'config': {'name': 'Arquivos de Configuração', 'items': []},
            'backups': {'name': 'Backups e Arquivos Compactados', 'items': []},
            'keys': {'name': 'Chaves Criptográficas', 'items': []},
            'pii': {'name': 'Dados Pessoais (PII/LGPD)', 'items': []}
        }
        
        for file in files:
            key = file.get('key', '').lower()
            severity = file.get('severity', 'LOW')
            
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                item = {
                    'file': file.get('key'),
                    'size': file.get('size', 0),
                    'severity': severity,
                    'reason': file.get('reason', ''),
                    'last_modified': file.get('last_modified', 'N/A')
                }
                
                if any(x in key for x in ['password', 'credential', 'secret', 'token', 'api_key']):
                    categories['credentials']['items'].append(item)
                elif any(x in key for x in ['.sql', '.db', '.sqlite', 'database', 'dump']):
                    categories['databases']['items'].append(item)
                elif any(x in key for x in ['.env', 'config', '.ini', '.yaml', '.yml']):
                    categories['config']['items'].append(item)
                elif any(x in key for x in ['backup', '.bak', '.zip', '.tar', '.gz']):
                    categories['backups']['items'].append(item)
                elif any(x in key for x in ['.pem', '.key', '.crt', '.cer', 'private']):
                    categories['keys']['items'].append(item)
                elif any(x in key for x in ['cpf', 'rg', 'passport', 'personal', 'customer']):
                    categories['pii']['items'].append(item)
        
        return {
            'categories': categories,
            'total_critical': severity_dist.get('critical', 0),
            'total_high': severity_dist.get('high', 0),
            'total_medium': severity_dist.get('medium', 0),
            'total_low': severity_dist.get('low', 0)
        }
    
    def _assess_risk(self) -> dict:
        """Avalia nível de risco segundo metodologia"""
        severity_dist = self.scan_data.get('severity_distribution', {})
        risk_score = self.scan_data.get('risk_score', 0)
        
        critical = severity_dist.get('critical', 0)
        high = severity_dist.get('high', 0)
        
        if critical > 0:
            level = "CRÍTICO"
            description = "Risco iminente de comprometimento"
        elif high > 5:
            level = "ALTO"
            description = "Risco elevado de incidente de segurança"
        elif high > 0:
            level = "MÉDIO"
            description = "Risco moderado com necessidade de ação"
        else:
            level = "BAIXO"
            description = "Risco controlado, monitoramento recomendado"
        
        return {
            'level': level,
            'score': risk_score,
            'description': description,
            'critical_count': critical,
            'high_count': high
        }
    
    def _generate_recommendations(self) -> list:
        """Gera recomendações técnicas"""
        recommendations = []
        severity_dist = self.scan_data.get('severity_distribution', {})
        
        critical = severity_dist.get('critical', 0)
        high = severity_dist.get('high', 0)
        
        if critical > 0:
            recommendations.append({
                'priority': 'CRÍTICA',
                'title': 'Remediação Imediata de Vulnerabilidades Críticas',
                'description': f'Foram identificadas {critical} vulnerabilidade(s) de severidade crítica que representam risco iminente.',
                'actions': [
                    'Remover ou restringir acesso aos arquivos críticos identificados',
                    'Revogar credenciais expostas e gerar novas',
                    'Investigar logs de acesso para detecção de comprometimento',
                    'Implementar monitoramento em tempo real',
                    'Notificar equipes de segurança e conformidade'
                ],
                'timeline': '0-24 horas',
                'methodology': 'Conforme NIST SP 800-61 (Computer Security Incident Handling Guide)'
            })
        
        if high > 0:
            recommendations.append({
                'priority': 'ALTA',
                'title': 'Correção de Vulnerabilidades de Alto Risco',
                'description': f'Identificadas {high} vulnerabilidade(s) de alto risco requerendo ação urgente.',
                'actions': [
                    'Revisar e atualizar políticas de acesso (IAM)',
                    'Implementar autenticação multifator (MFA)',
                    'Criptografar dados sensíveis com algoritmos aprovados (AES-256)',
                    'Ativar auditoria e logging conforme ISO 27001',
                    'Estabelecer processo de gestão de vulnerabilidades'
                ],
                'timeline': '1-7 dias',
                'methodology': 'Conforme ISO/IEC 27002:2022 - Controles de Segurança da Informação'
            })
        
        # Recomendações específicas por categoria
        for category_key, category_data in self.vulnerabilities['categories'].items():
            if not category_data['items']:
                continue
            
            count = len(category_data['items'])
            
            if category_key == 'credentials':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Gestão Segura de Credenciais',
                    'description': f'Detectados {count} arquivo(s) contendo credenciais expostas.',
                    'actions': [
                        'Migrar credenciais para cofre de senhas (Vault/Secrets Manager)',
                        'Implementar rotação automática de credenciais (máximo 90 dias)',
                        'Aplicar princípio de menor privilégio (PoLP)',
                        'Utilizar variáveis de ambiente com criptografia',
                        'Implementar política de senhas fortes (NIST SP 800-63B)'
                    ],
                    'timeline': '0-3 dias',
                    'methodology': 'CIS Controls v8 - Control 5: Account Management'
                })
            
            elif category_key == 'databases':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Proteção de Bancos de Dados',
                    'description': f'Identificados {count} arquivo(s) de banco de dados expostos publicamente.',
                    'actions': [
                        'Mover backups para armazenamento com controle de acesso',
                        'Aplicar criptografia em repouso (TDE - Transparent Data Encryption)',
                        'Implementar backup seguindo regra 3-2-1',
                        'Estabelecer política de retenção e descarte seguro',
                        'Realizar testes de restauração periódicos'
                    ],
                    'timeline': '1-5 dias',
                    'methodology': 'ISO/IEC 27018 - Proteção de PII em nuvens públicas'
                })
            
            elif category_key == 'pii':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Conformidade com LGPD/GDPR',
                    'description': f'Detectados {count} arquivo(s) com dados pessoais (PII) expostos.',
                    'actions': [
                        'Classificar dados conforme Art. 5º da LGPD',
                        'Implementar controles de privacidade by design',
                        'Estabelecer base legal para tratamento de dados',
                        'Criar registro de operações de tratamento (ROPA)',
                        'Notificar ANPD se houver incidente (Art. 48 LGPD)'
                    ],
                    'timeline': '0-72 horas',
                    'methodology': 'Lei 13.709/2018 (LGPD) e GDPR Art. 32-34'
                })
        
        # Recomendações estratégicas
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Implementação de Controles Preventivos',
            'description': 'Estabelecer controles de segurança para prevenção de exposições futuras.',
            'actions': [
                'Configurar buckets/containers como privados por padrão',
                'Implementar SAST/DAST em pipeline CI/CD',
                'Estabelecer programa de awareness em segurança',
                'Implementar DLP (Data Loss Prevention)',
                'Criar playbooks de resposta a incidentes'
            ],
            'timeline': '30-60 dias',
            'methodology': 'NIST Cybersecurity Framework v1.1'
        })
        
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Monitoramento e Detecção Contínua',
            'description': 'Estabelecer capacidades de detecção e resposta a incidentes.',
            'actions': [
                'Implementar SIEM para correlação de eventos',
                'Configurar alertas baseados em comportamento anômalo',
                'Estabelecer SOC (Security Operations Center)',
                'Realizar testes de intrusão periódicos',
                'Medir KPIs de segurança (MTTD, MTTR)'
            ],
            'timeline': '60-90 dias',
            'methodology': 'ISO/IEC 27035 - Gestão de Incidentes de Segurança'
        })
        
        return recommendations
    
    def _create_header_footer(self, canvas, doc):
        """Cabeçalho e rodapé conforme NBR 10719"""
        canvas.saveState()
        
        # Cabeçalho (apenas número de página no topo direito após capa)
        if doc.page > 2:  # Após capa e folha de rosto
            canvas.setFont('Times-Roman', 10)
            canvas.drawRightString(A4[0] - 2*cm, A4[1] - 2*cm, str(doc.page - 2))
        
        canvas.restoreState()
    
    def generate_pdf(self) -> str:
        """Gera relatório técnico NBR 10719"""
        filename = f"relatorio_tecnico_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.pdf"
        filepath = self.output_dir / filename
        
        # Margens NBR 10719: superior e esquerda 3cm, inferior e direita 2cm
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            leftMargin=3*cm,
            rightMargin=2*cm,
            topMargin=3*cm,
            bottomMargin=2*cm
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # Estilos conforme ABNT
        title_style = ParagraphStyle(
            'ABNTTitle',
            parent=styles['Normal'],
            fontSize=12,
            fontName='Times-Bold',
            alignment=TA_CENTER,
            spaceAfter=0,
            spaceBefore=0,
            leading=18  # Espaçamento 1,5
        )
        
        subtitle_style = ParagraphStyle(
            'ABNTSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            fontName='Times-Roman',
            alignment=TA_CENTER,
            spaceAfter=0,
            leading=18
        )
        
        heading1_style = ParagraphStyle(
            'ABNTHeading1',
            parent=styles['Normal'],
            fontSize=12,
            fontName='Times-Bold',
            alignment=TA_LEFT,
            spaceAfter=12,
            spaceBefore=24,
            leading=18
        )
        
        heading2_style = ParagraphStyle(
            'ABNTHeading2',
            parent=styles['Normal'],
            fontSize=12,
            fontName='Times-Bold',
            alignment=TA_LEFT,
            spaceAfter=12,
            spaceBefore=18,
            leading=18
        )
        
        body_style = ParagraphStyle(
            'ABNTBody',
            parent=styles['Normal'],
            fontSize=12,
            fontName='Times-Roman',
            alignment=TA_JUSTIFY,
            spaceAfter=12,
            firstLineIndent=1.25*cm,  # Parágrafo com recuo
            leading=18  # Espaçamento 1,5 linhas
        )
        
        # ============ CAPA ============
        story.append(Spacer(1, 6*cm))
        
        # Nome da organização (se houver)
        if self.client_info.get('name'):
            story.append(Paragraph(self.client_info.get('name', '').upper(), title_style))
            story.append(Spacer(1, 8*cm))
        else:
            story.append(Spacer(1, 10*cm))
        
        # Título
        story.append(Paragraph(
            "RELATÓRIO TÉCNICO DE AUDITORIA DE SEGURANÇA EM STORAGE MULTICLOUD",
            title_style
        ))
        story.append(Spacer(1, 2*cm))
        
        # Subtítulo
        bucket_name = self.scan_data.get('bucket', 'N/A').upper()
        story.append(Paragraph(f"Análise de Vulnerabilidades: {bucket_name}", subtitle_style))
        
        # Local e data (rodapé da capa)
        story.append(Spacer(1, 8*cm))
        city = "São Paulo"  # Pode ser parametrizado
        year = self.report_date.strftime("%Y")
        story.append(Paragraph(f"{city}", subtitle_style))
        story.append(Paragraph(f"{year}", subtitle_style))
        
        story.append(PageBreak())
        
        # ============ FOLHA DE ROSTO ============
        story.append(Spacer(1, 6*cm))
        
        if self.client_info.get('name'):
            story.append(Paragraph(self.client_info.get('name', '').upper(), title_style))
            story.append(Spacer(1, 6*cm))
        else:
            story.append(Spacer(1, 8*cm))
        
        story.append(Paragraph(
            "RELATÓRIO TÉCNICO DE AUDITORIA DE SEGURANÇA EM STORAGE MULTICLOUD",
            title_style
        ))
        story.append(Spacer(1, 3*cm))
        
        # Natureza do trabalho (recuado à direita)
        nature_style = ParagraphStyle(
            'Nature',
            parent=body_style,
            alignment=TA_JUSTIFY,
            leftIndent=8*cm,
            firstLineIndent=0
        )
        
        nature_text = f"""
        Relatório técnico apresentando análise de segurança realizada no ambiente 
        de armazenamento em nuvem {self.scan_data.get('provider', 'N/A')} - 
        {self.scan_data.get('bucket', 'N/A')}, conforme metodologias NIST, 
        ISO/IEC 27001 e OWASP.
        """
        story.append(Paragraph(nature_text, nature_style))
        
        story.append(Spacer(1, 4*cm))
        story.append(Paragraph(f"{city}", subtitle_style))
        story.append(Paragraph(f"{year}", subtitle_style))
        
        story.append(PageBreak())
        
        # ============ RESUMO ============
        story.append(Paragraph("RESUMO", heading1_style))
        story.append(Spacer(1, 0.5*cm))
        
        total_files = len(self.scan_data.get('files', []))
        risk = self.risk_assessment
        
        resumo_text = f"""
        Este relatório técnico apresenta os resultados da auditoria de segurança realizada 
        no ambiente de armazenamento em nuvem {self.scan_data.get('provider', 'N/A')}, 
        bucket/container "{self.scan_data.get('bucket', 'N/A')}", conduzida em 
        {self.report_date.strftime('%d de %B de %Y')}. Foram analisados {total_files} 
        arquivos utilizando metodologias reconhecidas internacionalmente (NIST SP 800-115, 
        OWASP Testing Guide). A auditoria identificou {risk['critical_count']} 
        vulnerabilidade(s) de severidade crítica e {risk['high_count']} de alto risco, 
        resultando em classificação de risco {risk['level']}. O relatório apresenta 
        análise detalhada das vulnerabilidades encontradas, categorização segundo 
        taxonomia CWE/CVE, avaliação de impacto conforme metodologia CVSS v3.1, e 
        recomendações técnicas priorizadas para remediação. As conclusões indicam 
        necessidade de ações imediatas para mitigação dos riscos identificados e 
        estabelecimento de controles preventivos conforme frameworks ISO/IEC 27001:2022 
        e NIST Cybersecurity Framework.
        """
        
        story.append(Paragraph(resumo_text, body_style))
        story.append(Spacer(1, 0.5*cm))
        
        # Palavras-chave
        palavras_chave = f"""
        <b>Palavras-chave:</b> Segurança da Informação. Auditoria de Segurança. 
        Cloud Storage. Vulnerabilidades. {self.scan_data.get('provider', 'N/A')}. 
        ISO 27001. LGPD.
        """
        story.append(Paragraph(palavras_chave, body_style))
        
        story.append(PageBreak())
        
        # ============ LISTA DE TABELAS ============
        story.append(Paragraph("LISTA DE TABELAS", heading1_style))
        story.append(Spacer(1, 0.5*cm))
        
        tables_list = [
            "Tabela 1 – Distribuição de Vulnerabilidades por Severidade",
            "Tabela 2 – Resumo Executivo da Auditoria",
        ]
        
        # Adicionar tabelas de vulnerabilidades
        table_num = 3
        for category_data in self.vulnerabilities['categories'].values():
            if category_data['items']:
                tables_list.append(f"Tabela {table_num} – Vulnerabilidades: {category_data['name']}")
                table_num += 1
        
        for table_name in tables_list:
            story.append(Paragraph(table_name, body_style))
        
        story.append(PageBreak())
        
        # ============ SUMÁRIO ============
        story.append(Paragraph("SUMÁRIO", heading1_style))
        story.append(Spacer(1, 0.5*cm))
        
        sumario_items = [
            "1 INTRODUÇÃO",
            "1.1 Contextualização",
            "1.2 Objetivos",
            "1.3 Escopo",
            "2 METODOLOGIA",
            "2.1 Ferramentas Utilizadas",
            "2.2 Critérios de Avaliação",
            "2.3 Classificação de Severidade",
            "3 RESULTADOS E ANÁLISE",
            "3.1 Visão Geral",
            "3.2 Análise de Vulnerabilidades",
            "3.3 Avaliação de Risco",
            "4 RECOMENDAÇÕES",
            "4.1 Ações Prioritárias",
            "4.2 Controles Preventivos",
            "4.3 Monitoramento Contínuo",
            "5 CONCLUSÕES",
            "REFERÊNCIAS",
            "ANEXO A – Detalhamento Técnico"
        ]
        
        for item in sumario_items:
            story.append(Paragraph(item, body_style))
        
        story.append(PageBreak())
        
        # ============ 1 INTRODUÇÃO ============
        story.append(Paragraph("1 INTRODUÇÃO", heading1_style))
        
        # 1.1 Contextualização
        story.append(Paragraph("1.1 Contextualização", heading2_style))
        
        intro_text = f"""
        A segurança da informação em ambientes de computação em nuvem representa 
        um desafio crítico para organizações contemporâneas. Segundo relatório da 
        Gartner (2023), 95% das falhas de segurança em nuvem são causadas por erro 
        humano, destacando a importância de auditorias periódicas e configuração 
        adequada de controles de acesso.
        """
        story.append(Paragraph(intro_text, body_style))
        
        intro_text2 = f"""
        Este relatório documenta auditoria de segurança realizada no ambiente de 
        armazenamento {self.scan_data.get('provider', 'N/A')}, especificamente no 
        bucket/container "{self.scan_data.get('bucket', 'N/A')}", visando identificar 
        vulnerabilidades, avaliar riscos e propor medidas de mitigação conforme 
        melhores práticas da indústria e requisitos regulatórios aplicáveis 
        (LGPD, ISO/IEC 27001).
        """
        story.append(Paragraph(intro_text2, body_style))
        
        # 1.2 Objetivos
        story.append(Paragraph("1.2 Objetivos", heading2_style))
        
        obj_text = """
        Os objetivos principais desta auditoria são:
        """
        story.append(Paragraph(obj_text, body_style))
        
        objetivos = [
            "Identificar vulnerabilidades de segurança no ambiente de armazenamento auditado;",
            "Classificar vulnerabilidades segundo severidade e potencial impacto;",
            "Avaliar conformidade com frameworks de segurança (ISO 27001, NIST CSF);",
            "Verificar aderência à Lei Geral de Proteção de Dados (LGPD);",
            "Recomendar ações corretivas priorizadas por criticidade e esforço de implementação."
        ]
        
        for obj in objetivos:
            story.append(Paragraph(f"• {obj}", body_style))
        
        # 1.3 Escopo
        story.append(Paragraph("1.3 Escopo", heading2_style))
        
        escopo_text = f"""
        O escopo desta auditoria compreende análise de {total_files} arquivos 
        armazenados no ambiente {self.scan_data.get('provider', 'N/A')}, 
        realizada em {self.report_date.strftime('%d/%m/%Y às %H:%M')}. 
        A avaliação abrange configurações de acesso, permissões, presença de 
        dados sensíveis e conformidade com políticas de segurança estabelecidas.
        """
        story.append(Paragraph(escopo_text, body_style))
        
        story.append(PageBreak())
        
        # ============ 2 METODOLOGIA ============
        story.append(Paragraph("2 METODOLOGIA", heading1_style))
        
        # 2.1 Ferramentas
        story.append(Paragraph("2.1 Ferramentas Utilizadas", heading2_style))
        
        tools_text = """
        A auditoria foi conduzida utilizando ferramenta proprietária "Security 
        Multicloud Scanner v2.0", desenvolvida conforme metodologias OWASP Testing 
        Guide v4.2 e NIST SP 800-115 (Technical Guide to Information Security Testing).
        """
        story.append(Paragraph(tools_text, body_style))
        
        # 2.2 Critérios
        story.append(Paragraph("2.2 Critérios de Avaliação", heading2_style))
        
        criterios_text = """
        As vulnerabilidades identificadas foram avaliadas considerando:
        """
        story.append(Paragraph(criterios_text, body_style))
        
        criterios = [
            "Tipo de arquivo e conteúdo (credenciais, dados pessoais, configurações);",
            "Nível de exposição (público, autenticado, privado);",
            "Sensibilidade dos dados segundo classificação da informação;",
            "Impacto potencial em caso de comprometimento (confidencialidade, integridade, disponibilidade);",
            "Requisitos regulatórios aplicáveis (LGPD, ISO 27001, PCI DSS)."
        ]
        
        for crit in criterios:
            story.append(Paragraph(f"• {crit}", body_style))
        
        # 2.3 Classificação
        story.append(Paragraph("2.3 Classificação de Severidade", heading2_style))
        
        classif_text = """
        A classificação de severidade segue taxonomia adaptada do Common Vulnerability 
        Scoring System (CVSS) v3.1:
        """
        story.append(Paragraph(classif_text, body_style))
        
        # Tabela de classificação
        self.table_counter += 1
        story.append(Paragraph(
            f"Tabela {self.table_counter} – Classificação de Severidade",
            ParagraphStyle('TableCaption', parent=body_style, fontSize=10, alignment=TA_CENTER)
        ))
        story.append(Spacer(1, 0.3*cm))
        
        classif_data = [
            ['Severidade', 'Descrição', 'Ação Requerida'],
            ['CRÍTICA', 'Risco iminente de comprometimento', 'Imediata (0-24h)'],
            ['ALTA', 'Risco elevado de incidente', 'Urgente (1-7 dias)'],
            ['MÉDIA', 'Risco moderado', 'Necessária (7-30 dias)'],
            ['BAIXA', 'Risco controlado', 'Monitorar']
        ]
        
        classif_table = Table(classif_data, colWidths=[3*cm, 6*cm, 4*cm])
        classif_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke)
        ]))
        
        story.append(classif_table)
        story.append(Spacer(1, 0.3*cm))
        
        fonte_text = "Fonte: Adaptado de CVSS v3.1 (FIRST, 2019)"
        story.append(Paragraph(fonte_text, ParagraphStyle('Source', parent=body_style, fontSize=10, alignment=TA_CENTER)))
        
        story.append(PageBreak())
        
        # ============ 3 RESULTADOS E ANÁLISE ============
        story.append(Paragraph("3 RESULTADOS E ANÁLISE", heading1_style))
        
        # 3.1 Visão Geral
        story.append(Paragraph("3.1 Visão Geral", heading2_style))
        
        visao_text = f"""
        A auditoria identificou total de {total_files} arquivos no ambiente analisado. 
        Destes, {risk['critical_count']} apresentam severidade crítica, {risk['high_count']} 
        severidade alta, {self.vulnerabilities['total_medium']} severidade média e 
        {self.vulnerabilities['total_low']} severidade baixa. O ambiente foi classificado 
        com nível de risco {risk['level']}, caracterizado como "{risk['description']}".
        """
        story.append(Paragraph(visao_text, body_style))
        
        # Tabela resumo
        self.table_counter += 1
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(
            f"Tabela {self.table_counter} – Resumo Executivo da Auditoria",
            ParagraphStyle('TableCaption', parent=body_style, fontSize=10, alignment=TA_CENTER)
        ))
        story.append(Spacer(1, 0.3*cm))
        
        resumo_data = [
            ['Parâmetro', 'Valor'],
            ['Provider', self.scan_data.get('provider', 'N/A')],
            ['Bucket/Container', self.scan_data.get('bucket', 'N/A')],
            ['Total de Arquivos', str(total_files)],
            ['Vulnerabilidades Críticas', str(risk['critical_count'])],
            ['Vulnerabilidades Altas', str(risk['high_count'])],
            ['Score de Risco', f"{risk['score']}%"],
            ['Classificação', risk['level']]
        ]
        
        resumo_table = Table(resumo_data, colWidths=[6*cm, 7*cm])
        resumo_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Times-Bold'),
            ('FONTNAME', (1, 1), (1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke)
        ]))
        
        story.append(resumo_table)
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("Fonte: Dados da auditoria", ParagraphStyle('Source', parent=body_style, fontSize=10, alignment=TA_CENTER)))
        
        # 3.2 Análise de Vulnerabilidades
        story.append(PageBreak())
        story.append(Paragraph("3.2 Análise de Vulnerabilidades", heading2_style))
        
        # Tabela distribuição
        self.table_counter += 1
        story.append(Paragraph(
            f"Tabela {self.table_counter} – Distribuição de Vulnerabilidades por Severidade",
            ParagraphStyle('TableCaption', parent=body_style, fontSize=10, alignment=TA_CENTER)
        ))
        story.append(Spacer(1, 0.3*cm))
        
        dist_data = [
            ['Severidade', 'Quantidade', 'Percentual'],
            ['CRÍTICA', str(risk['critical_count']), f"{self._calc_percent(risk['critical_count'], total_files)}%"],
            ['ALTA', str(risk['high_count']), f"{self._calc_percent(risk['high_count'], total_files)}%"],
            ['MÉDIA', str(self.vulnerabilities['total_medium']), f"{self._calc_percent(self.vulnerabilities['total_medium'], total_files)}%"],
            ['BAIXA', str(self.vulnerabilities['total_low']), f"{self._calc_percent(self.vulnerabilities['total_low'], total_files)}%"]
        ]
        
        dist_table = Table(dist_data, colWidths=[4*cm, 4*cm, 4*cm])
        dist_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke)
        ]))
        
        story.append(dist_table)
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("Fonte: Dados da auditoria", ParagraphStyle('Source', parent=body_style, fontSize=10, alignment=TA_CENTER)))
        
        # Análise por categoria
        story.append(Spacer(1, 0.5*cm))
        
        for category_key, category_data in self.vulnerabilities['categories'].items():
            if not category_data['items']:
                continue
            
            count = len(category_data['items'])
            
            story.append(Paragraph(f"3.2.{list(self.vulnerabilities['categories'].keys()).index(category_key) + 1} {category_data['name']}", heading2_style))
            
            cat_text = f"""
            Foram identificados {count} arquivo(s) classificados como "{category_data['name']}". 
            Esta categoria representa risco significativo considerando potencial de 
            comprometimento e impacto em caso de exploração maliciosa.
            """
            story.append(Paragraph(cat_text, body_style))
            
            # Tabela de arquivos (máximo 5)
            self.table_counter += 1
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph(
                f"Tabela {self.table_counter} – Vulnerabilidades: {category_data['name']}",
                ParagraphStyle('TableCaption', parent=body_style, fontSize=10, alignment=TA_CENTER)
            ))
            story.append(Spacer(1, 0.3*cm))
            
            vuln_data = [['Arquivo', 'Tamanho', 'Severidade']]
            for item in category_data['items'][:5]:
                file_name = item['file']
                if len(file_name) > 40:
                    file_name = file_name[:37] + '...'
                vuln_data.append([
                    file_name,
                    self._format_size(item['size']),
                    item['severity']
                ])
            
            vuln_table = Table(vuln_data, colWidths=[7*cm, 3*cm, 3*cm])
            vuln_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke)
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Fonte: Dados da auditoria", ParagraphStyle('Source', parent=body_style, fontSize=10, alignment=TA_CENTER)))
            
            if count > 5:
                story.append(Paragraph(f"Nota: Listados {min(5, count)} de {count} arquivos identificados.", body_style))
        
        # 3.3 Avaliação de Risco
        story.append(PageBreak())
        story.append(Paragraph("3.3 Avaliação de Risco", heading2_style))
        
        risco_text = f"""
        Baseado na metodologia NIST SP 800-30 (Guide for Conducting Risk Assessments), 
        o ambiente auditado apresenta nível de risco {risk['level']}, caracterizado por 
        {risk['description'].lower()}. Esta classificação considera probabilidade de 
        ocorrência de incidente de segurança e magnitude do impacto potencial.
        """
        story.append(Paragraph(risco_text, body_style))
        
        if risk['critical_count'] > 0:
            risco_crit = f"""
            A presença de {risk['critical_count']} vulnerabilidade(s) crítica(s) representa 
            risco iminente que requer ação imediata. Segundo framework NIST Cybersecurity, 
            tais vulnerabilidades permitem acesso não autorizado a dados sensíveis, 
            potencialmente violando princípios de confidencialidade estabelecidos pela LGPD 
            (Art. 6º, inciso VII) e ISO/IEC 27001 (Anexo A.9 - Controle de Acesso).
            """
            story.append(Paragraph(risco_crit, body_style))
        
        story.append(PageBreak())
        
        # ============ 4 RECOMENDAÇÕES ============
        story.append(Paragraph("4 RECOMENDAÇÕES", heading1_style))
        
        # 4.1 Ações Prioritárias
        story.append(Paragraph("4.1 Ações Prioritárias", heading2_style))
        
        for idx, rec in enumerate([r for r in self.recommendations if r['priority'] in ['CRÍTICA', 'ALTA']], 1):
            story.append(Paragraph(f"4.1.{idx} {rec['title']}", heading2_style))
            
            rec_text = f"""
            {rec['description']} Prazo recomendado: {rec['timeline']}. 
            Metodologia de referência: {rec.get('methodology', 'N/A')}.
            """
            story.append(Paragraph(rec_text, body_style))
            
            story.append(Paragraph("Ações recomendadas:", body_style))
            for action in rec['actions']:
                story.append(Paragraph(f"• {action}", body_style))
            
            story.append(Spacer(1, 0.3*cm))
        
        # 4.2 Controles Preventivos
        story.append(PageBreak())
        story.append(Paragraph("4.2 Controles Preventivos", heading2_style))
        
        preventivos = [r for r in self.recommendations if r['priority'] == 'MÉDIA' and 'Preventivos' in r['title']]
        if preventivos:
            rec = preventivos[0]
            prev_text = f"""
            {rec['description']} Estabelecer controles preventivos conforme 
            ISO/IEC 27001:2022 Anexo A.8 (Gestão de Ativos) e Anexo A.9 (Controle de Acesso).
            """
            story.append(Paragraph(prev_text, body_style))
            
            for action in rec['actions']:
                story.append(Paragraph(f"• {action}", body_style))
        
        # 4.3 Monitoramento
        story.append(Paragraph("4.3 Monitoramento Contínuo", heading2_style))
        
        monitora = [r for r in self.recommendations if 'Monitoramento' in r['title']]
        if monitora:
            rec = monitora[0]
            mon_text = f"""
            {rec['description']} Implementar capacidades de detecção conforme 
            ISO/IEC 27035 (Gestão de Incidentes) e NIST SP 800-61 
            (Computer Security Incident Handling Guide).
            """
            story.append(Paragraph(mon_text, body_style))
            
            for action in rec['actions']:
                story.append(Paragraph(f"• {action}", body_style))
        
        story.append(PageBreak())
        
        # ============ 5 CONCLUSÕES ============
        story.append(Paragraph("5 CONCLUSÕES", heading1_style))
        
        conclusao_text = f"""
        A auditoria de segurança realizada no ambiente {self.scan_data.get('provider', 'N/A')} 
        identificou {risk['critical_count']} vulnerabilidade(s) de severidade crítica e 
        {risk['high_count']} de alto risco, evidenciando necessidade de ações imediatas 
        para mitigação dos riscos identificados.
        """
        story.append(Paragraph(conclusao_text, body_style))
        
        conclusao2 = """
        As vulnerabilidades identificadas representam potencial violação de requisitos 
        estabelecidos pela Lei Geral de Proteção de Dados (Lei 13.709/2018), 
        particularmente no que tange aos princípios de segurança (Art. 6º, VII) e 
        prevenção (Art. 6º, VIII). Adicionalmente, configuram não conformidades com 
        controles especificados na ISO/IEC 27001:2022.
        """
        story.append(Paragraph(conclusao2, body_style))
        
        conclusao3 = """
        Recomenda-se implementação priorizada das ações corretivas apresentadas na 
        Seção 4, estabelecimento de programa de gestão contínua de vulnerabilidades 
        e realização de auditorias periódicas conforme boas práticas da indústria. 
        Sugere-se re-auditoria em prazo máximo de 90 dias para verificação de 
        efetividade das medidas implementadas.
        """
        story.append(Paragraph(conclusao3, body_style))
        
        story.append(PageBreak())
        
        # ============ REFERÊNCIAS ============
        story.append(Paragraph("REFERÊNCIAS", heading1_style))
        
        referencias = [
            "ASSOCIAÇÃO BRASILEIRA DE NORMAS TÉCNICAS. NBR 10719: Informação e documentação – Relatório técnico e/ou científico – Apresentação. Rio de Janeiro, 2015.",
            
            "BRASIL. Lei nº 13.709, de 14 de agosto de 2018. Lei Geral de Proteção de Dados Pessoais (LGPD). Brasília, DF: Diário Oficial da União, 2018.",
            
            "FIRST – Forum of Incident Response and Security Teams. Common Vulnerability Scoring System version 3.1: Specification Document. 2019. Disponível em: https://www.first.org/cvss/. Acesso em: " + self.report_date.strftime("%d %b. %Y") + ".",
            
            "INTERNATIONAL ORGANIZATION FOR STANDARDIZATION. ISO/IEC 27001:2022: Information security, cybersecurity and privacy protection – Information security management systems – Requirements. Geneva, 2022.",
            
            "INTERNATIONAL ORGANIZATION FOR STANDARDIZATION. ISO/IEC 27002:2022: Information security, cybersecurity and privacy protection – Information security controls. Geneva, 2022.",
            
            "INTERNATIONAL ORGANIZATION FOR STANDARDIZATION. ISO/IEC 27035:2023: Information technology – Security techniques – Information security incident management. Geneva, 2023.",
            
            "NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY. NIST SP 800-30: Guide for Conducting Risk Assessments. Gaithersburg, MD, 2012.",
            
            "NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY. NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide. Gaithersburg, MD, 2012.",
            
            "NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY. NIST SP 800-115: Technical Guide to Information Security Testing and Assessment. Gaithersburg, MD, 2008.",
            
            "NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY. Cybersecurity Framework Version 1.1. Gaithersburg, MD, 2018.",
            
            "OWASP FOUNDATION. OWASP Testing Guide v4.2. 2020. Disponível em: https://owasp.org/www-project-web-security-testing-guide/. Acesso em: " + self.report_date.strftime("%d %b. %Y") + "."
        ]
        
        for ref in referencias:
            story.append(Paragraph(ref, body_style))
            story.append(Spacer(1, 0.3*cm))
        
        story.append(PageBreak())
        
        # ============ ANEXO ============
        story.append(Paragraph("ANEXO A – DETALHAMENTO TÉCNICO", heading1_style))
        
        anexo_text = """
        Este anexo apresenta informações técnicas complementares sobre a auditoria 
        realizada, incluindo parâmetros de configuração, ferramentas utilizadas e 
        metodologias aplicadas.
        """
        story.append(Paragraph(anexo_text, body_style))
        
        story.append(Paragraph("A.1 Especificações Técnicas", heading2_style))
        
        specs = [
            f"Data e hora da auditoria: {self.report_date.strftime('%d/%m/%Y às %H:%M:%S')}",
            f"Ferramenta: Security Multicloud Scanner v2.0",
            f"Metodologia: NIST SP 800-115, OWASP Testing Guide v4.2",
            f"Provider: {self.scan_data.get('provider', 'N/A')}",
            f"Bucket/Container: {self.scan_data.get('bucket', 'N/A')}",
            f"Total de objetos analisados: {total_files}",
            f"Critérios de avaliação: CVSS v3.1, CWE/CVE taxonomy"
        ]
        
        for spec in specs:
            story.append(Paragraph(f"• {spec}", body_style))
        
        # Construir PDF
        doc.build(story, onFirstPage=self._create_header_footer, 
                 onLaterPages=self._create_header_footer)
        
        print(f"✅ Relatório Técnico NBR 10719 gerado: {filepath}")
        return str(filepath)
    
    def _calc_percent(self, value: int, total: int) -> str:
        if total == 0:
            return "0,0"
        return f"{(value / total * 100):.1f}".replace('.', ',')
    
    def _format_size(self, bytes_size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}".replace('.', ',')
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB".replace('.', ',')


def generate_executive_report(scan_data: dict, client_info: dict = None, output_format: str = 'pdf') -> dict:
    """Função principal para gerar relatórios NBR 10719"""
    generator = NBR10719ReportGenerator(scan_data, client_info)
    results = {}
    
    try:
        results['pdf'] = generator.generate_pdf()
    except Exception as e:
        print(f"❌ PDF erro: {e}")
        import traceback
        traceback.print_exc()
        results['pdf_error'] = str(e)
    
    return results
