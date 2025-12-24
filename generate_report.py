"""
generate_report.py - Gerador de Relatórios Executivos PROFISSIONAL
Versão Enterprise com design corporativo e análise aprofundada
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, 
    PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.graphics.shapes import Drawing as ShapeDrawing, Rect
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
from pathlib import Path

# Para DOCX
try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import RGBColor, Pt, Inches
    from docx.oxml.ns import qn
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


class ProfessionalReportGenerator:
    """Gerador de relatórios executivos PROFISSIONAL"""
    
    # Cores corporativas
    COLOR_PRIMARY = colors.HexColor('#1e3a8a')      # Azul escuro
    COLOR_SECONDARY = colors.HexColor('#3b82f6')    # Azul médio
    COLOR_ACCENT = colors.HexColor('#60a5fa')       # Azul claro
    COLOR_CRITICAL = colors.HexColor('#dc2626')     # Vermelho
    COLOR_HIGH = colors.HexColor('#ea580c')         # Laranja
    COLOR_MEDIUM = colors.HexColor('#ca8a04')       # Amarelo
    COLOR_LOW = colors.HexColor('#16a34a')          # Verde
    COLOR_HEADER = colors.HexColor('#0f172a')       # Quase preto
    COLOR_BG_LIGHT = colors.HexColor('#f8fafc')     # Cinza clarinho
    
    def __init__(self, scan_data: dict, client_info: dict = None):
        self.scan_data = scan_data
        self.client_info = client_info or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_date = datetime.now()
        
        # Criar diretório de saída
        self.output_dir = Path("./reports_executive")
        self.output_dir.mkdir(exist_ok=True)
        
        # Análise de vulnerabilidades
        self.vulnerabilities = self._analyze_vulnerabilities()
        self.recommendations = self._generate_recommendations()
        self.risk_level = self._calculate_risk_level()
        self.compliance_status = self._assess_compliance()
    
    def _calculate_risk_level(self) -> dict:
        """Calcula nível de risco geral"""
        severity_dist = self.scan_data.get('severity_distribution', {})
        risk_score = self.scan_data.get('risk_score', 0)
        
        critical = severity_dist.get('critical', 0)
        high = severity_dist.get('high', 0)
        medium = severity_dist.get('medium', 0)
        
        # Determinar nível
        if critical > 0:
            level = "CRÍTICO"
            color = self.COLOR_CRITICAL
            action = "AÇÃO IMEDIATA REQUERIDA"
        elif high > 5:
            level = "ALTO"
            color = self.COLOR_HIGH
            action = "AÇÃO URGENTE REQUERIDA"
        elif high > 0 or medium > 10:
            level = "MÉDIO"
            color = self.COLOR_MEDIUM
            action = "AÇÃO NECESSÁRIA"
        else:
            level = "BAIXO"
            color = self.COLOR_LOW
            action = "MONITORAMENTO RECOMENDADO"
        
        return {
            'level': level,
            'score': risk_score,
            'color': color,
            'action': action,
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium
        }
    
    def _assess_compliance(self) -> dict:
        """Avalia status de compliance"""
        severity_dist = self.scan_data.get('severity_distribution', {})
        critical = severity_dist.get('critical', 0)
        high = severity_dist.get('high', 0)
        
        frameworks = []
        
        # LGPD / GDPR
        if critical > 0 or high > 0:
            frameworks.append({
                'name': 'LGPD / GDPR',
                'status': '❌ NÃO CONFORME',
                'issues': 'Dados pessoais potencialmente expostos'
            })
        else:
            frameworks.append({
                'name': 'LGPD / GDPR',
                'status': '⚠️ REVISAR',
                'issues': 'Verificar classificação de dados'
            })
        
        # ISO 27001
        if critical > 0:
            frameworks.append({
                'name': 'ISO 27001',
                'status': '❌ NÃO CONFORME',
                'issues': 'Controles de acesso inadequados'
            })
        else:
            frameworks.append({
                'name': 'ISO 27001',
                'status': '⚠️ EM CONFORMIDADE PARCIAL',
                'issues': 'Revisar políticas de segurança'
            })
        
        # PCI DSS (se aplicável)
        if any('card' in f.get('key', '').lower() or 'payment' in f.get('key', '').lower() 
               for f in self.scan_data.get('files', [])):
            frameworks.append({
                'name': 'PCI DSS',
                'status': '❌ CRÍTICO',
                'issues': 'Dados de pagamento expostos'
            })
        
        return frameworks
    
    def _analyze_vulnerabilities(self) -> list:
        """Analisa arquivos e identifica vulnerabilidades específicas"""
        vulnerabilities = []
        files = self.scan_data.get('files', [])
        
        # Categorizar por tipo de vulnerabilidade
        vuln_categories = {
            'credentials': {'name': 'Credenciais Expostas', 'icon': '🔑', 'items': []},
            'databases': {'name': 'Bancos de Dados', 'icon': '💾', 'items': []},
            'config': {'name': 'Arquivos de Configuração', 'icon': '⚙️', 'items': []},
            'backups': {'name': 'Backups', 'icon': '💿', 'items': []},
            'source_code': {'name': 'Código Fonte', 'icon': '📝', 'items': []},
            'keys': {'name': 'Chaves Criptográficas', 'icon': '🔐', 'items': []},
            'pii': {'name': 'Dados Pessoais (PII)', 'icon': '👤', 'items': []}
        }
        
        for file in files:
            key = file.get('key', '').lower()
            severity = file.get('severity', 'LOW')
            reason = file.get('reason', '')
            
            if severity in ['CRITICAL', 'HIGH']:
                item = {
                    'file': file.get('key'),
                    'size': file.get('size', 0),
                    'severity': severity,
                    'reason': reason,
                    'last_modified': file.get('last_modified', 'N/A')
                }
                
                # Credenciais
                if any(x in key for x in ['password', 'credential', 'secret', 'token', 'api_key', 'apikey']):
                    vuln_categories['credentials']['items'].append(item)
                
                # Bancos de dados
                elif any(x in key for x in ['.sql', '.db', '.sqlite', 'database', 'dump', '.mdb']):
                    vuln_categories['databases']['items'].append(item)
                
                # Arquivos de configuração
                elif any(x in key for x in ['.env', 'config', '.ini', '.yaml', '.yml', '.conf', 'settings']):
                    vuln_categories['config']['items'].append(item)
                
                # Backups
                elif any(x in key for x in ['backup', '.bak', '.old', '.zip', '.tar', '.gz', '.rar']):
                    vuln_categories['backups']['items'].append(item)
                
                # Chaves
                elif any(x in key for x in ['.pem', '.key', '.crt', '.cer', '.p12', '.pfx', 'private', 'rsa']):
                    vuln_categories['keys']['items'].append(item)
                
                # PII
                elif any(x in key for x in ['cpf', 'rg', 'passport', 'social', 'personal', 'customer']):
                    vuln_categories['pii']['items'].append(item)
        
        # Montar lista de vulnerabilidades
        for category, data in vuln_categories.items():
            if data['items']:
                vulnerabilities.append({
                    'category': category,
                    'name': data['name'],
                    'icon': data['icon'],
                    'items': data['items'],
                    'count': len(data['items'])
                })
        
        return vulnerabilities
    
    def _generate_recommendations(self) -> list:
        """Gera recomendações específicas baseadas nas vulnerabilidades"""
        recommendations = []
        files = self.scan_data.get('files', [])
        severity_dist = self.scan_data.get('severity_distribution', {})
        
        critical_count = severity_dist.get('critical', 0)
        high_count = severity_dist.get('high', 0)
        
        # Recomendações prioritárias
        if critical_count > 0:
            recommendations.append({
                'priority': 'CRÍTICA',
                'title': 'Remover Arquivos Críticos Imediatamente',
                'description': f'Identificados {critical_count} arquivo(s) de severidade CRÍTICA. Risco imediato de comprometimento.',
                'actions': [
                    'Remover ou mover arquivos críticos para storage privado HOJE',
                    'Revogar todas as credenciais expostas IMEDIATAMENTE',
                    'Investigar logs de acesso para detectar comprometimento',
                    'Ativar alertas em tempo real para acesso a arquivos sensíveis',
                    'Notificar equipe de segurança e stakeholders'
                ],
                'timeline': '0-24 horas',
                'responsible': 'CISO / Equipe de Segurança'
            })
        
        if high_count > 0:
            recommendations.append({
                'priority': 'ALTA',
                'title': 'Remediar Arquivos de Alto Risco',
                'description': f'Encontrados {high_count} arquivo(s) de alto risco.',
                'actions': [
                    'Revisar e atualizar políticas de acesso ao bucket/container',
                    'Implementar autenticação multifator (MFA)',
                    'Criptografar arquivos sensíveis com KMS',
                    'Configurar logs de auditoria e alertas',
                    'Realizar scan de segurança semanal'
                ],
                'timeline': '1-7 dias',
                'responsible': 'DevOps / Cloud Security'
            })
        
        # Recomendações por tipo de vulnerabilidade
        for vuln in self.vulnerabilities:
            category = vuln['category']
            count = vuln['count']
            
            if category == 'credentials':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Gestão Segura de Credenciais',
                    'description': f'{count} arquivo(s) com credenciais expostas.',
                    'actions': [
                        'Migrar para AWS Secrets Manager / Azure Key Vault / GCP Secret Manager',
                        'Implementar rotação automática de credenciais (30-90 dias)',
                        'Utilizar variáveis de ambiente com criptografia',
                        'Auditar todos os sistemas que usam as credenciais expostas',
                        'Implementar política de senha forte (mínimo 16 caracteres)'
                    ],
                    'timeline': '0-3 dias',
                    'responsible': 'DevSecOps / Platform Team'
                })
            
            elif category == 'databases':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Proteção de Bancos de Dados',
                    'description': f'{count} arquivo(s) de banco de dados expostos.',
                    'actions': [
                        'Mover backups para storage com acesso restrito',
                        'Criptografar dumps com AES-256 ou superior',
                        'Implementar política de retenção (ex: 30 dias)',
                        'Usar serviços gerenciados de backup (AWS Backup, Azure Backup)',
                        'Testar restauração de backups mensalmente'
                    ],
                    'timeline': '1-5 dias',
                    'responsible': 'DBA / Infrastructure Team'
                })
            
            elif category == 'config':
                recommendations.append({
                    'priority': 'ALTA',
                    'title': 'Gestão de Configurações',
                    'description': f'{count} arquivo(s) de configuração sensíveis.',
                    'actions': [
                        'Remover .env, config.ini de repositórios e storage público',
                        'Usar sistemas de configuração gerenciada (Consul, etcd)',
                        'Separar configurações por ambiente com namespaces',
                        'Implementar GitOps com aprovação obrigatória',
                        'Criar template de configuração sem dados sensíveis'
                    ],
                    'timeline': '3-7 dias',
                    'responsible': 'DevOps / SRE'
                })
            
            elif category == 'keys':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Gestão de Chaves Criptográficas',
                    'description': f'{count} chave(s) privada(s) exposta(s).',
                    'actions': [
                        'REVOGAR todas as chaves comprometidas IMEDIATAMENTE',
                        'Gerar novos pares de chaves com algoritmo forte (RSA 4096+)',
                        'Usar HSM (Hardware Security Module) para chaves críticas',
                        'Implementar rotação automática de certificados (Let\'s Encrypt)',
                        'Auditar todos os serviços que usam as chaves expostas'
                    ],
                    'timeline': '0-1 dia',
                    'responsible': 'Security Team / PKI Admin'
                })
        
        # Recomendações estratégicas
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Implementar Controles Preventivos',
            'description': 'Estabelecer controles para prevenir exposições futuras.',
            'actions': [
                'Configurar buckets/containers como PRIVADO por padrão',
                'Implementar scanning automatizado em pipeline CI/CD',
                'Estabelecer processo de code review obrigatório',
                'Implementar DLP (Data Loss Prevention)',
                'Criar runbooks de resposta a incidentes',
                'Realizar treinamento de segurança para toda equipe'
            ],
            'timeline': '30-60 dias',
            'responsible': 'CISO / Security Champions'
        })
        
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Monitoramento e Detecção Contínua',
            'description': 'Estabelecer visibilidade e resposta a incidentes.',
            'actions': [
                'Ativar CloudTrail / Azure Monitor / GCP Cloud Logging',
                'Configurar alertas para acessos anômalos',
                'Implementar SIEM (Splunk, ELK, Azure Sentinel)',
                'Realizar auditorias de segurança trimestrais',
                'Implementar threat intelligence feeds',
                'Estabelecer métricas de segurança (KPIs)'
            ],
            'timeline': '60-90 dias',
            'responsible': 'SOC / Security Operations'
        })
        
        return recommendations
    
    def _create_header_footer(self, canvas, doc):
        """Cria cabeçalho e rodapé em todas as páginas"""
        canvas.saveState()
        
        # Cabeçalho
        canvas.setFillColor(self.COLOR_HEADER)
        canvas.rect(0, A4[1] - 40, A4[0], 40, fill=True, stroke=False)
        
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawString(30, A4[1] - 25, "🔒 RELATÓRIO DE SEGURANÇA - CONFIDENCIAL")
        
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(A4[0] - 30, A4[1] - 25, 
                              f"Cliente: {self.client_info.get('name', 'N/A')}")
        
        # Rodapé
        canvas.setFillColor(self.COLOR_HEADER)
        canvas.rect(0, 0, A4[0], 30, fill=True, stroke=False)
        
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(30, 12, 
                         f"Security Multicloud Scanner v2.0 | {self.report_date.strftime('%d/%m/%Y')}")
        canvas.drawRightString(A4[0] - 30, 12, f"Página {doc.page}")
        
        canvas.restoreState()
    
    def _create_severity_chart(self) -> ShapeDrawing:
        """Cria gráfico de barras de severidade"""
        severity_dist = self.scan_data.get('severity_distribution', {})
        
        drawing = ShapeDrawing(400, 200)
        
        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 50
        chart.height = 125
        chart.width = 300
        
        data = [[
            severity_dist.get('critical', 0),
            severity_dist.get('high', 0),
            severity_dist.get('medium', 0),
            severity_dist.get('low', 0)
        ]]
        
        chart.data = data
        chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(max(data[0]), 10)
        
        chart.bars[0].fillColor = self.COLOR_CRITICAL
        
        drawing.add(chart)
        
        return drawing
    
    def generate_pdf(self) -> str:
        """Gera relatório PDF PROFISSIONAL"""
        filename = f"relatorio_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.pdf"
        filepath = self.output_dir / filename
        
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=50,
            bottomMargin=40
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # Estilos personalizados
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=10,
            spaceBefore=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=self.COLOR_SECONDARY,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=self.COLOR_PRIMARY,
            borderPadding=8,
            backColor=self.COLOR_BG_LIGHT
        )
        
        # ============ PÁGINA 1: CAPA ============
        story.append(Spacer(1, 2*inch))
        
        # Título
        story.append(Paragraph("🔒 RELATÓRIO DE<br/>SEGURANÇA EXECUTIVO", title_style))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph("Auditoria de Storage Multicloud", subtitle_style))
        
        # Box de risco
        risk_info = self.risk_level
        risk_color = risk_info['color']
        
        risk_table_data = [[
            Paragraph(f"<b>NÍVEL DE RISCO: {risk_info['level']}</b>", 
                     ParagraphStyle('RiskLevel', fontSize=18, textColor=risk_color, alignment=TA_CENTER)),
        ], [
            Paragraph(f"Score: {risk_info['score']}%", 
                     ParagraphStyle('RiskScore', fontSize=14, alignment=TA_CENTER))
        ], [
            Paragraph(risk_info['action'], 
                     ParagraphStyle('RiskAction', fontSize=12, alignment=TA_CENTER, textColor=risk_color))
        ]]
        
        risk_table = Table(risk_table_data, colWidths=[5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 2, risk_color),
            ('PADDING', (0, 0), (-1, -1), 15),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        
        story.append(Spacer(1, 0.5*inch))
        story.append(risk_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Informações do cliente
        if self.client_info.get('name'):
            client_data = [
                ['', ''],
                ['Cliente:', self.client_info.get('name', '-')],
                ['Contato:', self.client_info.get('contact', '-')],
                ['Data:', self.report_date.strftime("%d/%m/%Y às %H:%M")],
                ['', '']
            ]
            
            client_table = Table(client_data, colWidths=[1.5*inch, 3.5*inch])
            client_table.setStyle(TableStyle([
                ('FONTNAME', (0, 1), (0, -2), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 1), (-1, -2), 11),
                ('ALIGN', (0, 1), (0, -2), 'RIGHT'),
                ('ALIGN', (1, 1), (1, -2), 'LEFT'),
                ('PADDING', (0, 0), (-1, -1), 8)
            ]))
            
            story.append(client_table)
        
        story.append(PageBreak())
        
        # ============ PÁGINA 2: SUMÁRIO EXECUTIVO ============
        story.append(Paragraph("📋 SUMÁRIO EXECUTIVO", heading_style))
        story.append(Spacer(1, 0.2*inch))
        
        provider = self.scan_data.get('provider', 'N/A')
        bucket = self.scan_data.get('bucket', 'N/A')
        total_files = len(self.scan_data.get('files', []))
        
        # Resumo em destaque
        summary_text = f"""
        <b>Provider:</b> {provider}<br/>
        <b>Bucket/Container:</b> {bucket}<br/>
        <b>Total de Arquivos Analisados:</b> {total_files}<br/>
        <b>Vulnerabilidades Críticas:</b> {risk_info['critical_count']}<br/>
        <b>Vulnerabilidades Altas:</b> {risk_info['high_count']}<br/>
        <b>Vulnerabilidades Médias:</b> {risk_info['medium_count']}<br/>
        <b>Score de Risco:</b> {risk_info['score']}%
        """
        
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Distribuição com tabela melhorada
        story.append(Paragraph("📊 DISTRIBUIÇÃO DE SEVERIDADE", heading_style))
        story.append(Spacer(1, 0.1*inch))
        
        severity_dist = self.scan_data.get('severity_distribution', {})
        severity_data = [
            [
                Paragraph('<b>Severidade</b>', ParagraphStyle('Header', fontSize=10, textColor=colors.white)),
                Paragraph('<b>Quantidade</b>', ParagraphStyle('Header', fontSize=10, textColor=colors.white)),
                Paragraph('<b>%</b>', ParagraphStyle('Header', fontSize=10, textColor=colors.white)),
                Paragraph('<b>Status</b>', ParagraphStyle('Header', fontSize=10, textColor=colors.white))
            ],
            [
                '🔴 CRITICAL',
                str(severity_dist.get('critical', 0)),
                f"{self._calc_percent(severity_dist.get('critical', 0), total_files)}%",
                'AÇÃO IMEDIATA' if severity_dist.get('critical', 0) > 0 else '-'
            ],
            [
                '🟠 HIGH',
                str(severity_dist.get('high', 0)),
                f"{self._calc_percent(severity_dist.get('high', 0), total_files)}%",
                'AÇÃO URGENTE' if severity_dist.get('high', 0) > 0 else '-'
            ],
            [
                '🟡 MEDIUM',
                str(severity_dist.get('medium', 0)),
                f"{self._calc_percent(severity_dist.get('medium', 0), total_files)}%",
                'REVISAR' if severity_dist.get('medium', 0) > 0 else '-'
            ],
            [
                '🟢 LOW',
                str(severity_dist.get('low', 0)),
                f"{self._calc_percent(severity_dist.get('low', 0), total_files)}%",
                'MONITORAR'
            ]
        ]
        
        severity_table = Table(severity_data, colWidths=[1.5*inch, 1.2*inch, 1*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, self.COLOR_PRIMARY),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLOR_BG_LIGHT]),
            ('ALIGN', (1, 1), (2, -1), 'CENTER')
        ]))
        
        story.append(severity_table)
        story.append(PageBreak())
        
        # ============ VULNERABILIDADES ============
        if self.vulnerabilities:
            story.append(Paragraph("⚠️ VULNERABILIDADES IDENTIFICADAS", heading_style))
            story.append(Spacer(1, 0.15*inch))
            
            for vuln in self.vulnerabilities:
                category_title = f"{vuln['icon']} {vuln['name']} ({vuln['count']} arquivo(s))"
                
                category_style = ParagraphStyle(
                    'Category',
                    fontSize=13,
                    textColor=self.COLOR_CRITICAL,
                    fontName='Helvetica-Bold',
                    spaceAfter=8
                )
                
                story.append(Paragraph(category_title, category_style))
                
                # Tabela de arquivos
                vuln_files_data = [[
                    Paragraph('<b>Arquivo</b>', ParagraphStyle('H', fontSize=9)),
                    Paragraph('<b>Tamanho</b>', ParagraphStyle('H', fontSize=9)),
                    Paragraph('<b>Severidade</b>', ParagraphStyle('H', fontSize=9))
                ]]
                
                for item in vuln['items'][:8]:  # Máximo 8 por categoria
                    file_name = item['file']
                    if len(file_name) > 45:
                        file_name = file_name[:42] + '...'
                    
                    vuln_files_data.append([
                        file_name,
                        self._format_size(item['size']),
                        item['severity']
                    ])
                
                vuln_table = Table(vuln_files_data, colWidths=[3.2*inch, 0.9*inch, 1*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_CRITICAL),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLOR_BG_LIGHT])
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 0.15*inch))
                
                if len(vuln['items']) > 8:
                    story.append(Paragraph(
                        f"<i>... e mais {len(vuln['items']) - 8} arquivo(s)</i>",
                        styles['Normal']
                    ))
                    story.append(Spacer(1, 0.1*inch))
            
            story.append(PageBreak())
        
        # ============ RECOMENDAÇÕES ============
        story.append(Paragraph("✅ PLANO DE AÇÃO E RECOMENDAÇÕES", heading_style))
        story.append(Spacer(1, 0.15*inch))
        
        for i, rec in enumerate(self.recommendations, 1):
            # Box de recomendação
            priority_colors = {
                'CRÍTICA': self.COLOR_CRITICAL,
                'ALTA': self.COLOR_HIGH,
                'MÉDIA': self.COLOR_MEDIUM
            }
            
            rec_color = priority_colors.get(rec['priority'], self.COLOR_MEDIUM)
            
            # Título
            rec_title = f"<b>[{rec['priority']}] {rec['title']}</b>"
            story.append(Paragraph(rec_title, ParagraphStyle(
                'RecTitle',
                fontSize=12,
                textColor=rec_color,
                fontName='Helvetica-Bold',
                spaceAfter=5
            )))
            
            # Descrição
            story.append(Paragraph(rec['description'], styles['Normal']))
            story.append(Spacer(1, 0.05*inch))
            
            # Timeline e responsável
            timeline_text = f"<b>Prazo:</b> {rec.get('timeline', 'A definir')} | <b>Responsável:</b> {rec.get('responsible', 'A definir')}"
            story.append(Paragraph(timeline_text, ParagraphStyle(
                'Timeline',
                fontSize=9,
                textColor=colors.grey,
                spaceAfter=5
            )))
            
            # Ações
            story.append(Paragraph("<b>Ações Recomendadas:</b>", styles['Normal']))
            for action in rec['actions'][:5]:  # Máximo 5 ações
                story.append(Paragraph(f"• {action}", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
        
        story.append(PageBreak())
        
        # ============ COMPLIANCE ============
        story.append(Paragraph("📜 STATUS DE CONFORMIDADE", heading_style))
        story.append(Spacer(1, 0.15*inch))
        
        compliance_data = [['Framework', 'Status', 'Observações']]
        for framework in self.compliance_status:
            compliance_data.append([
                framework['name'],
                framework['status'],
                framework['issues']
            ])
        
        compliance_table = Table(compliance_data, colWidths=[1.5*inch, 1.8*inch, 2*inch])
        compliance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLOR_PRIMARY),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        
        story.append(compliance_table)
        story.append(Spacer(1, 0.3*inch))
        
        # ============ CONCLUSÃO ============
        story.append(Paragraph("🎯 CONCLUSÕES E PRÓXIMOS PASSOS", heading_style))
        story.append(Spacer(1, 0.1*inch))
        
        conclusion_text = f"""
        Este relatório identificou <b>{risk_info['critical_count']} vulnerabilidades críticas</b> e 
        <b>{risk_info['high_count']} de alto risco</b> no ambiente analisado. 
        
        É fundamental que as ações prioritárias sejam executadas nos prazos estabelecidos para 
        mitigar os riscos identificados e garantir a conformidade com frameworks de segurança.
        
        <b>Próximos Passos Recomendados:</b><br/>
        1. Reunião de alinhamento com stakeholders (próximas 48h)<br/>
        2. Execução das ações críticas (0-7 dias)<br/>
        3. Implementação de controles preventivos (30-60 dias)<br/>
        4. Re-auditoria de segurança (em 90 dias)<br/>
        5. Estabelecimento de programa de segurança contínua
        """
        
        story.append(Paragraph(conclusion_text, styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Assinatura
        signature_text = """
        <b>Security Multicloud Scanner</b><br/>
        Relatório gerado automaticamente<br/>
        Este documento contém informações confidenciais
        """
        
        story.append(Paragraph(signature_text, ParagraphStyle(
            'Signature',
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )))
        
        # Construir PDF com cabeçalho/rodapé
        doc.build(story, onFirstPage=self._create_header_footer, 
                 onLaterPages=self._create_header_footer)
        
        print(f"✅ PDF PROFISSIONAL gerado: {filepath}")
        return str(filepath)
    
    def generate_docx(self) -> str:
        """Gera relatório DOCX profissional"""
        if not DOCX_AVAILABLE:
            return None
        
        filename = f"relatorio_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.docx"
        filepath = self.output_dir / filename
        
        doc = Document()
        
        # Configurar estilos
        sections = doc.sections
        for section in sections:
            section.page_height = Inches(11.69)
            section.page_width = Inches(8.27)
            section.left_margin = Inches(0.8)
            section.right_margin = Inches(0.8)
        
        # Título
        title = doc.add_heading('🔒 RELATÓRIO DE SEGURANÇA EXECUTIVO', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        subtitle = doc.add_paragraph('Auditoria de Storage Multicloud')
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        doc.add_paragraph()
        
        # Cliente
        if self.client_info.get('name'):
            doc.add_heading('INFORMAÇÕES DO CLIENTE', level=1)
            doc.add_paragraph(f"Cliente: {self.client_info.get('name')}")
            doc.add_paragraph(f"Contato: {self.client_info.get('contact')}")
            doc.add_paragraph(f"Data: {self.report_date.strftime('%d/%m/%Y às %H:%M')}")
        
        # Resumo
        doc.add_heading('RESUMO EXECUTIVO', level=1)
        doc.add_paragraph(f"Provider: {self.scan_data.get('provider', 'N/A')}")
        doc.add_paragraph(f"Bucket: {self.scan_data.get('bucket', 'N/A')}")
        doc.add_paragraph(f"Arquivos: {len(self.scan_data.get('files', []))}")
        doc.add_paragraph(f"Risco: {self.risk_level['score']}% ({self.risk_level['level']})")
        
        # Vulnerabilidades
        if self.vulnerabilities:
            doc.add_heading('VULNERABILIDADES IDENTIFICADAS', level=1)
            for vuln in self.vulnerabilities:
                doc.add_heading(f"{vuln['icon']} {vuln['name']} ({vuln['count']} arquivos)", level=2)
                for item in vuln['items'][:10]:
                    doc.add_paragraph(f"• {item['file']} - {item['severity']}", style='List Bullet')
        
        # Recomendações
        doc.add_heading('RECOMENDAÇÕES', level=1)
        for rec in self.recommendations:
            doc.add_heading(f"[{rec['priority']}] {rec['title']}", level=2)
            doc.add_paragraph(rec['description'])
            for action in rec['actions']:
                doc.add_paragraph(f"• {action}", style='List Bullet')
        
        # Compliance
        doc.add_heading('STATUS DE CONFORMIDADE', level=1)
        for framework in self.compliance_status:
            doc.add_paragraph(f"{framework['name']}: {framework['status']}")
            doc.add_paragraph(f"   {framework['issues']}")
        
        doc.save(str(filepath))
        print(f"✅ DOCX gerado: {filepath}")
        return str(filepath)
    
    def _calc_percent(self, value: int, total: int) -> str:
        if total == 0:
            return "0.0"
        return f"{(value / total * 100):.1f}"
    
    def _format_size(self, bytes_size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f}{unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f}TB"


def generate_executive_report(scan_data: dict, client_info: dict = None, output_format: str = 'both') -> dict:
    """Função principal para gerar relatórios PROFISSIONAIS"""
    generator = ProfessionalReportGenerator(scan_data, client_info)
    results = {}
    
    if output_format in ['pdf', 'both']:
        try:
            results['pdf'] = generator.generate_pdf()
        except Exception as e:
            print(f"❌ PDF erro: {e}")
            import traceback
            traceback.print_exc()
            results['pdf_error'] = str(e)
    
    if output_format in ['docx', 'both'] and DOCX_AVAILABLE:
        try:
            results['docx'] = generator.generate_docx()
        except Exception as e:
            print(f"❌ DOCX erro: {e}")
            import traceback
            traceback.print_exc()
            results['docx_error'] = str(e)
    
    return results
