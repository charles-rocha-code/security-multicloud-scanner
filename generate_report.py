"""
generate_report.py - Gerador de Relatórios Executivos PROFISSIONAL
Versão Enterprise com design corporativo e análise aprofundada
CORRIGIDO: Suporte completo para Azure Blob Storage
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
    
    # Mapeamento de providers
    PROVIDER_NAMES = {
        'AWS_S3': 'AWS S3',
        'GCS': 'Google Cloud Storage',
        'AZURE': 'Azure Blob Storage',
        'AZURE_BLOB': 'Azure Blob Storage',
        'UNIVERSAL': 'Multi-Cloud'
    }
    
    def __init__(self, scan_data: dict, client_info: dict = None):
        """
        Inicializa gerador com validação de dados
        
        Args:
            scan_data: Dados do scan (bucket, files, severity_distribution, etc)
            client_info: Informações do cliente (name, contact)
        """
        print("🔧 Inicializando gerador de relatórios...")
        print(f"📊 Dados recebidos: {list(scan_data.keys())}")
        
        # Validar dados essenciais
        self._validate_scan_data(scan_data)
        
        self.scan_data = scan_data
        self.client_info = client_info or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_date = datetime.now()
        
        # Criar diretório de saída
        self.output_dir = Path("./reports_executive")
        self.output_dir.mkdir(exist_ok=True)
        
        print(f"📁 Diretório de saída: {self.output_dir}")
        
        # Normalizar provider name
        self.provider_name = self._get_provider_name()
        print(f"☁️ Provider: {self.provider_name}")
        
        # Análise de vulnerabilidades
        try:
            self.vulnerabilities = self._analyze_vulnerabilities()
            print(f"🔍 Vulnerabilidades analisadas: {len(self.vulnerabilities)} categorias")
        except Exception as e:
            print(f"⚠️ Erro ao analisar vulnerabilidades: {e}")
            self.vulnerabilities = []
        
        try:
            self.recommendations = self._generate_recommendations()
            print(f"💡 Recomendações geradas: {len(self.recommendations)}")
        except Exception as e:
            print(f"⚠️ Erro ao gerar recomendações: {e}")
            self.recommendations = []
        
        try:
            self.risk_level = self._calculate_risk_level()
            print(f"⚠️ Nível de risco: {self.risk_level['level']} ({self.risk_level['score']}%)")
        except Exception as e:
            print(f"⚠️ Erro ao calcular risco: {e}")
            self.risk_level = {
                'level': 'DESCONHECIDO',
                'score': 0,
                'color': self.COLOR_MEDIUM,
                'action': 'ANÁLISE NECESSÁRIA',
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0
            }
        
        try:
            self.compliance_status = self._assess_compliance()
            print(f"📋 Status de compliance: {len(self.compliance_status)} frameworks")
        except Exception as e:
            print(f"⚠️ Erro ao avaliar compliance: {e}")
            self.compliance_status = []
    
    def _validate_scan_data(self, scan_data: dict):
        """Valida se os dados do scan estão minimamente completos"""
        if not scan_data:
            raise ValueError("❌ scan_data está vazio")
        
        if 'bucket' not in scan_data:
            print("⚠️ Campo 'bucket' ausente, usando valor padrão")
            scan_data['bucket'] = 'unknown-bucket'
        
        if 'files' not in scan_data:
            print("⚠️ Campo 'files' ausente, usando lista vazia")
            scan_data['files'] = []
        
        if 'severity_distribution' not in scan_data:
            print("⚠️ Campo 'severity_distribution' ausente, calculando...")
            scan_data['severity_distribution'] = self._calculate_severity_distribution(scan_data.get('files', []))
        
        if 'risk_score' not in scan_data:
            print("⚠️ Campo 'risk_score' ausente, usando 0")
            scan_data['risk_score'] = 0
        
        if 'provider' not in scan_data:
            print("⚠️ Campo 'provider' ausente, usando UNIVERSAL")
            scan_data['provider'] = 'UNIVERSAL'
        
        print("✅ Validação de dados concluída")
    
    def _calculate_severity_distribution(self, files: list) -> dict:
        """Calcula distribuição de severidade se não estiver presente"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for file in files:
            severity = file.get('severity', 'LOW').lower()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _get_provider_name(self) -> str:
        """Retorna nome formatado do provider"""
        provider = self.scan_data.get('provider', 'UNIVERSAL').upper()
        return self.PROVIDER_NAMES.get(provider, provider)
    
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
        
        print(f"🔍 Analisando {len(files)} arquivos...")
        
        # Categorizar por tipo de vulnerabilidade
        vuln_categories = {
            'credentials': {'name': 'Credenciais Expostas', 'icon': '[KEY]', 'items': []},
            'databases': {'name': 'Bancos de Dados', 'icon': '[DB]', 'items': []},
            'config': {'name': 'Arquivos de Configuracao', 'icon': '[CFG]', 'items': []},
            'backups': {'name': 'Backups', 'icon': '[BAK]', 'items': []},
            'source_code': {'name': 'Codigo Fonte', 'icon': '[SRC]', 'items': []},
            'keys': {'name': 'Chaves Criptograficas', 'icon': '[SEC]', 'items': []},
            'pii': {'name': 'Dados Pessoais (PII)', 'icon': '[PII]', 'items': []}
        }
        
        for file in files:
            try:
                key = file.get('key', file.get('name', '')).lower()
                severity = file.get('severity', 'LOW')
                reason = file.get('reason', '')
                
                if severity in ['CRITICAL', 'HIGH']:
                    item = {
                        'file': file.get('key', file.get('name', 'unknown')),
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
                    
                    # Source code
                    elif any(x in key for x in ['.py', '.java', '.js', '.php', '.rb', '.go', '.cpp']):
                        vuln_categories['source_code']['items'].append(item)
            
            except Exception as e:
                print(f"⚠️ Erro ao analisar arquivo {file}: {e}")
                continue
        
        # Converter para lista apenas categorias com itens
        for cat_key, cat_data in vuln_categories.items():
            if cat_data['items']:
                vulnerabilities.append({
                    'name': cat_data['name'],
                    'icon': cat_data['icon'],
                    'count': len(cat_data['items']),
                    'items': cat_data['items'][:20]  # Máximo 20 por categoria
                })
        
        print(f"✅ {len(vulnerabilities)} categorias de vulnerabilidades encontradas")
        return vulnerabilities
    
    def _generate_recommendations(self) -> list:
        """Gera recomendações baseadas nas vulnerabilidades"""
        recommendations = []
        severity_dist = self.scan_data.get('severity_distribution', {})
        provider = self.scan_data.get('provider', 'UNIVERSAL').upper()
        
        critical_count = severity_dist.get('critical', 0)
        high_count = severity_dist.get('high', 0)
        
        # Recomendação 1: Acesso Público
        if critical_count > 0 or high_count > 0:
            if 'AZURE' in provider:
                actions = [
                    "Revisar políticas de acesso em 'Access control (IAM)' no Azure Portal",
                    "Configurar 'Private endpoints' para acesso restrito",
                    "Habilitar 'Shared Access Signatures (SAS)' com expiração",
                    "Implementar 'Azure AD' para autenticação",
                    "Configurar 'Network rules' para restringir IPs"
                ]
            elif provider == 'AWS_S3':
                actions = [
                    "Revisar bucket policies e ACLs no console AWS",
                    "Bloquear acesso público via 'Block Public Access'",
                    "Implementar bucket encryption (AES-256 ou KMS)",
                    "Habilitar versioning para recovery",
                    "Configurar logging para auditoria"
                ]
            elif provider == 'GCS':
                actions = [
                    "Revisar IAM policies no GCP Console",
                    "Remover 'allUsers' e 'allAuthenticatedUsers' das permissões",
                    "Implementar 'Uniform bucket-level access'",
                    "Habilitar 'Object versioning'",
                    "Configurar 'Audit logs'"
                ]
            else:
                actions = [
                    "Revisar políticas de acesso do bucket/container",
                    "Remover permissões públicas desnecessárias",
                    "Implementar autenticação forte",
                    "Habilitar criptografia em repouso",
                    "Configurar logs de auditoria"
                ]
            
            recommendations.append({
                'priority': 'CRÍTICA',
                'title': 'Restringir Acesso Público ao Storage',
                'description': f'Foram identificados {critical_count + high_count} arquivos com exposição pública. É fundamental restringir o acesso imediatamente.',
                'actions': actions,
                'timeline': '0-24 horas',
                'responsible': 'Equipe de Segurança / DevOps'
            })
        
        # Recomendação 2: Criptografia
        recommendations.append({
            'priority': 'ALTA',
            'title': 'Implementar Criptografia de Dados',
            'description': 'Garantir que todos os dados sensíveis estejam criptografados em repouso e em trânsito.',
            'actions': [
                "Habilitar criptografia server-side no storage",
                "Implementar HTTPS/TLS para todas as transferências",
                "Rotacionar chaves de criptografia regularmente",
                "Usar chaves gerenciadas pelo cliente (CMK) quando possível",
                "Documentar procedimentos de gestão de chaves"
            ],
            'timeline': '7-14 dias',
            'responsible': 'Equipe de Segurança'
        })
        
        # Recomendação 3: Monitoramento
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Implementar Monitoramento Contínuo',
            'description': 'Estabelecer monitoramento contínuo para detectar acessos suspeitos e mudanças de configuração.',
            'actions': [
                "Configurar alertas para acessos anômalos",
                "Implementar SIEM para análise de logs",
                "Criar dashboards de segurança",
                "Estabelecer processo de resposta a incidentes",
                "Realizar auditorias de segurança regulares"
            ],
            'timeline': '14-30 dias',
            'responsible': 'Equipe de SecOps'
        })
        
        # Recomendação 4: Políticas e Governança
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Estabelecer Políticas de Governança',
            'description': 'Definir e implementar políticas claras de classificação e proteção de dados.',
            'actions': [
                "Classificar dados por sensibilidade (Público, Interno, Confidencial, Restrito)",
                "Definir políticas de retenção de dados",
                "Implementar controles de DLP (Data Loss Prevention)",
                "Treinar equipes sobre políticas de segurança",
                "Realizar revisões trimestrais de acessos"
            ],
            'timeline': '30-60 dias',
            'responsible': 'CISO / Compliance'
        })
        
        return recommendations
    
    def _create_header_footer(self, canvas, doc):
        """Cria cabeçalho e rodapé profissional"""
        canvas.saveState()
        
        # Cabeçalho com fundo azul
        canvas.setFillColor(self.COLOR_PRIMARY)
        canvas.rect(0, A4[1] - 0.6*inch, A4[0], 0.6*inch, fill=True, stroke=False)
        
        # Título do relatório (SEM emoji)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 12)
        canvas.drawString(0.5*inch, A4[1] - 0.35*inch, "RELATORIO DE SEGURANCA EXECUTIVO")
        
        # Data no canto direito
        canvas.setFont('Helvetica', 9)
        canvas.drawRightString(A4[0] - 0.5*inch, A4[1] - 0.35*inch, 
                              self.report_date.strftime("%d/%m/%Y"))
        
        # Rodapé
        canvas.setFillColor(colors.grey)
        canvas.setFont('Helvetica', 8)
        canvas.drawString(0.5*inch, 0.4*inch, 
                         f"Security Multicloud Scanner | {self.provider_name}")
        canvas.drawRightString(A4[0] - 0.5*inch, 0.4*inch, 
                              f"Pagina {doc.page}")
        
        # Linha divisória no rodapé
        canvas.setStrokeColor(self.COLOR_PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(0.5*inch, 0.6*inch, A4[0] - 0.5*inch, 0.6*inch)
        
        canvas.restoreState()
    
    def generate_pdf(self) -> str:
        """Gera relatório PDF profissional"""
        print("📄 Gerando PDF...")
        
        bucket_name = self.scan_data.get('bucket', 'scan').replace('.', '_').replace('/', '_')
        filename = f"relatorio_{bucket_name}_{self.timestamp}.pdf"
        filepath = self.output_dir / filename
        
        print(f"💾 Arquivo: {filepath}")
        
        try:
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=A4,
                topMargin=0.8*inch,
                bottomMargin=0.8*inch,
                leftMargin=0.7*inch,
                rightMargin=0.7*inch
            )
            
            story = []
            styles = getSampleStyleSheet()
            
            # Estilos customizados
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=self.COLOR_PRIMARY,
                spaceAfter=12,
                spaceBefore=12,
                fontName='Helvetica-Bold'
            )
            
            # ============ CAPA ============
            story.append(Spacer(1, 2*inch))
            
            title = Paragraph("RELATORIO DE SEGURANCA EXECUTIVO", ParagraphStyle(
                'Title',
                fontSize=26,
                alignment=TA_CENTER,
                textColor=self.COLOR_PRIMARY,
                fontName='Helvetica-Bold',
                spaceAfter=30,
                leading=32
            ))
            story.append(title)
            
            subtitle = Paragraph(f"Auditoria de Storage Multicloud<br/>{self.provider_name}", ParagraphStyle(
                'Subtitle',
                fontSize=14,
                alignment=TA_CENTER,
                textColor=colors.grey,
                spaceAfter=40
            ))
            story.append(subtitle)
            
            # Info do cliente
            if self.client_info.get('name'):
                client_table_data = [
                    ['Cliente:', self.client_info.get('name', 'N/A')],
                    ['Contato:', self.client_info.get('contact', 'N/A')],
                    ['Data:', self.report_date.strftime('%d/%m/%Y às %H:%M')],
                    ['Bucket/Container:', self.scan_data.get('bucket', 'N/A')]
                ]
                
                client_table = Table(client_table_data, colWidths=[1.5*inch, 3.5*inch])
                client_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 11),
                    ('TEXTCOLOR', (0, 0), (0, -1), self.COLOR_PRIMARY),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                ]))
                
                story.append(client_table)
            
            story.append(PageBreak())
            
            # ============ RESUMO EXECUTIVO ============
            story.append(Paragraph("RESUMO EXECUTIVO", heading_style))
            story.append(Spacer(1, 0.15*inch))
            
            risk_info = self.risk_level
            severity_dist = self.scan_data.get('severity_distribution', {})
            total_files = len(self.scan_data.get('files', []))
            
            # Box de risco
            risk_box_data = [[
                Paragraph(f"<b>NÍVEL DE RISCO: {risk_info['level']}</b>", ParagraphStyle(
                    'RiskLevel',
                    fontSize=14,
                    textColor=colors.white,
                    alignment=TA_CENTER
                )),
                Paragraph(f"<b>{risk_info['score']}%</b>", ParagraphStyle(
                    'RiskScore',
                    fontSize=20,
                    textColor=colors.white,
                    alignment=TA_CENTER,
                    fontName='Helvetica-Bold'
                ))
            ]]
            
            risk_box = Table(risk_box_data, colWidths=[3*inch, 1.5*inch])
            risk_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), risk_info['color']),
                ('PADDING', (0, 0), (-1, -1), 15),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            
            story.append(risk_box)
            story.append(Spacer(1, 0.2*inch))
            
            # Métricas principais
            metrics_data = [
                ['Métrica', 'Valor'],
                ['Provider', self.provider_name],
                ['Bucket/Container', self.scan_data.get('bucket', 'N/A')],
                ['Total de Arquivos Analisados', str(total_files)],
                ['Vulnerabilidades CRÍTICAS', str(severity_dist.get('critical', 0))],
                ['Vulnerabilidades ALTAS', str(severity_dist.get('high', 0))],
                ['Vulnerabilidades MÉDIAS', str(severity_dist.get('medium', 0))],
                ['Vulnerabilidades BAIXAS', str(severity_dist.get('low', 0))]
            ]
            
            metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLOR_PRIMARY),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLOR_BG_LIGHT])
            ]))
            
            story.append(metrics_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Mensagem de ação
            action_text = f"<b>{risk_info['action']}</b>"
            story.append(Paragraph(action_text, ParagraphStyle(
                'ActionText',
                fontSize=12,
                textColor=risk_info['color'],
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )))
            
            story.append(PageBreak())
            
            # ============ VULNERABILIDADES ============
            if self.vulnerabilities:
                story.append(Paragraph("VULNERABILIDADES IDENTIFICADAS", heading_style))
                story.append(Spacer(1, 0.15*inch))
                
                for vuln in self.vulnerabilities:
                    # Título da categoria
                    vuln_title = f"{vuln['icon']} {vuln['name']} ({vuln['count']} arquivos)"
                    story.append(Paragraph(vuln_title, ParagraphStyle(
                        'VulnTitle',
                        fontSize=12,
                        fontName='Helvetica-Bold',
                        textColor=self.COLOR_SECONDARY,
                        spaceAfter=8
                    )))
                    
                    # Tabela de arquivos
                    vuln_table_data = [['Arquivo', 'Severidade', 'Tamanho']]
                    
                    for item in vuln['items'][:10]:  # Máximo 10 por categoria
                        vuln_table_data.append([
                            item['file'][:60] + ('...' if len(item['file']) > 60 else ''),
                            item['severity'],
                            self._format_size(item['size'])
                        ])
                    
                    vuln_table = Table(vuln_table_data, colWidths=[3.5*inch, 0.8*inch, 0.8*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_SECONDARY),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('PADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLOR_BG_LIGHT])
                    ]))
                    
                    story.append(vuln_table)
                    story.append(Spacer(1, 0.15*inch))
            
            story.append(PageBreak())
            
            # ============ RECOMENDAÇÕES ============
            story.append(Paragraph("RECOMENDACOES PRIORITARIAS", heading_style))
            story.append(Spacer(1, 0.15*inch))
            
            for i, rec in enumerate(self.recommendations, 1):
                # Cabeçalho da recomendação
                priority_colors = {
                    'CRÍTICA': self.COLOR_CRITICAL,
                    'ALTA': self.COLOR_HIGH,
                    'MÉDIA': self.COLOR_MEDIUM,
                    'BAIXA': self.COLOR_LOW
                }
                
                rec_header = f"[{rec['priority']}] {rec['title']}"
                story.append(Paragraph(rec_header, ParagraphStyle(
                    'RecTitle',
                    fontSize=11,
                    fontName='Helvetica-Bold',
                    textColor=priority_colors.get(rec['priority'], self.COLOR_MEDIUM),
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
            if self.compliance_status:
                story.append(Paragraph("STATUS DE CONFORMIDADE", heading_style))
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
            story.append(Paragraph("CONCLUSOES E PROXIMOS PASSOS", heading_style))
            story.append(Spacer(1, 0.1*inch))
            
            conclusion_text = f"""
            Este relatório identificou <b>{risk_info['critical_count']} vulnerabilidades críticas</b> e 
            <b>{risk_info['high_count']} de alto risco</b> no ambiente {self.provider_name} analisado. 
            
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
            signature_text = f"""
            <b>Security Multicloud Scanner</b><br/>
            {self.provider_name} | Relatório gerado automaticamente<br/>
            Este documento contém informações confidenciais
            """
            
            story.append(Paragraph(signature_text, ParagraphStyle(
                'Signature',
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER
            )))
            
            # Construir PDF com cabeçalho/rodapé
            print("🔨 Construindo PDF...")
            doc.build(story, onFirstPage=self._create_header_footer, 
                     onLaterPages=self._create_header_footer)
            
            print(f"✅ PDF gerado com sucesso: {filepath}")
            return str(filepath)
        
        except Exception as e:
            print(f"❌ Erro ao gerar PDF: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def generate_docx(self) -> str:
        """Gera relatório DOCX profissional"""
        if not DOCX_AVAILABLE:
            print("⚠️ python-docx não disponível")
            return None
        
        print("📝 Gerando DOCX...")
        
        bucket_name = self.scan_data.get('bucket', 'scan').replace('.', '_').replace('/', '_')
        filename = f"relatorio_{bucket_name}_{self.timestamp}.docx"
        filepath = self.output_dir / filename
        
        print(f"💾 Arquivo: {filepath}")
        
        try:
            doc = Document()
            
            # Configurar estilos
            sections = doc.sections
            for section in sections:
                section.page_height = Inches(11.69)
                section.page_width = Inches(8.27)
                section.left_margin = Inches(0.8)
                section.right_margin = Inches(0.8)
            
            # Título
            title = doc.add_heading('RELATORIO DE SEGURANCA EXECUTIVO', 0)
            title.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            subtitle = doc.add_paragraph(f'Auditoria de Storage Multicloud - {self.provider_name}')
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
            doc.add_paragraph(f"Provider: {self.provider_name}")
            doc.add_paragraph(f"Bucket/Container: {self.scan_data.get('bucket', 'N/A')}")
            doc.add_paragraph(f"Arquivos Analisados: {len(self.scan_data.get('files', []))}")
            doc.add_paragraph(f"Nível de Risco: {self.risk_level['level']} ({self.risk_level['score']}%)")
            doc.add_paragraph(f"Ação Requerida: {self.risk_level['action']}")
            
            # Vulnerabilidades
            if self.vulnerabilities:
                doc.add_heading('VULNERABILIDADES IDENTIFICADAS', level=1)
                for vuln in self.vulnerabilities:
                    doc.add_heading(f"{vuln['icon']} {vuln['name']} ({vuln['count']} arquivos)", level=2)
                    for item in vuln['items'][:10]:
                        doc.add_paragraph(f"• {item['file']} - {item['severity']}", style='List Bullet')
            
            # Recomendações
            doc.add_heading('RECOMENDAÇÕES PRIORITÁRIAS', level=1)
            for rec in self.recommendations:
                doc.add_heading(f"[{rec['priority']}] {rec['title']}", level=2)
                doc.add_paragraph(rec['description'])
                doc.add_paragraph(f"Prazo: {rec.get('timeline', 'A definir')}")
                doc.add_paragraph(f"Responsável: {rec.get('responsible', 'A definir')}")
                doc.add_paragraph('Ações Recomendadas:')
                for action in rec['actions']:
                    doc.add_paragraph(f"• {action}", style='List Bullet')
            
            # Compliance
            if self.compliance_status:
                doc.add_heading('STATUS DE CONFORMIDADE', level=1)
                for framework in self.compliance_status:
                    doc.add_paragraph(f"{framework['name']}: {framework['status']}")
                    doc.add_paragraph(f"   {framework['issues']}")
            
            # Conclusão
            doc.add_heading('CONCLUSÕES', level=1)
            doc.add_paragraph(f"""
            Este relatório identificou {self.risk_level['critical_count']} vulnerabilidades críticas e 
            {self.risk_level['high_count']} de alto risco no ambiente {self.provider_name} analisado.
            É fundamental executar as ações prioritárias nos prazos estabelecidos.
            """)
            
            doc.save(str(filepath))
            print(f"✅ DOCX gerado com sucesso: {filepath}")
            return str(filepath)
        
        except Exception as e:
            print(f"❌ Erro ao gerar DOCX: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _calc_percent(self, value: int, total: int) -> str:
        if total == 0:
            return "0.0"
        return f"{(value / total * 100):.1f}"
    
    def _format_size(self, bytes_size: int) -> str:
        """Formata tamanho de arquivo"""
        try:
            bytes_size = int(bytes_size)
        except (ValueError, TypeError):
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f}{unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f}TB"


def generate_executive_report(scan_data: dict, client_info: dict = None, output_format: str = 'both') -> dict:
    """
    Função principal para gerar relatórios PROFISSIONAIS
    
    Args:
        scan_data: Dados do scan
        client_info: Informações do cliente
        output_format: 'pdf', 'docx', ou 'both'
    
    Returns:
        dict com caminhos dos arquivos gerados
    """
    print("\n" + "="*60)
    print("🚀 INICIANDO GERAÇÃO DE RELATÓRIO EXECUTIVO")
    print("="*60)
    
    try:
        generator = ProfessionalReportGenerator(scan_data, client_info)
        results = {}
        
        if output_format in ['pdf', 'both']:
            try:
                print("\n📄 Gerando PDF...")
                results['pdf'] = generator.generate_pdf()
                print(f"✅ PDF: {results['pdf']}")
            except Exception as e:
                print(f"❌ Erro ao gerar PDF: {e}")
                import traceback
                traceback.print_exc()
                results['pdf_error'] = str(e)
        
        if output_format in ['docx', 'both'] and DOCX_AVAILABLE:
            try:
                print("\n📝 Gerando DOCX...")
                results['docx'] = generator.generate_docx()
                print(f"✅ DOCX: {results['docx']}")
            except Exception as e:
                print(f"❌ Erro ao gerar DOCX: {e}")
                import traceback
                traceback.print_exc()
                results['docx_error'] = str(e)
        
        print("\n" + "="*60)
        print("✅ GERAÇÃO DE RELATÓRIO CONCLUÍDA")
        print("="*60 + "\n")
        
        return results
    
    except Exception as e:
        print(f"\n❌ ERRO CRÍTICO na geração de relatório: {e}")
        import traceback
        traceback.print_exc()
        raise
