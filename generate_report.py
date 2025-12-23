"""
generate_report.py - Gerador de Relatórios Executivos
Gera relatórios profissionais em PDF e DOCX com análise de vulnerabilidades
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from pathlib import Path

# Para DOCX
try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import RGBColor, Pt
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


class ReportGenerator:
    """Gerador de relatórios executivos com análise de vulnerabilidades"""
    
    def __init__(self, scan_data: dict, client_info: dict = None):
        self.scan_data = scan_data
        self.client_info = client_info or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Criar diretório de saída
        self.output_dir = Path("./reports_executive")
        self.output_dir.mkdir(exist_ok=True)
        
        # Análise de vulnerabilidades
        self.vulnerabilities = self._analyze_vulnerabilities()
        self.recommendations = self._generate_recommendations()
    
    def _analyze_vulnerabilities(self) -> list:
        """Analisa arquivos e identifica vulnerabilidades específicas"""
        vulnerabilities = []
        files = self.scan_data.get('files', [])
        
        # Categorizar por tipo de vulnerabilidade
        vuln_categories = {
            'credentials': [],
            'databases': [],
            'config': [],
            'backups': [],
            'source_code': [],
            'pii': [],
            'keys': []
        }
        
        for file in files:
            key = file.get('key', '').lower()
            severity = file.get('severity', 'LOW')
            reason = file.get('reason', '')
            
            if severity in ['CRITICAL', 'HIGH']:
                # Credenciais
                if any(x in key for x in ['password', 'credential', 'secret', 'token', 'api_key', 'apikey']):
                    vuln_categories['credentials'].append({
                        'file': file.get('key'),
                        'size': file.get('size', 0),
                        'severity': severity,
                        'reason': reason,
                        'type': 'Credenciais Expostas'
                    })
                
                # Bancos de dados
                elif any(x in key for x in ['.sql', '.db', '.sqlite', 'database', 'dump', '.mdb']):
                    vuln_categories['databases'].append({
                        'file': file.get('key'),
                        'size': file.get('size', 0),
                        'severity': severity,
                        'reason': reason,
                        'type': 'Banco de Dados Exposto'
                    })
                
                # Arquivos de configuração
                elif any(x in key for x in ['.env', 'config', '.ini', '.yaml', '.yml', '.conf', 'settings']):
                    vuln_categories['config'].append({
                        'file': file.get('key'),
                        'size': file.get('size', 0),
                        'severity': severity,
                        'reason': reason,
                        'type': 'Configuração Sensível'
                    })
                
                # Backups
                elif any(x in key for x in ['backup', '.bak', '.old', '.zip', '.tar', '.gz', '.rar']):
                    vuln_categories['backups'].append({
                        'file': file.get('key'),
                        'size': file.get('size', 0),
                        'severity': severity,
                        'reason': reason,
                        'type': 'Backup Exposto'
                    })
                
                # Código fonte
                elif any(x in key for x in ['.git', '.svn', 'source', '.java', '.py', '.js', '.php']):
                    vuln_categories['source_code'].append({
                        'file': file.get('key'),
                        'size': file.get('size', 0),
                        'severity': severity,
                        'reason': reason,
                        'type': 'Código Fonte Exposto'
                    })
                
                # Chaves e certificados
                elif any(x in key for x in ['.pem', '.key', '.crt', '.cer', '.p12', '.pfx', 'private', 'rsa']):
                    vuln_categories['keys'].append({
                        'file': file.get('key'),
                        'size': file.get('size', 0),
                        'severity': severity,
                        'reason': reason,
                        'type': 'Chaves Criptográficas Expostas'
                    })
        
        # Montar lista de vulnerabilidades
        for category, items in vuln_categories.items():
            if items:
                vulnerabilities.append({
                    'category': category,
                    'items': items,
                    'count': len(items)
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
                'description': f'Foram encontrados {critical_count} arquivo(s) de severidade CRÍTICA. Estes arquivos representam risco imediato de comprometimento.',
                'actions': [
                    'Remover ou mover arquivos críticos para storage privado',
                    'Revogar credenciais expostas imediatamente',
                    'Investigar possível acesso não autorizado',
                    'Ativar alertas de acesso a estes arquivos'
                ]
            })
        
        if high_count > 0:
            recommendations.append({
                'priority': 'ALTA',
                'title': 'Remediar Arquivos de Alto Risco',
                'description': f'Identificados {high_count} arquivo(s) de alto risco que requerem ação urgente.',
                'actions': [
                    'Revisar políticas de acesso ao bucket/container',
                    'Implementar autenticação e autorização',
                    'Criptografar arquivos sensíveis',
                    'Configurar logs de auditoria'
                ]
            })
        
        # Recomendações por tipo de vulnerabilidade
        for vuln in self.vulnerabilities:
            category = vuln['category']
            count = vuln['count']
            
            if category == 'credentials':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Gestão de Credenciais',
                    'description': f'{count} arquivo(s) com credenciais expostas detectados.',
                    'actions': [
                        'Utilizar serviços de secrets management (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)',
                        'Nunca armazenar credenciais em arquivos de código ou configuração',
                        'Implementar rotação automática de credenciais',
                        'Usar variáveis de ambiente ou serviços gerenciados'
                    ]
                })
            
            elif category == 'databases':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Proteção de Bancos de Dados',
                    'description': f'{count} arquivo(s) de banco de dados expostos.',
                    'actions': [
                        'Mover backups de banco para storage privado',
                        'Criptografar dumps de banco de dados',
                        'Implementar retenção e rotação de backups',
                        'Usar serviços gerenciados de backup'
                    ]
                })
            
            elif category == 'config':
                recommendations.append({
                    'priority': 'ALTA',
                    'title': 'Arquivos de Configuração',
                    'description': f'{count} arquivo(s) de configuração sensíveis.',
                    'actions': [
                        'Remover arquivos .env, config.ini de repositórios públicos',
                        'Usar sistemas de configuração gerenciada',
                        'Separar configurações por ambiente (dev/staging/prod)',
                        'Nunca commitar arquivos de configuração no Git'
                    ]
                })
            
            elif category == 'backups':
                recommendations.append({
                    'priority': 'ALTA',
                    'title': 'Gestão de Backups',
                    'description': f'{count} arquivo(s) de backup expostos.',
                    'actions': [
                        'Mover backups para buckets privados com versionamento',
                        'Criptografar backups com KMS',
                        'Implementar políticas de lifecycle',
                        'Restringir acesso apenas a contas autorizadas'
                    ]
                })
            
            elif category == 'keys':
                recommendations.append({
                    'priority': 'CRÍTICA',
                    'title': 'Chaves Criptográficas',
                    'description': f'{count} chave(s) privada(s) exposta(s).',
                    'actions': [
                        'Revogar chaves comprometidas imediatamente',
                        'Gerar novos pares de chaves',
                        'Usar HSM (Hardware Security Module) para chaves sensíveis',
                        'Implementar rotação automática de certificados'
                    ]
                })
        
        # Recomendações gerais de segurança
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Implementar Controles Preventivos',
            'description': 'Estabelecer controles para prevenir exposições futuras.',
            'actions': [
                'Configurar políticas de bucket/container como privado por padrão',
                'Implementar scanning automatizado em CI/CD',
                'Treinar equipe em práticas de segurança',
                'Estabelecer processo de code review',
                'Implementar DLP (Data Loss Prevention)',
                'Criar runbooks de resposta a incidentes'
            ]
        })
        
        recommendations.append({
            'priority': 'MÉDIA',
            'title': 'Monitoramento Contínuo',
            'description': 'Estabelecer monitoramento e alertas de segurança.',
            'actions': [
                'Ativar logging de acesso ao storage',
                'Configurar alertas para acessos não autorizados',
                'Implementar SIEM para análise de logs',
                'Realizar auditorias de segurança regulares',
                'Monitorar tentativas de acesso suspeitas'
            ]
        })
        
        return recommendations
    
    def generate_pdf(self) -> str:
        """Gera relatório em PDF com vulnerabilidades e recomendações"""
        filename = f"relatorio_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.pdf"
        filepath = self.output_dir / filename
        
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=30
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # Estilos personalizados
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        )
        
        priority_critical = ParagraphStyle(
            'PriorityCritical',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold'
        )
        
        # Título
        story.append(Paragraph("🔒 RELATÓRIO DE SEGURANÇA", title_style))
        story.append(Paragraph("Auditoria de Storage Multicloud", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Informações do Cliente
        if self.client_info.get('name'):
            story.append(Paragraph("INFORMAÇÕES DO CLIENTE", heading_style))
            client_data = [
                ['Cliente:', self.client_info.get('name', '-')],
                ['Contato:', self.client_info.get('contact', '-')],
                ['Data do Relatório:', datetime.now().strftime("%d/%m/%Y %H:%M")]
            ]
            client_table = Table(client_data, colWidths=[1.5*inch, 4.5*inch])
            client_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(client_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Resumo Executivo
        story.append(Paragraph("RESUMO EXECUTIVO", heading_style))
        
        provider = self.scan_data.get('provider', 'N/A')
        bucket = self.scan_data.get('bucket', 'N/A')
        risk_score = self.scan_data.get('risk_score', 0)
        total_files = len(self.scan_data.get('files', []))
        
        summary_data = [
            ['Provider:', provider],
            ['Bucket/Container:', bucket],
            ['Total de Arquivos:', str(total_files)],
            ['Score de Risco:', f"{risk_score}%"],
            ['Nível de Risco:', self._get_risk_status(risk_score)]
        ]
        
        summary_table = Table(summary_data, colWidths=[1.5*inch, 4.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Distribuição de Severidade
        story.append(Paragraph("DISTRIBUIÇÃO DE SEVERIDADE", heading_style))
        
        severity_dist = self.scan_data.get('severity_distribution', {})
        severity_data = [
            ['Severidade', 'Quantidade', 'Percentual', 'Status'],
            ['🔴 CRITICAL', str(severity_dist.get('critical', 0)), 
             f"{self._calc_percent(severity_dist.get('critical', 0), total_files)}%",
             'AÇÃO IMEDIATA' if severity_dist.get('critical', 0) > 0 else '-'],
            ['🟠 HIGH', str(severity_dist.get('high', 0)),
             f"{self._calc_percent(severity_dist.get('high', 0), total_files)}%",
             'AÇÃO URGENTE' if severity_dist.get('high', 0) > 0 else '-'],
            ['🔵 MEDIUM', str(severity_dist.get('medium', 0)),
             f"{self._calc_percent(severity_dist.get('medium', 0), total_files)}%",
             'REVISAR' if severity_dist.get('medium', 0) > 0 else '-'],
            ['🟢 LOW', str(severity_dist.get('low', 0)),
             f"{self._calc_percent(severity_dist.get('low', 0), total_files)}%",
             'MONITORAR' if severity_dist.get('low', 0) > 0 else '-']
        ]
        
        severity_table = Table(severity_data, colWidths=[1.5*inch, 1.2*inch, 1.2*inch, 1.8*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')])
        ]))
        story.append(severity_table)
        story.append(PageBreak())
        
        # VULNERABILIDADES IDENTIFICADAS
        if self.vulnerabilities:
            story.append(Paragraph("⚠️ VULNERABILIDADES IDENTIFICADAS", heading_style))
            story.append(Spacer(1, 0.1*inch))
            
            for vuln in self.vulnerabilities:
                category_name = vuln['category'].replace('_', ' ').title()
                count = vuln['count']
                
                story.append(Paragraph(f"<b>{category_name}</b> ({count} arquivo(s))", styles['Normal']))
                story.append(Spacer(1, 0.05*inch))
                
                # Listar arquivos (máximo 10 por categoria)
                vuln_files_data = [['Arquivo', 'Tamanho', 'Severidade', 'Tipo']]
                for item in vuln['items'][:10]:
                    vuln_files_data.append([
                        item['file'][:40] + '...' if len(item['file']) > 40 else item['file'],
                        self._format_size(item['size']),
                        item['severity'],
                        item['type']
                    ])
                
                vuln_table = Table(vuln_files_data, colWidths=[2.2*inch, 0.8*inch, 0.9*inch, 1.8*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fee2e2')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#991b1b')),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('PADDING', (0, 0), (-1, -1), 5),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                story.append(vuln_table)
                story.append(Spacer(1, 0.15*inch))
                
                if len(vuln['items']) > 10:
                    story.append(Paragraph(f"<i>... e mais {len(vuln['items']) - 10} arquivo(s)</i>", styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            story.append(PageBreak())
        
        # RECOMENDAÇÕES
        story.append(Paragraph("✅ RECOMENDAÇÕES DE CORREÇÃO", heading_style))
        story.append(Spacer(1, 0.1*inch))
        
        for i, rec in enumerate(self.recommendations, 1):
            # Prioridade
            priority_color = {
                'CRÍTICA': colors.HexColor('#dc2626'),
                'ALTA': colors.HexColor('#ea580c'),
                'MÉDIA': colors.HexColor('#ca8a04')
            }.get(rec['priority'], colors.black)
            
            priority_text = f"<b><font color='#{priority_color.hexval()[2:]}'>[{rec['priority']}]</font> {rec['title']}</b>"
            story.append(Paragraph(priority_text, styles['Normal']))
            story.append(Spacer(1, 0.05*inch))
            
            # Descrição
            story.append(Paragraph(rec['description'], styles['Normal']))
            story.append(Spacer(1, 0.05*inch))
            
            # Ações
            story.append(Paragraph("<b>Ações Recomendadas:</b>", styles['Normal']))
            for action in rec['actions']:
                story.append(Paragraph(f"• {action}", styles['Normal']))
            
            story.append(Spacer(1, 0.15*inch))
        
        # Rodapé
        story.append(PageBreak())
        story.append(Spacer(1, 0.3*inch))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            f"Relatório gerado em {datetime.now().strftime('%d/%m/%Y às %H:%M')} | Security Multicloud Scanner v2.0<br/>Este relatório contém informações confidenciais e deve ser tratado como tal.",
            footer_style
        ))
        
        # Construir PDF
        doc.build(story)
        
        print(f"✅ PDF gerado: {filepath}")
        return str(filepath)
    
    def generate_docx(self) -> str:
        """Gera relatório em DOCX"""
        if not DOCX_AVAILABLE:
            return None
        
        filename = f"relatorio_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.docx"
        filepath = self.output_dir / filename
        
        doc = Document()
        
        # Título
        title = doc.add_heading('🔒 RELATÓRIO DE SEGURANÇA', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        subtitle = doc.add_paragraph('Auditoria de Storage Multicloud')
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Cliente
        if self.client_info.get('name'):
            doc.add_heading('INFORMAÇÕES DO CLIENTE', level=1)
            doc.add_paragraph(f"Cliente: {self.client_info.get('name')}")
            doc.add_paragraph(f"Contato: {self.client_info.get('contact')}")
            doc.add_paragraph(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        
        # Resumo
        doc.add_heading('RESUMO EXECUTIVO', level=1)
        doc.add_paragraph(f"Provider: {self.scan_data.get('provider', 'N/A')}")
        doc.add_paragraph(f"Bucket: {self.scan_data.get('bucket', 'N/A')}")
        doc.add_paragraph(f"Arquivos: {len(self.scan_data.get('files', []))}")
        doc.add_paragraph(f"Risco: {self.scan_data.get('risk_score', 0)}%")
        
        # Vulnerabilidades
        if self.vulnerabilities:
            doc.add_heading('VULNERABILIDADES', level=1)
            for vuln in self.vulnerabilities:
                doc.add_heading(f"{vuln['category'].replace('_', ' ').title()} ({vuln['count']} arquivos)", level=2)
                for item in vuln['items'][:10]:
                    doc.add_paragraph(f"• {item['file']} - {item['severity']}", style='List Bullet')
        
        # Recomendações
        doc.add_heading('RECOMENDAÇÕES', level=1)
        for rec in self.recommendations:
            doc.add_heading(f"[{rec['priority']}] {rec['title']}", level=2)
            doc.add_paragraph(rec['description'])
            for action in rec['actions']:
                doc.add_paragraph(f"• {action}", style='List Bullet')
        
        doc.save(str(filepath))
        print(f"✅ DOCX gerado: {filepath}")
        return str(filepath)
    
    def _get_risk_status(self, risk_score: int) -> str:
        if risk_score >= 75:
            return "🔴 CRÍTICO"
        elif risk_score >= 50:
            return "🟠 ALTO"
        elif risk_score >= 25:
            return "🔵 MÉDIO"
        else:
            return "🟢 BAIXO"
    
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
    """Função principal para gerar relatórios"""
    generator = ReportGenerator(scan_data, client_info)
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
