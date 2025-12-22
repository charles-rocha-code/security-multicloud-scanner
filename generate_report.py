"""
generate_report.py - Gerador de Relatórios Executivos
Gera relatórios profissionais em PDF e DOCX
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from pathlib import Path

# Para DOCX
try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


class ReportGenerator:
    """Gerador de relatórios executivos"""
    
    def __init__(self, scan_data: dict, client_info: dict = None):
        self.scan_data = scan_data
        self.client_info = client_info or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Criar diretório de saída
        self.output_dir = Path("./reports_executive")
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_pdf(self) -> str:
        """Gera relatório em PDF"""
        filename = f"relatorio_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.pdf"
        filepath = self.output_dir / filename
        
        doc = SimpleDocTemplate(str(filepath), pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        story = []
        styles = getSampleStyleSheet()
        
        # Título
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#1e3a8a'), spaceAfter=30, alignment=TA_CENTER)
        story.append(Paragraph("📊 RELATÓRIO DE AUDITORIA", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Cliente
        if self.client_info.get('name'):
            story.append(Paragraph(f"<b>Cliente:</b> {self.client_info.get('name')}", styles['Normal']))
            story.append(Paragraph(f"<b>Contato:</b> {self.client_info.get('contact')}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Resumo
        story.append(Paragraph("<b>RESUMO EXECUTIVO</b>", styles['Heading2']))
        summary_data = [
            ['Provider:', self.scan_data.get('provider', 'N/A')],
            ['Bucket:', self.scan_data.get('bucket', 'N/A')],
            ['Arquivos:', str(len(self.scan_data.get('files', [])))],
            ['Risco:', f"{self.scan_data.get('risk_score', 0)}%"]
        ]
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e5e7eb')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('PADDING', (0, 0), (-1, -1), 8)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Severidade
        story.append(Paragraph("<b>DISTRIBUIÇÃO</b>", styles['Heading2']))
        severity_dist = self.scan_data.get('severity_distribution', {})
        total = len(self.scan_data.get('files', []))
        severity_data = [
            ['Severidade', 'Quantidade', '%'],
            ['CRITICAL', str(severity_dist.get('critical', 0)), f"{self._calc_percent(severity_dist.get('critical', 0), total)}%"],
            ['HIGH', str(severity_dist.get('high', 0)), f"{self._calc_percent(severity_dist.get('high', 0), total)}%"],
            ['MEDIUM', str(severity_dist.get('medium', 0)), f"{self._calc_percent(severity_dist.get('medium', 0), total)}%"],
            ['LOW', str(severity_dist.get('low', 0)), f"{self._calc_percent(severity_dist.get('low', 0), total)}%"]
        ]
        severity_table = Table(severity_data, colWidths=[2*inch, 2*inch, 2*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('PADDING', (0, 0), (-1, -1), 8)
        ]))
        story.append(severity_table)
        
        doc.build(story)
        print(f"✅ PDF: {filepath}")
        return str(filepath)
    
    def generate_docx(self) -> str:
        """Gera relatório em DOCX"""
        if not DOCX_AVAILABLE:
            return None
        
        filename = f"relatorio_{self.scan_data.get('bucket', 'scan')}_{self.timestamp}.docx"
        filepath = self.output_dir / filename
        
        doc = Document()
        title = doc.add_heading('📊 RELATÓRIO DE AUDITORIA', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        if self.client_info.get('name'):
            doc.add_paragraph(f"Cliente: {self.client_info.get('name')}")
            doc.add_paragraph(f"Contato: {self.client_info.get('contact')}")
        
        doc.add_heading('RESUMO', level=1)
        doc.add_paragraph(f"Provider: {self.scan_data.get('provider', 'N/A')}")
        doc.add_paragraph(f"Bucket: {self.scan_data.get('bucket', 'N/A')}")
        doc.add_paragraph(f"Arquivos: {len(self.scan_data.get('files', []))}")
        doc.add_paragraph(f"Risco: {self.scan_data.get('risk_score', 0)}%")
        
        doc.save(str(filepath))
        print(f"✅ DOCX: {filepath}")
        return str(filepath)
    
    def _calc_percent(self, value: int, total: int) -> str:
        if total == 0:
            return "0.0"
        return f"{(value / total * 100):.1f}"


def generate_executive_report(scan_data: dict, client_info: dict = None, output_format: str = 'both') -> dict:
    generator = ReportGenerator(scan_data, client_info)
    results = {}
    
    if output_format in ['pdf', 'both']:
        try:
            results['pdf'] = generator.generate_pdf()
        except Exception as e:
            print(f"❌ PDF erro: {e}")
            results['pdf_error'] = str(e)
    
    if output_format in ['docx', 'both'] and DOCX_AVAILABLE:
        try:
            results['docx'] = generator.generate_docx()
        except Exception as e:
            print(f"❌ DOCX erro: {e}")
    
    return results
