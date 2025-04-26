from flask import Blueprint, render_template, make_response, redirect, url_for, flash
from flask_login import login_required, current_user
import io
import json
from datetime import datetime
import logging
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app import db
from models import Scan, AnomalyResult, TrafficStatistics

logger = logging.getLogger(__name__)
reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/report/<int:scan_id>')
@login_required
def generate_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to view this report.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get anomalies for this scan
    anomalies = AnomalyResult.query.filter_by(scan_id=scan_id).all()
    
    # Get traffic statistics
    stats = TrafficStatistics.query.filter_by(scan_id=scan_id).first()
    
    # For HTML report preview
    return render_template('report.html', scan=scan, anomalies=anomalies, stats=stats)

@reports_bp.route('/report/<int:scan_id>/pdf')
@login_required
def download_pdf_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to download this report.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get anomalies for this scan
    anomalies = AnomalyResult.query.filter_by(scan_id=scan_id).all()
    anomaly_count = len([a for a in anomalies if a.is_anomaly])
    
    # Get traffic statistics
    stats = TrafficStatistics.query.filter_by(scan_id=scan_id).first()
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    # Container for elements to be added to the PDF
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Center', alignment=1))
    
    # Title
    title = f"Network Traffic Analysis Report - Scan #{scan.id}"
    elements.append(Paragraph(title, styles['Title']))
    elements.append(Spacer(1, 12))
    
    # Scan Information
    elements.append(Paragraph("Scan Information", styles['Heading2']))
    elements.append(Spacer(1, 6))
    
    scan_info = [
        ["Original Filename", scan.original_filename],
        ["Date/Time", scan.created_at.strftime("%Y-%m-%d %H:%M:%S")],
        ["Status", scan.status],
        ["Total Packets", str(scan.total_packets)],
        ["Anomalies Detected", str(anomaly_count)]
    ]
    
    scan_table = Table(scan_info, colWidths=[120, 350])
    scan_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    
    elements.append(scan_table)
    elements.append(Spacer(1, 12))
    
    # Traffic Statistics
    if stats:
        elements.append(Paragraph("Traffic Statistics", styles['Heading2']))
        elements.append(Spacer(1, 6))
        
        # Protocol Distribution
        elements.append(Paragraph("Protocol Distribution", styles['Heading3']))
        protocol_dist = json.loads(stats.protocol_distribution)
        protocol_data = [["Protocol", "Count"]]
        for proto, count in protocol_dist.items():
            protocol_data.append([proto, str(count)])
        
        protocol_table = Table(protocol_data, colWidths=[200, 200])
        protocol_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        
        elements.append(protocol_table)
        elements.append(Spacer(1, 12))
    
    # Anomalies
    if anomalies:
        elements.append(Paragraph("Detected Anomalies", styles['Heading2']))
        elements.append(Spacer(1, 6))
        
        # Only include actual anomalies
        anomaly_data = [["Source IP", "Destination IP", "Protocol", "Anomaly Score", "Blocked"]]
        for anomaly in anomalies:
            if anomaly.is_anomaly:
                anomaly_data.append([
                    anomaly.source_ip,
                    anomaly.destination_ip,
                    anomaly.protocol,
                    f"{anomaly.anomaly_score:.4f}",
                    "Yes" if anomaly.is_blocked else "No"
                ])
        
        if len(anomaly_data) > 1:  # If we have actual anomalies
            anomaly_table = Table(anomaly_data, colWidths=[100, 100, 80, 80, 60])
            anomaly_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            
            elements.append(anomaly_table)
        else:
            elements.append(Paragraph("No anomalies detected in this scan.", styles['Normal']))
    
    # Conclusion
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Conclusion", styles['Heading2']))
    elements.append(Spacer(1, 6))
    
    conclusion_text = f"""
    This report presents the analysis of network traffic data captured on {scan.created_at.strftime("%Y-%m-%d")}.
    The analysis identified {anomaly_count} potential anomalies in the network traffic.
    """
    if anomaly_count > 0:
        conclusion_text += " It is recommended to investigate these anomalies further and take appropriate action."
    else:
        conclusion_text += " No abnormal traffic patterns were detected in this scan."
    
    elements.append(Paragraph(conclusion_text, styles['Normal']))
    
    # Build the PDF
    doc.build(elements)
    
    # Prepare response
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=report_scan_{scan_id}.pdf'
    
    return response
