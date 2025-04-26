from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField
from werkzeug.utils import secure_filename
import os
import uuid
import pandas as pd
import datetime
import logging
import json
from scapy.all import rdpcap, IP

from app import db
from models import Scan, TrafficStatistics

logger = logging.getLogger(__name__)
pcap_bp = Blueprint('pcap', __name__)

class UploadPcapForm(FlaskForm):
    pcap_file = FileField('PCAP File', validators=[
        FileRequired(),
        FileAllowed(['pcap', 'pcapng'], 'PCAP files only!')
    ])
    submit = SubmitField('Upload and Analyze')

@pcap_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadPcapForm()
    
    if form.validate_on_submit():
        # Save the uploaded file
        f = form.pcap_file.data
        original_filename = secure_filename(f.filename)
        
        # Generate unique filename
        unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            f.save(file_path)
            logger.info(f"File saved: {file_path}")
            
            # Create a new scan record
            scan = Scan(
                user_id=current_user.id,
                filename=unique_filename,
                original_filename=original_filename,
                status='processing'
            )
            
            db.session.add(scan)
            db.session.commit()
            
            # Redirect to the analysis page
            return redirect(url_for('pcap.analyze', scan_id=scan.id))
            
        except Exception as e:
            logger.error(f"Error saving file: {str(e)}")
            flash('An error occurred while uploading the file.', 'danger')
    
    return render_template('upload.html', form=form)

@pcap_bp.route('/analyze/<int:scan_id>')
@login_required
def analyze(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to analyze this scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if scan is already processed
    if scan.status == 'completed':
        return redirect(url_for('pcap.results', scan_id=scan.id))
    
    # Process the PCAP file
    try:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], scan.filename)
        
        # Basic processing to show on analysis page
        packets = rdpcap(file_path)
        scan.total_packets = len(packets)
        
        # Extract basic statistics for visualization
        process_pcap_statistics(packets, scan)
        
        # Update scan status
        scan.status = 'analyzed'
        db.session.commit()
        
        # Pass to anomaly detection
        return redirect(url_for('detector.detect_anomalies', scan_id=scan.id))
        
    except Exception as e:
        scan.status = 'failed'
        db.session.commit()
        logger.error(f"Error analyzing PCAP file: {str(e)}")
        flash('An error occurred while analyzing the file.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('analysis.html', scan=scan)

@pcap_bp.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to view this scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get statistics for this scan
    stats = TrafficStatistics.query.filter_by(scan_id=scan_id).first()
    
    return render_template('results.html', scan=scan, stats=stats)

def process_pcap_statistics(packets, scan):
    """Process PCAP file and extract statistics for visualization"""
    
    # Initialize counters
    protocol_counts = {}
    port_counts = {}
    packet_sizes = []
    timestamps = []
    
    for packet in packets:
        try:
            # Extract packet timestamp - convert to float first to avoid EDecimal issue
            packet_time = float(packet.time)
            timestamp = datetime.datetime.fromtimestamp(packet_time)
            timestamps.append(timestamp)
            
            # Extract packet size
            packet_sizes.append(len(packet))
            
            # Extract protocol information if it's an IP packet
            if IP in packet:
                protocol = packet[IP].proto
                protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, str(protocol))
                
                protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                
                # Extract port information for TCP/UDP
                if protocol_name in ['TCP', 'UDP']:
                    if hasattr(packet, 'sport'):
                        src_port = packet.sport
                        port_counts[f"{src_port}"] = port_counts.get(f"{src_port}", 0) + 1
                    if hasattr(packet, 'dport'):
                        dst_port = packet.dport
                        port_counts[f"{dst_port}"] = port_counts.get(f"{dst_port}", 0) + 1
        except Exception as e:
            logger.warning(f"Error processing packet: {str(e)}")
            continue
    
    # Prepare time distribution data - group by hour
    time_distrib = {}
    for ts in timestamps:
        hour = ts.strftime("%Y-%m-%d %H:00")
        time_distrib[hour] = time_distrib.get(hour, 0) + 1
    
    # Calculate packet size statistics
    if packet_sizes:
        packet_size_stats = {
            'min': min(packet_sizes),
            'max': max(packet_sizes),
            'avg': sum(packet_sizes) / len(packet_sizes),
            'distribution': {}
        }
        
        # Group packet sizes for visualization
        for size in packet_sizes:
            # Group into ranges of 100 bytes
            size_range = f"{(size // 100) * 100}-{(size // 100 + 1) * 100}"
            packet_size_stats['distribution'][size_range] = packet_size_stats['distribution'].get(size_range, 0) + 1
    else:
        packet_size_stats = {'min': 0, 'max': 0, 'avg': 0, 'distribution': {}}
    
    # Store statistics in the database
    traffic_stats = TrafficStatistics(
        scan_id=scan.id,
        protocol_distribution=json.dumps(protocol_counts),
        port_distribution=json.dumps(dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])),
        packet_size_stats=json.dumps(packet_size_stats),
        time_distribution=json.dumps(time_distrib)
    )
    
    db.session.add(traffic_stats)
    db.session.commit()
    
    return traffic_stats
