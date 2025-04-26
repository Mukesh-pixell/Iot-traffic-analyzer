from flask import Blueprint, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
import os
import pandas as pd
import numpy as np
import json
import pickle
import logging
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app import db
from models import Scan, AnomalyResult

logger = logging.getLogger(__name__)
detector_bp = Blueprint('detector', __name__)

@detector_bp.route('/detect/<int:scan_id>')
@login_required
def detect_anomalies(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to analyze this scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if scan is ready for anomaly detection
    if scan.status != 'analyzed':
        flash('Scan must be analyzed before detecting anomalies.', 'danger')
        return redirect(url_for('pcap.analyze', scan_id=scan.id))
    
    try:
        # Get the path to the PCAP file
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], scan.filename)
        
        # Convert PCAP to structured data
        features_df = extract_features_from_pcap(file_path)
        
        # Detect anomalies
        anomalies = detect_anomalies_in_data(features_df, scan)
        
        # Update scan status
        scan.status = 'completed'
        scan.anomalies_detected = len([a for a in anomalies if a.is_anomaly])
        db.session.commit()
        
        flash(f'Analysis complete! Found {scan.anomalies_detected} potential anomalies.', 'success')
        return redirect(url_for('pcap.results', scan_id=scan.id))
        
    except Exception as e:
        scan.status = 'failed'
        db.session.commit()
        logger.error(f"Error detecting anomalies: {str(e)}")
        flash('An error occurred during anomaly detection.', 'danger')
        return redirect(url_for('dashboard'))

def extract_features_from_pcap(pcap_file):
    """Extract features from PCAP file for anomaly detection"""
    try:
        packets = rdpcap(pcap_file)
        
        # Prepare data structures for feature extraction
        packet_features = []
        
        # Process each packet
        for packet in packets:
            try:
                if IP in packet:
                    features = {}
                    
                    # Basic IP features
                    features['src_ip'] = str(packet[IP].src)
                    features['dst_ip'] = str(packet[IP].dst)
                    features['protocol'] = int(packet[IP].proto)
                    features['ttl'] = int(packet[IP].ttl)
                    features['packet_size'] = int(len(packet))
                    
                    # Convert packet time to float to avoid EDecimal issues
                    try:
                        packet_time = float(packet.time)
                        features['timestamp'] = datetime.fromtimestamp(packet_time)
                    except (ValueError, TypeError) as e:
                        # Use current time if packet time is invalid
                        logger.warning(f"Invalid packet time: {e}. Using current time.")
                        features['timestamp'] = datetime.now()
                    
                    # Protocol-specific features
                    if TCP in packet:
                        features['src_port'] = int(packet[TCP].sport)
                        features['dst_port'] = int(packet[TCP].dport)
                        
                        # Handle TCP flags - convert to integer safely
                        try:
                            tcp_flags = packet[TCP].flags
                            # Directly use string representation which converts to int
                            features['tcp_flags'] = int(str(tcp_flags).replace('FlagValue', '').strip())
                        except (ValueError, TypeError, AttributeError):
                            # Default value if conversion fails
                            features['tcp_flags'] = 0
                            
                        # Handle TCP window
                        try:
                            features['tcp_window'] = int(packet[TCP].window)
                        except (ValueError, TypeError, AttributeError):
                            features['tcp_window'] = 0
                            
                    elif UDP in packet:
                        features['src_port'] = int(packet[UDP].sport)
                        features['dst_port'] = int(packet[UDP].dport)
                        
                        # Handle UDP length
                        try:
                            features['udp_len'] = int(packet[UDP].len)
                        except (ValueError, TypeError, AttributeError):
                            features['udp_len'] = 0
                    else:
                        features['src_port'] = 0
                        features['dst_port'] = 0
                    
                    packet_features.append(features)
            except Exception as e:
                logger.warning(f"Error processing packet in anomaly detector: {str(e)}")
                continue
    
        if not packet_features:
            logger.warning("No valid packets found in the PCAP file")
            # Create a minimal default packet to prevent DataFrame errors
            packet_features.append({
                'src_ip': '0.0.0.0',
                'dst_ip': '0.0.0.0',
                'protocol': 0,
                'ttl': 0,
                'packet_size': 0,
                'timestamp': datetime.now(),
                'src_port': 0,
                'dst_port': 0
            })
    except Exception as e:
        logger.error(f"Error reading PCAP file: {str(e)}")
        # Create a minimal default packet to prevent DataFrame errors
        packet_features.append({
            'src_ip': '0.0.0.0',
            'dst_ip': '0.0.0.0',
            'protocol': 0,
            'ttl': 0,
            'packet_size': 0,
            'timestamp': datetime.now(),
            'src_port': 0,
            'dst_port': 0
        })
    
    # Convert to DataFrame
    df = pd.DataFrame(packet_features)
    
    # Handle missing values
    numeric_cols = ['ttl', 'packet_size', 'src_port', 'dst_port']
    df[numeric_cols] = df[numeric_cols].fillna(0)
    
    # Add derived features
    if 'tcp_flags' in df.columns:
        df['tcp_flags'] = df['tcp_flags'].fillna(0)
    if 'tcp_window' in df.columns:
        df['tcp_window'] = df['tcp_window'].fillna(0)
    if 'udp_len' in df.columns:
        df['udp_len'] = df['udp_len'].fillna(0)
    
    # Convert protocol to numeric
    protocol_map = {1: 1, 6: 2, 17: 3}  # ICMP, TCP, UDP
    df['protocol_num'] = df['protocol'].map(lambda x: protocol_map.get(x, 0))
    
    return df

def detect_anomalies_in_data(df, scan):
    """Detect anomalies in the extracted features using Isolation Forest"""
    anomaly_results = []
    
    try:
        # Select numerical features for anomaly detection
        numeric_features = ['ttl', 'packet_size', 'protocol_num']
        
        # Add TCP/UDP features if available
        if 'tcp_flags' in df.columns:
            numeric_features.append('tcp_flags')
        if 'tcp_window' in df.columns:
            numeric_features.append('tcp_window')
        if 'udp_len' in df.columns:
            numeric_features.append('udp_len')
        
        numeric_features.extend(['src_port', 'dst_port'])
        
        # Prepare feature matrix
        X = df[numeric_features].copy()
        
        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Fit Isolation Forest model
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # Assume 5% of traffic may be anomalous
            random_state=42
        )
        
        # Get anomaly scores (-1 for anomalies, 1 for normal)
        y_pred = model.fit_predict(X_scaled)
        anomaly_scores = model.score_samples(X_scaled)
        
        # Create anomaly result records
        for i, (_, row) in enumerate(df.iterrows()):
            is_anomaly = y_pred[i] == -1
            score = anomaly_scores[i]
            
            # Create result object
            result = AnomalyResult(
                scan_id=scan.id,
                source_ip=row['src_ip'],
                destination_ip=row['dst_ip'],
                protocol=str({1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(row['protocol'], row['protocol'])),
                timestamp=row['timestamp'],
                anomaly_score=float(score),
                is_anomaly=is_anomaly,
                details=json.dumps({
                    'src_port': int(row['src_port']),
                    'dst_port': int(row['dst_port']),
                    'ttl': int(row['ttl']),
                    'packet_size': int(row['packet_size'])
                })
            )
            
            anomaly_results.append(result)
            db.session.add(result)
        
        db.session.commit()
        return anomaly_results
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in anomaly detection: {str(e)}")
        raise
