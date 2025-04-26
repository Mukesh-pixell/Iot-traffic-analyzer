from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, IPAddress
import logging

from app import db
from models import BlockedIP, AnomalyResult

logger = logging.getLogger(__name__)
blocker_bp = Blueprint('blocker', __name__)

class BlockIPForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    submit = SubmitField('Block IP')

@blocker_bp.route('/block_ip', methods=['GET', 'POST'])
@login_required
def block_ip():
    form = BlockIPForm()
    
    if form.validate_on_submit():
        ip_address = form.ip_address.data
        
        # Check if IP is already blocked
        existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
        if existing:
            flash(f'IP {ip_address} is already blocked.', 'warning')
            return redirect(url_for('blocker.blocked_ips'))
        
        # Create new blocked IP record
        blocked_ip = BlockedIP(
            ip_address=ip_address,
            reason=form.reason.data,
            blocked_by=current_user.id
        )
        
        try:
            db.session.add(blocked_ip)
            db.session.commit()
            
            # Update any existing anomaly records with this IP
            update_anomaly_records(ip_address)
            
            flash(f'IP {ip_address} has been blocked successfully.', 'success')
            return redirect(url_for('blocker.blocked_ips'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error blocking IP: {str(e)}")
            flash('An error occurred while blocking the IP.', 'danger')
    
    return render_template('block_ip.html', form=form)

@blocker_bp.route('/block_from_anomaly/<int:anomaly_id>', methods=['POST'])
@login_required
def block_from_anomaly(anomaly_id):
    anomaly = AnomalyResult.query.get_or_404(anomaly_id)
    
    # Verify user has permission
    if anomaly.scan.user_id != current_user.id:
        flash('You do not have permission to block this IP.', 'danger')
        return redirect(url_for('dashboard'))
    
    ip_address = anomaly.source_ip
    
    # Check if already blocked
    existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if existing:
        flash(f'IP {ip_address} is already blocked.', 'warning')
        return redirect(url_for('pcap.results', scan_id=anomaly.scan_id))
    
    # Create blocked IP record
    blocked_ip = BlockedIP(
        ip_address=ip_address,
        reason=f"Blocked due to detected anomaly in scan #{anomaly.scan_id}",
        blocked_by=current_user.id
    )
    
    try:
        db.session.add(blocked_ip)
        db.session.commit()
        
        # Update anomaly record
        anomaly.is_blocked = True
        db.session.commit()
        
        # Update any other anomaly records with this IP
        update_anomaly_records(ip_address)
        
        flash(f'IP {ip_address} has been blocked successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error blocking IP: {str(e)}")
        flash('An error occurred while blocking the IP.', 'danger')
    
    return redirect(url_for('pcap.results', scan_id=anomaly.scan_id))

@blocker_bp.route('/blocked_ips')
@login_required
def blocked_ips():
    blocked = BlockedIP.query.filter_by(blocked_by=current_user.id).all()
    return render_template('blocked_ips.html', blocked_ips=blocked)

@blocker_bp.route('/unblock_ip/<int:ip_id>', methods=['POST'])
@login_required
def unblock_ip(ip_id):
    ip = BlockedIP.query.get_or_404(ip_id)
    
    # Ensure the user owns this blocked IP
    if ip.blocked_by != current_user.id:
        flash('You do not have permission to unblock this IP.', 'danger')
        return redirect(url_for('blocker.blocked_ips'))
    
    ip_address = ip.ip_address
    
    try:
        # Update anomaly records
        anomalies = AnomalyResult.query.filter(
            (AnomalyResult.source_ip == ip_address) | 
            (AnomalyResult.destination_ip == ip_address)
        ).all()
        
        for anomaly in anomalies:
            anomaly.is_blocked = False
        
        # Delete blocked IP record
        db.session.delete(ip)
        db.session.commit()
        
        flash(f'IP {ip_address} has been unblocked.', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error unblocking IP: {str(e)}")
        flash('An error occurred while unblocking the IP.', 'danger')
    
    return redirect(url_for('blocker.blocked_ips'))

def update_anomaly_records(ip_address):
    """Update all anomaly records associated with the blocked IP"""
    anomalies = AnomalyResult.query.filter(
        (AnomalyResult.source_ip == ip_address) | 
        (AnomalyResult.destination_ip == ip_address)
    ).all()
    
    for anomaly in anomalies:
        anomaly.is_blocked = True
    
    db.session.commit()
