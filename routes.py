from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
import logging
from app import app, db
from models import Scan, AnomalyResult, BlockedIP

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.created_at.desc()).limit(5).all()
    
    # Count total scans, anomalies, and blocked IPs for the user
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    
    total_anomalies = db.session.query(db.func.sum(Scan.anomalies_detected))\
        .filter(Scan.user_id == current_user.id).scalar() or 0
    
    total_blocked = BlockedIP.query.filter_by(blocked_by=current_user.id).count()
    
    # Get data for summary charts
    scan_stats = {
        'total_scans': total_scans,
        'total_anomalies': total_anomalies,
        'total_blocked': total_blocked
    }
    
    return render_template('dashboard.html', 
                          recent_scans=recent_scans,
                          scan_stats=scan_stats)

@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get paginated scan history
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('history.html', scans=scans)

@app.route('/view_scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to view this scan.', 'danger')
        return redirect(url_for('history'))
    
    # Get all anomalies from this scan
    anomalies = AnomalyResult.query.filter_by(scan_id=scan_id).all()
    
    return render_template('results.html', scan=scan, anomalies=anomalies)

@app.route('/blocked_ips')
@login_required
def blocked_ips():
    blocked = BlockedIP.query.filter_by(blocked_by=current_user.id).all()
    return render_template('blocked_ips.html', blocked_ips=blocked)

@app.route('/unblock_ip/<int:ip_id>', methods=['POST'])
@login_required
def unblock_ip(ip_id):
    ip = BlockedIP.query.get_or_404(ip_id)
    
    # Ensure the user owns this blocked IP
    if ip.blocked_by != current_user.id:
        flash('You do not have permission to unblock this IP.', 'danger')
        return redirect(url_for('blocked_ips'))
    
    try:
        db.session.delete(ip)
        db.session.commit()
        flash(f'IP {ip.ip_address} has been unblocked.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error unblocking IP: {str(e)}")
        flash('An error occurred while unblocking the IP.', 'danger')
    
    return redirect(url_for('blocked_ips'))
