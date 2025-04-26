import os
import logging
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, login_required, current_user
import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with declarative base
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///iot_traffic_analyzer.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure file upload settings
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload size
app.config["UPLOAD_FOLDER"] = "uploads"
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# Initialize SQLAlchemy with the app
db.init_app(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"

# Add custom template filters
@app.template_filter('tojson')
def to_json(value):
    import json
    return json.dumps(value)

@app.template_filter('fromjson')
def from_json(value):
    import json
    try:
        return json.loads(value)
    except:
        return {}

# Add jinja2 custom template functions
@app.context_processor
def inject_now():
    return {'now': datetime.datetime.now}

with app.app_context():
    # Import models and create tables
    import models
    db.create_all()
    
    # Import routes
    from auth import auth_bp
    from pcap_parser import pcap_bp
    from anomaly_detector import detector_bp
    from ip_blocker import blocker_bp
    from report_generator import reports_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(pcap_bp)
    app.register_blueprint(detector_bp)
    app.register_blueprint(blocker_bp)
    app.register_blueprint(reports_bp)
    
    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))
    
    # Import routes that depend on the app
    import routes  # noqa

# Create error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

# Add delete scan route
@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    from models import Scan
    import os
    
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to delete this scan.', 'danger')
        return redirect(url_for('history'))
    
    try:
        # Delete associated file if it exists
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], scan.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Delete scan from database (cascade will delete related anomalies)
        db.session.delete(scan)
        db.session.commit()
        
        flash('Scan has been successfully deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting scan: {str(e)}")
        flash('An error occurred while deleting the scan.', 'danger')
    
    return redirect(url_for('history'))

# Add block all IPs route
@app.route('/block_all_ips/<int:scan_id>', methods=['POST'])
@login_required
def block_all_ips(scan_id):
    from models import Scan, AnomalyResult, BlockedIP
    
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the user owns this scan
    if scan.user_id != current_user.id:
        flash('You do not have permission to modify this scan.', 'danger')
        return redirect(url_for('view_scan', scan_id=scan_id))
    
    # Get all anomalies from this scan that are not already blocked
    anomalies = AnomalyResult.query.filter_by(
        scan_id=scan_id, 
        is_anomaly=True, 
        is_blocked=False
    ).all()
    
    blocked_count = 0
    
    for anomaly in anomalies:
        # Check if IP is already blocked
        existing = BlockedIP.query.filter_by(ip_address=anomaly.source_ip).first()
        if not existing:
            # Create new blocked IP record
            blocked_ip = BlockedIP(
                ip_address=anomaly.source_ip,
                reason=f"Automatically blocked from scan #{scan.id} as part of bulk action",
                blocked_by=current_user.id
            )
            
            db.session.add(blocked_ip)
            
            # Update anomaly record
            anomaly.is_blocked = True
            blocked_count += 1
    
    try:
        if blocked_count > 0:
            scan.blocked_ips += blocked_count
            db.session.commit()
            flash(f'Successfully blocked {blocked_count} IP addresses.', 'success')
        else:
            flash('No new IP addresses to block.', 'info')
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error blocking IPs: {str(e)}")
        flash('An error occurred while blocking the IP addresses.', 'danger')
    
    return redirect(url_for('pcap.results', scan_id=scan_id))
