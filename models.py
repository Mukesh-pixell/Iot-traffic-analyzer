from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    original_filename = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')  # pending, processing, completed, failed
    total_packets = db.Column(db.Integer, default=0)
    anomalies_detected = db.Column(db.Integer, default=0)
    blocked_ips = db.Column(db.Integer, default=0)
    results = db.relationship('AnomalyResult', backref='scan', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Scan {self.id} by {self.user_id}>'

class AnomalyResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    is_anomaly = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    details = db.Column(db.Text)
    
    def __repr__(self):
        return f'<AnomalyResult {self.id} for scan {self.scan_id}>'

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'

class TrafficStatistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    protocol_distribution = db.Column(db.Text, nullable=False)  # JSON string
    port_distribution = db.Column(db.Text, nullable=False)  # JSON string
    packet_size_stats = db.Column(db.Text, nullable=False)  # JSON string
    time_distribution = db.Column(db.Text, nullable=False)  # JSON string
    
    def __repr__(self):
        return f'<TrafficStatistics for scan {self.scan_id}>'
