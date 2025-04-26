import os
import uuid
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

def ensure_dir_exists(directory):
    """Ensure the given directory exists"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        logger.info(f"Created directory: {directory}")

def generate_unique_filename(original_filename):
    """Generate a unique filename while preserving the original extension"""
    ext = os.path.splitext(original_filename)[1]
    return f"{uuid.uuid4().hex}{ext}"

def format_datetime(dt):
    """Format datetime for display"""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    
    return str(dt)

def format_bytes(size):
    """Format byte size to human-readable format"""
    power = 2**10  # 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    
    while size > power and n < len(power_labels) - 1:
        size /= power
        n += 1
    
    return f"{size:.2f} {power_labels[n]}"

def parse_json_field(json_str):
    """Safely parse a JSON string field from the database"""
    if not json_str:
        return {}
    
    try:
        return json.loads(json_str)
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return {}

def get_protocol_name(protocol_num):
    """Convert protocol number to name"""
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }
    return protocol_map.get(protocol_num, f"Protocol {protocol_num}")

def is_valid_ip(ip):
    """Simple validation for IPv4 addresses"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
    except ValueError:
        return False
    
    return True
