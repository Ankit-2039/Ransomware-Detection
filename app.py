"""
Flask + Socket.io Web Application for Ransomware Detection Dashboard
Real-time updates using efficient polling (NO MongoDB Change Streams needed)
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
from datetime import datetime
import logging
import threading
import time

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ransomware_detection_secret'
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=60, ping_interval=25)

# MongoDB Connection (NO Replica Set Required!)
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "ransomware_detection"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    db = client[DB_NAME]
    threat_collection = db["threat_logs"]
    monitor_collection = db["monitor_logs"]
    logger.info("✓ MongoDB connected successfully")
except Exception as e:
    logger.error(f"✗ MongoDB connection failed: {e}")
    threat_collection = None
    monitor_collection = None

# Track last known logs to detect new ones
last_threats = []
last_monitors = []

# ============= FETCH FUNCTIONS ============= #

def get_threat_logs():
    """Get all threat logs from MongoDB"""
    try:
        if threat_collection is None:
            return []
        return list(threat_collection.find({}, {'_id': 0}).sort('timestamp', -1))
    except Exception as e:
        logger.error(f"Error fetching threat logs: {e}")
        return []

def get_monitor_logs():
    """Get all monitor logs from MongoDB"""
    try:
        if monitor_collection is None:
            return []
        return list(monitor_collection.find({}, {'_id': 0}).sort('timestamp', -1))
    except Exception as e:
        logger.error(f"Error fetching monitor logs: {e}")
        return []

# ============= SMART POLLING (Efficient) ============= #

def detect_new_logs():
    """Poll for new logs efficiently - only detect changes"""
    global last_threats, last_monitors
    
    logger.info("Starting smart log polling (100ms interval)...")
    
    while True:
        try:
            current_threats = get_threat_logs()
            current_monitors = get_monitor_logs()
            
            # Detect NEW threats (compare with last check)
            if len(current_threats) > len(last_threats):
                # Find new threats (they're at the beginning due to sort -1)
                new_count = len(current_threats) - len(last_threats)
                new_threats = current_threats[:new_count]
                
                # Emit each new threat
                for threat in reversed(new_threats):  # Reverse to emit oldest first
                    logger.info(f"✓ New threat: {threat.get('file_path')}")
                    socketio.emit('new_threat_log', {'data': threat}, broadcast=True, namespace='/')
                
                last_threats = current_threats
            
            # Detect NEW monitors (compare with last check)
            if len(current_monitors) > len(last_monitors):
                # Find new monitors
                new_count = len(current_monitors) - len(last_monitors)
                new_monitors = current_monitors[:new_count]
                
                # Emit each new monitor
                for monitor in reversed(new_monitors):  # Reverse to emit oldest first
                    logger.info(f"✓ New file monitored: {monitor.get('file_path')}")
                    socketio.emit('new_monitor_log', {'data': monitor}, broadcast=True, namespace='/')
                
                last_monitors = current_monitors
            
            time.sleep(0.1)  # Poll every 100ms (very fast, minimal CPU)
            
        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(0.5)

def start_polling():
    """Start background polling thread"""
    thread = threading.Thread(target=detect_new_logs, daemon=True)
    thread.daemon = True
    thread.start()
    logger.info("✓ Smart polling started (100ms interval)")

# ============= ROUTES ============= #

@app.route('/')
def index():
    """Render dashboard"""
    return render_template('dashboard.html')

@app.route('/api/threat-logs', methods=['GET'])
def api_threat_logs():
    """API endpoint for threat logs"""
    return jsonify(get_threat_logs())

@app.route('/api/monitor-logs', methods=['GET'])
def api_monitor_logs():
    """API endpoint for monitor logs"""
    return jsonify(get_monitor_logs())

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """API endpoint for statistics"""
    threats = get_threat_logs()
    monitors = get_monitor_logs()
    
    stats = {
        'total_detections': len(threats),
        'total_monitored': len(monitors),
        'malware_detected': len(threats),
        'benign_detected': len([m for m in monitors if m.get('prediction') == 'legitimate'])
    }
    
    return jsonify(stats)

# ============= SOCKET EVENTS ============= #

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("✓ Client connected - sending initial data")
    
    global last_threats, last_monitors
    
    # Send initial data
    threats = get_threat_logs()
    monitors = get_monitor_logs()
    
    last_threats = threats
    last_monitors = monitors
    
    emit('update_threat_logs', {'data': threats})
    emit('update_monitor_logs', {'data': monitors})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("✓ Client disconnected")

@socketio.on('clear_threat_logs')
def handle_clear_threats():
    """Clear all threat logs"""
    try:
        if threat_collection is None:
            emit('error', {'message': 'Database not connected'})
            return
        
        threat_collection.delete_many({})
        logger.info("✓ Threat logs cleared")
        
        global last_threats
        last_threats = []
        
        socketio.emit('update_threat_logs', {'data': []}, broadcast=True, namespace='/')
        socketio.emit('notification', {'message': 'Threat logs cleared'}, broadcast=True, namespace='/')
    except Exception as e:
        logger.error(f"Error clearing threat logs: {e}")
        emit('error', {'message': str(e)})

@socketio.on('clear_monitor_logs')
def handle_clear_monitors():
    """Clear all monitor logs"""
    try:
        if monitor_collection is None:
            emit('error', {'message': 'Database not connected'})
            return
        
        monitor_collection.delete_many({})
        logger.info("✓ Monitor logs cleared")
        
        global last_monitors
        last_monitors = []
        
        socketio.emit('update_monitor_logs', {'data': []}, broadcast=True, namespace='/')
        socketio.emit('notification', {'message': 'Monitor logs cleared'}, broadcast=True, namespace='/')
    except Exception as e:
        logger.error(f"Error clearing monitor logs: {e}")
        emit('error', {'message': str(e)})

@socketio.on('download_threat_logs')
def handle_download_threats():
    """Trigger threat logs download"""
    threats = get_threat_logs()
    emit('trigger_download', {
        'data': threats,
        'filename': f"threat_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    })

@socketio.on('download_monitor_logs')
def handle_download_monitors():
    """Trigger monitor logs download"""
    monitors = get_monitor_logs()
    emit('trigger_download', {
        'data': monitors,
        'filename': f"monitor_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    })

# ============= RUN ============= #

if __name__ == '__main__':
    logger.info("="*60)
    logger.info("Starting Ransomware Detection Dashboard")
    logger.info("="*60)
    logger.info("MongoDB Mode: Standalone")
    start_polling()
    logger.info("✓ Dashboard ready at http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)