import os, csv, sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from flask import Flask, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow React frontend on Windows to call this API
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LOCAL_LOG_DIR = os.path.join(PROJECT_DIR, 'logs', 'detection')
HOME_LOG_DIR = os.path.join(os.path.expanduser('~/CN_CP'), 'logs', 'detection')

def get_log_file(filename):
    for d in [LOCAL_LOG_DIR, HOME_LOG_DIR]:
        p = os.path.join(d, filename)
        if os.path.exists(p):
            return p
    return os.path.join(LOCAL_LOG_DIR, filename)

DETECTION_CSV = get_log_file('detection_events.csv')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    detection_csv = get_log_file('detection_events.csv')
    if not os.path.exists(detection_csv):
        return jsonify({
            'status': 'NO_DATA',
            'latest': {
                'timestamp': 'N/A', 'iso_time': 'No logs yet', 'server_ip': '10.0.0.200',
                'packet_rate': 0.0, 'byte_rate': 0.0, 'active_flows': 0,
                'unique_sources': 0, 'traffic_concentration': 0.0, 'suspicion_score': 0,
                'consecutive_suspicious': 0, 'detection_status': 'BASELINE_COLLECTION',
                'reason': 'Waiting for controller statistics...'
            },
            'history': []
        })

    rows = []
    try:
        with open(detection_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append({
                    'timestamp': row.get('timestamp', ''),
                    'iso_time': row.get('iso_time', ''),
                    'server_ip': row.get('server_ip', '10.0.0.200'),
                    'packet_rate': float(row.get('packet_rate', 0.0)),
                    'byte_rate': float(row.get('byte_rate', 0.0)) / 1000.0,
                    'active_flows': int(row.get('active_flows', 0)),
                    'unique_sources': int(row.get('unique_sources', 0)),
                    'traffic_concentration': float(row.get('traffic_concentration', 0.0)),
                    'suspicion_score': int(row.get('suspicion_score', 0)),
                    'consecutive_suspicious': int(row.get('consecutive_suspicious', 0)),
                    'detection_status': row.get('detection_status', 'NORMAL'),
                    'reason': row.get('reason', '')
                })
    except Exception:
        pass

    # Deduplicate / merge rows that arrive in the same second by taking the higher packet rate
    # (Switch 2 connected to the target server carries the attack telemetry)
    merged_by_second = {}
    for r in rows:
        sec_key = r.get('iso_time', '')
        if not sec_key:
            continue
        if sec_key not in merged_by_second:
            merged_by_second[sec_key] = r
        else:
            existing = merged_by_second[sec_key]
            # Prioritize attack state or higher packet rate
            if (r['detection_status'] == 'DDOS_DETECTED' and existing['detection_status'] != 'DDOS_DETECTED') or \
               (r['detection_status'] == 'SUSPICIOUS' and existing['detection_status'] == 'NORMAL') or \
               (r['packet_rate'] > existing['packet_rate']):
                merged_by_second[sec_key] = r

    clean_rows = list(merged_by_second.values())

    if clean_rows:
        recent = clean_rows[-6:]
        attack_row = next((r for r in reversed(recent) if r['detection_status'] == 'DDOS_DETECTED'), None)
        suspicious_row = next((r for r in reversed(recent) if r['detection_status'] == 'SUSPICIOUS'), None)
        priority_row = attack_row or suspicious_row
        if priority_row:
            latest = dict(priority_row)
            latest['packet_rate'] = max(r['packet_rate'] for r in recent)
            latest['byte_rate'] = max(r['byte_rate'] for r in recent)
            latest['suspicion_score'] = max(r['suspicion_score'] for r in recent)
        else:
            latest = clean_rows[-1]
    else:
        latest = {
            'timestamp': '', 'iso_time': 'No logs', 'server_ip': '10.0.0.200',
            'packet_rate': 0.0, 'byte_rate': 0.0, 'active_flows': 0,
            'unique_sources': 0, 'traffic_concentration': 0.0,
            'suspicion_score': 0, 'consecutive_suspicious': 0,
            'detection_status': 'NORMAL', 'reason': 'No data'
        }

    history = clean_rows[-30:] if len(clean_rows) > 30 else clean_rows
    return jsonify({'status': 'OK', 'latest': latest, 'history': history})


@app.route('/api/mitigation')
def get_mitigation():
    """Returns list of blocked attackers from mitigation_events.csv"""
    MITIGATION_CSV = get_log_file('mitigation_events.csv')
    blocked = []
    if os.path.exists(MITIGATION_CSV):
        try:
            with open(MITIGATION_CSV, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    blocked.append({
                        'timestamp': row.get('timestamp', ''),
                        'iso_time': row.get('iso_time', ''),
                        'dpid': row.get('dpid', ''),
                        'attacker_mac': row.get('attacker_mac', ''),
                        'target_ip': row.get('target_ip', ''),
                        'action': row.get('action', ''),
                        'status': row.get('status', '')
                    })
        except Exception:
            pass
    return jsonify({'status': 'OK', 'blocked_count': len(blocked), 'blocked': blocked})


@app.route('/api/network-info')
def get_network_info():
    """Returns static network topology info for the frontend visualizer"""
    return jsonify({
        'topology': {
            'switches': [
                {'id': 's1', 'dpid': '0000000000000001'},
                {'id': 's2', 'dpid': '0000000000000002'}
            ],
            'hosts': [
                {'id': 'client1', 'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01', 'type': 'client', 'switch': 's1'},
                {'id': 'client2', 'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'type': 'client', 'switch': 's1'},
                {'id': 'client3', 'ip': '10.0.0.3', 'mac': '00:00:00:00:00:03', 'type': 'client', 'switch': 's1'},
                {'id': 'attacker1', 'ip': '10.0.0.100', 'mac': '00:00:00:00:00:a1', 'type': 'attacker', 'switch': 's2'},
                {'id': 'attacker2', 'ip': '10.0.0.101', 'mac': '00:00:00:00:00:a2', 'type': 'attacker', 'switch': 's2'},
                {'id': 'server1', 'ip': '10.0.0.200', 'mac': '00:00:00:00:00:fe', 'type': 'server', 'switch': 's2'}
            ],
            'links': [
                {'from': 'client1', 'to': 's1'},
                {'from': 'client2', 'to': 's1'},
                {'from': 'client3', 'to': 's1'},
                {'from': 'attacker1', 'to': 's2'},
                {'from': 'attacker2', 'to': 's2'},
                {'from': 'server1', 'to': 's2'},
                {'from': 's1', 'to': 's2'}
            ]
        }
    })


if __name__ == '__main__':
    print("==================================================")
    print("[*] SDN DDoS Protection API Server Starting...")
    print("    API Base URL: http://localhost:5000")
    print("    Endpoints:")
    print("      GET /api/stats        -> Detection events & live metrics")
    print("      GET /api/mitigation   -> Blocked attackers list")
    print("      GET /api/network-info -> Topology data for visualizer")
    print("    React Frontend: http://localhost:3000")
    print("==================================================")
    app.run(host='0.0.0.0', port=5000, debug=False)
