#!/usr/bin/env python3
"""
Dashboard de monitoring temps réel pour SecureIoT-VIF Enterprise Edition

Fonctionnalités Enterprise :
- Monitoring temps réel des métriques sécurité
- Interface web interactive
- Alertes proactives
- Analyse prédictive ML
- Exports de données
- Tableau de bord exécutif
"""

import os
import sys
import json
import time
import threading
import sqlite3
import serial
import re
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import plotly.graph_objs as go
import plotly.utils

class EnterpriseMonitoringDashboard:
    def __init__(self, serial_port="/dev/ttyUSB0", baudrate=115200):
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.monitoring_active = False
        self.data_buffer = []
        self.alerts = []
        self.predictions = []
        
        # Configuration Flask
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'secureiot_vif_enterprise_2025'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Base de données pour stocker les métriques
        self.setup_database()
        
        # Configuration des routes
        self.setup_routes()
        
        # Configuration WebSocket
        self.setup_websockets()
        
        # Métriques en temps réel
        self.current_metrics = {
            'system_status': 'INITIALIZING',
            'integrity_score': 0,
            'security_level': 0,
            'crypto_performance': 0,
            'ml_confidence': 0,
            'uptime': 0,
            'alerts_count': 0,
            'last_update': datetime.now()
        }
    
    def setup_database(self):
        """Configurer la base de données SQLite pour les métriques"""
        self.db_path = Path("monitoring_data.db")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des métriques temps réel
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT,
                    status TEXT,
                    metadata TEXT
                )
            ''')
            
            # Table des alertes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolution_time DATETIME,
                    metadata TEXT
                )
            ''')
            
            # Table des prédictions ML
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    prediction_type TEXT NOT NULL,
                    predicted_value REAL,
                    confidence_score REAL,
                    time_horizon INTEGER,
                    actual_value REAL,
                    accuracy REAL
                )
            ''')
            
            conn.commit()
    
    def setup_routes(self):
        """Configurer les routes Flask"""
        
        @self.app.route('/')
        def dashboard():
            """Page principale du dashboard"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/current_metrics')
        def get_current_metrics():
            """API pour obtenir les métriques actuelles"""
            return jsonify(self.current_metrics)
        
        @self.app.route('/api/historical_data')
        def get_historical_data():
            """API pour obtenir les données historiques"""
            hours = request.args.get('hours', 24, type=int)
            since = datetime.now() - timedelta(hours=hours)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT timestamp, metric_name, value, unit
                    FROM metrics 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC
                    LIMIT 1000
                ''', (since,))
                
                data = []
                for row in cursor.fetchall():
                    data.append({
                        'timestamp': row[0],
                        'metric': row[1],
                        'value': row[2],
                        'unit': row[3]
                    })
                
                return jsonify(data)
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """API pour obtenir les alertes"""
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT timestamp, alert_type, severity, message, resolved
                    FROM alerts 
                    ORDER BY timestamp DESC
                    LIMIT 100
                ''')
                
                alerts = []
                for row in cursor.fetchall():
                    alerts.append({
                        'timestamp': row[0],
                        'type': row[1],
                        'severity': row[2],
                        'message': row[3],
                        'resolved': bool(row[4])
                    })
                
                return jsonify(alerts)
        
        @self.app.route('/api/system_health')
        def get_system_health():
            """API pour obtenir l'état de santé système"""
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Métriques des dernières 24h
                since = datetime.now() - timedelta(hours=24)
                cursor.execute('''
                    SELECT 
                        AVG(CASE WHEN metric_name = 'integrity_score' THEN value END) as avg_integrity,
                        AVG(CASE WHEN metric_name = 'security_level' THEN value END) as avg_security,
                        AVG(CASE WHEN metric_name = 'crypto_performance' THEN value END) as avg_crypto,
                        COUNT(CASE WHEN metric_name = 'error_count' THEN 1 END) as total_errors,
                        MAX(timestamp) as last_update
                    FROM metrics 
                    WHERE timestamp > ?
                ''', (since,))
                
                row = cursor.fetchone()
                
                health_score = 0
                if row and row[0] is not None:
                    # Calculer un score de santé global
                    integrity = row[0] or 0
                    security = row[1] or 0
                    crypto = row[2] or 0
                    errors = row[3] or 0
                    
                    health_score = (integrity + security + min(crypto/100, 100) - errors) / 3
                    health_score = max(0, min(100, health_score))
                
                return jsonify({
                    'health_score': round(health_score, 1),
                    'integrity_avg': round(row[0] or 0, 1),
                    'security_avg': round(row[1] or 0, 1),
                    'crypto_avg': round(row[2] or 0, 1),
                    'error_count': row[3] or 0,
                    'last_update': row[4]
                })
        
        @self.app.route('/api/export_data')
        def export_data():
            """API pour exporter les données"""
            format_type = request.args.get('format', 'json')
            hours = request.args.get('hours', 24, type=int)
            
            since = datetime.now() - timedelta(hours=hours)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT timestamp, metric_type, metric_name, value, unit, status
                    FROM metrics 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (since,))
                
                data = []
                for row in cursor.fetchall():
                    data.append({
                        'timestamp': row[0],
                        'type': row[1],
                        'metric': row[2],
                        'value': row[3],
                        'unit': row[4],
                        'status': row[5]
                    })
                
                if format_type == 'csv':
                    import csv
                    import io
                    
                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=data[0].keys() if data else [])
                    writer.writeheader()
                    writer.writerows(data)
                    
                    response = self.app.response_class(
                        output.getvalue(),
                        mimetype='text/csv',
                        headers={'Content-Disposition': 'attachment; filename=metrics_export.csv'}
                    )
                    return response
                
                return jsonify(data)
    
    def setup_websockets(self):
        """Configurer les WebSockets pour les updates temps réel"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Connexion WebSocket"""
            print(f"Client connecté: {request.sid}")
            emit('status', {'message': 'Connecté au monitoring Enterprise'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Déconnexion WebSocket"""
            print(f"Client déconnecté: {request.sid}")
        
        @self.socketio.on('start_monitoring')
        def handle_start_monitoring():
            """Démarrer le monitoring"""
            if not self.monitoring_active:
                self.start_monitoring()
                emit('status', {'message': 'Monitoring démarré'})
        
        @self.socketio.on('stop_monitoring')
        def handle_stop_monitoring():
            """Arrêter le monitoring"""
            if self.monitoring_active:
                self.stop_monitoring()
                emit('status', {'message': 'Monitoring arrêté'})
    
    def parse_serial_data(self, data):
        """Parser les données série provenant de l'ESP32"""
        patterns = {
            'integrity': r'Intégrité: (\d+)% \((\d+)ms\)',
            'security': r'Sécurité niveau: (\d+)/5',
            'crypto': r'Crypto perf: (\d+)ms, (\w+)',
            'ml_score': r'ML: Score:(\d+)%, Confiance:(\d+)%',
            'attestation': r'Attestation: (\w+) \((\d+)ms\)',
            'sensor': r'Capteur: T=([\d.-]+)°C, H=([\d.-]+)%, Q=(\d+)',
            'memory': r'Mémoire: Libre:(\d+), Utilisée:(\d+)',
            'alert': r'ALERTE: (\w+) - (.+)',
            'error': r'ERREUR: (.+)',
            'warning': r'ATTENTION: (.+)'
        }
        
        parsed_data = []
        
        for line in data.split('\
'):
            line = line.strip()
            if not line:
                continue
            
            for pattern_name, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    timestamp = datetime.now()
                    
                    if pattern_name == 'integrity':
                        parsed_data.append({
                            'timestamp': timestamp,
                            'type': 'security',
                            'metric': 'integrity_score',
                            'value': int(match.group(1)),
                            'unit': '%',
                            'status': 'OK',
                            'metadata': json.dumps({'time_ms': int(match.group(2))})
                        })
                    
                    elif pattern_name == 'security':
                        parsed_data.append({
                            'timestamp': timestamp,
                            'type': 'security',
                            'metric': 'security_level',
                            'value': int(match.group(1)) * 20,  # Convertir 1-5 en 0-100
                            'unit': '%',
                            'status': 'OK'
                        })
                    
                    elif pattern_name == 'crypto':
                        parsed_data.append({
                            'timestamp': timestamp,
                            'type': 'performance',
                            'metric': 'crypto_performance',
                            'value': int(match.group(1)),
                            'unit': 'ms',
                            'status': 'OK',
                            'metadata': json.dumps({'operation': match.group(2)})
                        })
                    
                    elif pattern_name == 'ml_score':
                        parsed_data.extend([
                            {
                                'timestamp': timestamp,
                                'type': 'ml',
                                'metric': 'ml_score',
                                'value': int(match.group(1)),
                                'unit': '%',
                                'status': 'OK'
                            },
                            {
                                'timestamp': timestamp,
                                'type': 'ml',
                                'metric': 'ml_confidence',
                                'value': int(match.group(2)),
                                'unit': '%',
                                'status': 'OK'
                            }
                        ])
                    
                    elif pattern_name == 'sensor':
                        parsed_data.extend([
                            {
                                'timestamp': timestamp,
                                'type': 'sensor',
                                'metric': 'temperature',
                                'value': float(match.group(1)),
                                'unit': '°C',
                                'status': 'OK'
                            },
                            {
                                'timestamp': timestamp,
                                'type': 'sensor',
                                'metric': 'humidity',
                                'value': float(match.group(2)),
                                'unit': '%',
                                'status': 'OK'
                            },
                            {
                                'timestamp': timestamp,
                                'type': 'sensor',
                                'metric': 'quality',
                                'value': int(match.group(3)),
                                'unit': '',
                                'status': 'OK'
                            }
                        ])
                    
                    elif pattern_name == 'alert':
                        alert = {
                            'timestamp': timestamp,
                            'type': match.group(1),
                            'severity': 'HIGH',
                            'message': match.group(2),
                            'resolved': False
                        }
                        self.add_alert(alert)
                    
                    elif pattern_name in ['error', 'warning']:
                        severity = 'HIGH' if pattern_name == 'error' else 'MEDIUM'
                        alert = {
                            'timestamp': timestamp,
                            'type': pattern_name.upper(),
                            'severity': severity,
                            'message': match.group(1),
                            'resolved': False
                        }
                        self.add_alert(alert)
        
        return parsed_data
    
    def add_metrics(self, metrics_list):
        """Ajouter des métriques à la base de données"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for metric in metrics_list:
                cursor.execute('''
                    INSERT INTO metrics (timestamp, metric_type, metric_name, value, unit, status, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metric['timestamp'],
                    metric['type'],
                    metric['metric'],
                    metric['value'],
                    metric.get('unit', ''),
                    metric.get('status', 'OK'),
                    metric.get('metadata', '')
                ))
            
            conn.commit()
        
        # Mettre à jour les métriques actuelles
        for metric in metrics_list:
            if metric['metric'] in self.current_metrics:
                self.current_metrics[metric['metric']] = metric['value']
        
        self.current_metrics['last_update'] = datetime.now()
        
        # Envoyer les updates via WebSocket
        self.socketio.emit('metrics_update', {
            'metrics': self.current_metrics,
            'new_data': metrics_list
        })
    
    def add_alert(self, alert):
        """Ajouter une alerte"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, severity, message, resolved, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert['type'],
                alert['severity'],
                alert['message'],
                alert['resolved'],
                alert.get('metadata', '')
            ))
            conn.commit()
        
        self.alerts.append(alert)
        self.current_metrics['alerts_count'] = len([a for a in self.alerts if not a['resolved']])
        
        # Envoyer l'alerte via WebSocket
        self.socketio.emit('new_alert', alert)
    
    def monitoring_loop(self):
        """Boucle de monitoring principal"""
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=1) as ser:
                print(f"Monitoring démarré sur {self.serial_port}")
                self.current_metrics['system_status'] = 'MONITORING'
                
                buffer = ""
                
                while self.monitoring_active:
                    if ser.in_waiting:
                        data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                        buffer += data
                        
                        # Process complete lines
                        lines = buffer.split('\
')
                        buffer = lines[-1]  # Keep incomplete line
                        
                        for line in lines[:-1]:
                            if line.strip():
                                # Parse and add metrics
                                metrics = self.parse_serial_data(line)
                                if metrics:
                                    self.add_metrics(metrics)
                    
                    time.sleep(0.1)  # 100ms polling
                    
        except Exception as e:
            print(f"Erreur monitoring: {e}")
            self.current_metrics['system_status'] = 'ERROR'
            alert = {
                'timestamp': datetime.now(),
                'type': 'SYSTEM',
                'severity': 'HIGH',
                'message': f'Erreur monitoring: {e}',
                'resolved': False
            }
            self.add_alert(alert)
        
        finally:
            self.monitoring_active = False
            self.current_metrics['system_status'] = 'STOPPED'
    
    def start_monitoring(self):
        """Démarrer le monitoring"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self.monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            
            print("Monitoring Enterprise démarré")
            return True
        return False
    
    def stop_monitoring(self):
        """Arrêter le monitoring"""
        if self.monitoring_active:
            self.monitoring_active = False
            if hasattr(self, 'monitoring_thread'):
                self.monitoring_thread.join(timeout=5)
            
            print("Monitoring Enterprise arrêté")
            return True
        return False
    
    def generate_report(self, hours=24):
        """Générer un rapport de monitoring"""
        since = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Métriques générales
            cursor.execute('''
                SELECT 
                    metric_name,
                    AVG(value) as avg_value,
                    MIN(value) as min_value,
                    MAX(value) as max_value,
                    COUNT(*) as count
                FROM metrics 
                WHERE timestamp > ?
                GROUP BY metric_name
            ''', (since,))
            
            metrics_summary = {}
            for row in cursor.fetchall():
                metrics_summary[row[0]] = {
                    'avg': round(row[1], 2),
                    'min': round(row[2], 2),
                    'max': round(row[3], 2),
                    'count': row[4]
                }
            
            # Alertes
            cursor.execute('''
                SELECT alert_type, severity, COUNT(*) as count
                FROM alerts 
                WHERE timestamp > ?
                GROUP BY alert_type, severity
            ''', (since,))
            
            alerts_summary = {}
            for row in cursor.fetchall():
                key = f"{row[0]}_{row[1]}"
                alerts_summary[key] = row[2]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'period_hours': hours,
            'metrics_summary': metrics_summary,
            'alerts_summary': alerts_summary,
            'system_health': self.current_metrics['system_status']
        }
        
        return report
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Démarrer le serveur dashboard"""
        print(f"🏢 SecureIoT-VIF Enterprise Monitoring Dashboard")
        print(f"🌐 Interface web: http://{host}:{port}")
        print(f"📊 Monitoring temps réel activé")
        
        # Démarrer le monitoring automatiquement
        self.start_monitoring()
        
        try:
            # Démarrer le serveur Flask
            self.socketio.run(self.app, host=host, port=port, debug=debug)
        except KeyboardInterrupt:
            print("\
🛑 Arrêt en cours...")
        finally:
            self.stop_monitoring()

# Template HTML pour le dashboard (à sauvegarder dans templates/dashboard.html)
DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureIoT-VIF Enterprise Monitoring</title>
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .metric-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .chart-container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .alerts-container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .alert { padding: 10px; margin: 5px 0; border-radius: 3px; }
        .alert-high { background: #e74c3c; color: white; }
        .alert-medium { background: #f39c12; color: white; }
        .alert-low { background: #95a5a6; color: white; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 10px; }
        .status-ok { background: #27ae60; }
        .status-warning { background: #f39c12; }
        .status-error { background: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 SecureIoT-VIF Enterprise Monitoring Dashboard</h1>
        <p>Monitoring temps réel des métriques de sécurité et performance</p>
    </div>
    
    <div class="metrics-grid">
        <div class="metric-card">
            <h3>État Système</h3>
            <div class="metric-value" id="system-status">INITIALIZING</div>
        </div>
        <div class="metric-card">
            <h3>Score Intégrité</h3>
            <div class="metric-value" id="integrity-score">0%</div>
        </div>
        <div class="metric-card">
            <h3>Niveau Sécurité</h3>
            <div class="metric-value" id="security-level">0/5</div>
        </div>
        <div class="metric-card">
            <h3>Performance Crypto</h3>
            <div class="metric-value" id="crypto-perf">0ms</div>
        </div>
        <div class="metric-card">
            <h3>Confiance ML</h3>
            <div class="metric-value" id="ml-confidence">0%</div>
        </div>
        <div class="metric-card">
            <h3>Alertes Actives</h3>
            <div class="metric-value" id="alerts-count">0</div>
        </div>
    </div>
    
    <div class="chart-container">
        <h3>Métriques Temps Réel</h3>
        <div id="realtime-chart" style="height: 400px;"></div>
    </div>
    
    <div class="alerts-container">
        <h3>Alertes Récentes</h3>
        <div id="alerts-list"></div>
    </div>
    
    <script>
        const socket = io();
        
        socket.on('connect', function() {
            console.log('Connecté au monitoring');
        });
        
        socket.on('metrics_update', function(data) {
            updateMetrics(data.metrics);
        });
        
        socket.on('new_alert', function(alert) {
            addAlert(alert);
        });
        
        function updateMetrics(metrics) {
            document.getElementById('system-status').textContent = metrics.system_status;
            document.getElementById('integrity-score').textContent = metrics.integrity_score + '%';
            document.getElementById('security-level').textContent = metrics.security_level/20 + '/5';
            document.getElementById('crypto-perf').textContent = metrics.crypto_performance + 'ms';
            document.getElementById('ml-confidence').textContent = metrics.ml_confidence + '%';
            document.getElementById('alerts-count').textContent = metrics.alerts_count;
        }
        
        function addAlert(alert) {
            const alertsContainer = document.getElementById('alerts-list');
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${alert.severity.toLowerCase()}`;
            alertDiv.innerHTML = `
                <strong>${alert.type}</strong> - ${alert.message}
                <small style="float: right;">${new Date(alert.timestamp).toLocaleString()}</small>
            `;
            alertsContainer.insertBefore(alertDiv, alertsContainer.firstChild);
        }
        
        // Initialiser le graphique
        Plotly.newPlot('realtime-chart', [], {
            title: 'Métriques de Sécurité Temps Réel',
            xaxis: { title: 'Temps' },
            yaxis: { title: 'Valeur' }
        });
        
        // Démarrer le monitoring
        socket.emit('start_monitoring');
    </script>
</body>
</html>
'''

def main():
    """Fonction principale"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Dashboard de monitoring SecureIoT-VIF Enterprise")
    parser.add_argument("-p", "--port", default="/dev/ttyUSB0", help="Port série ESP32")
    parser.add_argument("--web-port", default=5000, type=int, help="Port serveur web")
    parser.add_argument("--host", default="0.0.0.0", help="Adresse serveur web")
    parser.add_argument("--debug", action="store_true", help="Mode debug")
    
    args = parser.parse_args()
    
    # Créer le répertoire templates si nécessaire
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Créer le template dashboard
    dashboard_file = templates_dir / "dashboard.html"
    if not dashboard_file.exists():
        with open(dashboard_file, 'w') as f:
            f.write(DASHBOARD_TEMPLATE)
    
    # Démarrer le dashboard
    dashboard = EnterpriseMonitoringDashboard(args.port)
    dashboard.run(host=args.host, port=args.web_port, debug=args.debug)

if __name__ == "__main__":
    main()