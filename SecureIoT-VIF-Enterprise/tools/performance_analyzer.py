#!/usr/bin/env python3
"""
Analyseur de performance pour SecureIoT-VIF Enterprise Edition

Fonctionnalités Enterprise :
- Analyse de performance temps réel
- Benchmarks automatisés
- Détection de goulots d'étranglement
- Optimisation automatique
- Rapports de performance détaillés
- Comparaisons historiques
"""

import os
import sys
import json
import time
import serial
import statistics
import threading
import sqlite3
import re
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

class EnterprisePerformanceAnalyzer:
    def __init__(self, serial_port="/dev/ttyUSB0", baudrate=115200):
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.analysis_active = False
        self.performance_data = {}
        self.benchmarks = {}
        self.bottlenecks = []
        self.optimizations = []
        
        # Base de données pour les métriques de performance
        self.db_path = Path("performance_data.db")
        self.setup_database()
        
        # Configuration des benchmarks Enterprise
        self.benchmark_config = {
            'crypto_operations': {
                'aes_encrypt': {'target': 10, 'unit': 'ms', 'max_acceptable': 50},
                'sha256_hash': {'target': 5, 'unit': 'ms', 'max_acceptable': 25},
                'ecdsa_sign': {'target': 40, 'unit': 'ms', 'max_acceptable': 100},
                'rng_generation': {'target': 1, 'unit': 'ms', 'max_acceptable': 10}
            },
            'integrity_verification': {
                'boot_verification': {'target': 2000, 'unit': 'ms', 'max_acceptable': 10000},
                'realtime_check': {'target': 200, 'unit': 'ms', 'max_acceptable': 1000},
                'chunk_verification': {'target': 50, 'unit': 'ms', 'max_acceptable': 200},
                'full_verification': {'target': 5000, 'unit': 'ms', 'max_acceptable': 30000}
            },
            'attestation': {
                'generate_attestation': {'target': 100, 'unit': 'ms', 'max_acceptable': 500},
                'verify_attestation': {'target': 50, 'unit': 'ms', 'max_acceptable': 200},
                'continuous_attestation': {'target': 30000, 'unit': 'ms', 'max_acceptable': 120000}
            },
            'ml_processing': {
                'anomaly_detection': {'target': 10, 'unit': 'ms', 'max_acceptable': 50},
                'model_update': {'target': 100, 'unit': 'ms', 'max_acceptable': 500},
                'prediction_generation': {'target': 5, 'unit': 'ms', 'max_acceptable': 25}
            },
            'sensor_operations': {
                'sensor_read': {'target': 500, 'unit': 'ms', 'max_acceptable': 2000},
                'data_processing': {'target': 10, 'unit': 'ms', 'max_acceptable': 50},
                'calibration': {'target': 1000, 'unit': 'ms', 'max_acceptable': 5000}
            },
            'system_metrics': {
                'boot_time': {'target': 3000, 'unit': 'ms', 'max_acceptable': 15000},
                'memory_usage': {'target': 30, 'unit': '%', 'max_acceptable': 80},
                'cpu_usage': {'target': 50, 'unit': '%', 'max_acceptable': 90}
            }
        }
    
    def setup_database(self):
        """Configurer la base de données de performance"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des métriques de performance
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    category TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT,
                    target_value REAL,
                    performance_score REAL,
                    metadata TEXT
                )
            ''')
            
            # Table des benchmarks
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS benchmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    benchmark_name TEXT NOT NULL,
                    duration_seconds INTEGER,
                    iterations INTEGER,
                    avg_performance REAL,
                    min_performance REAL,
                    max_performance REAL,
                    std_dev REAL,
                    results_json TEXT
                )
            ''')
            
            # Table des optimisations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS optimizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    optimization_type TEXT NOT NULL,
                    before_value REAL,
                    after_value REAL,
                    improvement_percent REAL,
                    description TEXT,
                    applied BOOLEAN DEFAULT FALSE
                )
            ''')
            
            conn.commit()
    
    def log_message(self, message, level="INFO"):
        """Log un message avec timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def parse_performance_data(self, data):
        """Parser les données de performance provenant de l'ESP32"""
        patterns = {
            'crypto_aes': r'AES-256: (\d+)ms',
            'crypto_sha': r'SHA-256: (\d+)ms',
            'crypto_ecdsa': r'ECDSA: (\d+)ms',
            'crypto_rng': r'RNG: (\d+)ms',
            'integrity_boot': r'Boot verification: (\d+)ms',
            'integrity_realtime': r'Realtime check: (\d+)ms',
            'integrity_chunk': r'Chunk verify: (\d+)ms',
            'integrity_full': r'Full verification: (\d+)ms',
            'attestation_gen': r'Attestation gen: (\d+)ms',
            'attestation_verify': r'Attestation verify: (\d+)ms',
            'ml_anomaly': r'ML anomaly: (\d+)ms',
            'ml_update': r'ML update: (\d+)ms',
            'ml_predict': r'ML predict: (\d+)ms',
            'sensor_read': r'Sensor read: (\d+)ms',
            'sensor_process': r'Data process: (\d+)ms',
            'system_boot': r'Boot time: (\d+)ms',
            'memory_usage': r'Memory: (\d+)% used',
            'cpu_usage': r'CPU: (\d+)% usage'
        }
        
        parsed_metrics = []
        
        for line in data.split('\
'):
            line = line.strip()
            for pattern_name, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    value = int(match.group(1))
                    
                    # Déterminer la catégorie et le nom de la métrique
                    if pattern_name.startswith('crypto_'):
                        category = 'crypto_operations'
                        metric_name = pattern_name.replace('crypto_', '') + '_encrypt' if 'aes' in pattern_name else pattern_name.replace('crypto_', '') + '_hash' if 'sha' in pattern_name else pattern_name.replace('crypto_', '') + '_sign' if 'ecdsa' in pattern_name else pattern_name.replace('crypto_', '') + '_generation'
                    elif pattern_name.startswith('integrity_'):
                        category = 'integrity_verification'
                        metric_name = pattern_name.replace('integrity_', '') + '_verification'
                    elif pattern_name.startswith('attestation_'):
                        category = 'attestation'
                        metric_name = 'generate_attestation' if 'gen' in pattern_name else 'verify_attestation'
                    elif pattern_name.startswith('ml_'):
                        category = 'ml_processing'
                        metric_name = 'anomaly_detection' if 'anomaly' in pattern_name else 'model_update' if 'update' in pattern_name else 'prediction_generation'
                    elif pattern_name.startswith('sensor_'):
                        category = 'sensor_operations'
                        metric_name = 'sensor_read' if 'read' in pattern_name else 'data_processing'
                    else:
                        category = 'system_metrics'
                        metric_name = pattern_name.replace('system_', '').replace('_usage', '_usage')
                    
                    # Obtenir la configuration du benchmark
                    benchmark_config = self.benchmark_config.get(category, {}).get(metric_name, {})
                    target_value = benchmark_config.get('target', 0)
                    max_acceptable = benchmark_config.get('max_acceptable', target_value * 5)
                    unit = benchmark_config.get('unit', 'ms')
                    
                    # Calculer le score de performance (0-100)
                    if target_value > 0:
                        if value <= target_value:
                            performance_score = 100
                        elif value <= max_acceptable:
                            performance_score = 100 * (max_acceptable - value) / (max_acceptable - target_value)
                        else:
                            performance_score = 0
                    else:
                        performance_score = 50  # Score neutre si pas de cible
                    
                    parsed_metrics.append({
                        'timestamp': datetime.now(),
                        'category': category,
                        'metric_name': metric_name,
                        'value': value,
                        'unit': unit,
                        'target_value': target_value,
                        'performance_score': round(performance_score, 2)
                    })
        
        return parsed_metrics
    
    def store_performance_data(self, metrics):
        """Stocker les données de performance dans la base"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for metric in metrics:
                cursor.execute('''
                    INSERT INTO performance_metrics 
                    (timestamp, category, metric_name, value, unit, target_value, performance_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metric['timestamp'],
                    metric['category'],
                    metric['metric_name'],
                    metric['value'],
                    metric['unit'],
                    metric['target_value'],
                    metric['performance_score']
                ))
            
            conn.commit()
    
    def run_benchmark_suite(self):
        """Exécuter la suite complète de benchmarks Enterprise"""
        self.log_message("🚀 Démarrage de la suite de benchmarks Enterprise", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=60) as ser:
                time.sleep(3)  # Stabilisation
                
                benchmark_results = {}
                
                # Benchmarks par catégorie
                benchmark_commands = [
                    ('crypto_benchmark_suite', 'Benchmarks crypto HSM'),
                    ('integrity_benchmark_suite', 'Benchmarks intégrité'),
                    ('attestation_benchmark_suite', 'Benchmarks attestation'),
                    ('ml_benchmark_suite', 'Benchmarks ML'),
                    ('sensor_benchmark_suite', 'Benchmarks capteurs'),
                    ('system_benchmark_suite', 'Benchmarks système')
                ]
                
                for cmd, description in benchmark_commands:
                    self.log_message(f"Exécution: {description}...", "INFO")
                    
                    # Envoyer la commande
                    ser.write(f"{cmd}\
".encode())
                    
                    # Collecter les résultats
                    start_time = time.time()
                    benchmark_data = ""
                    
                    while time.time() - start_time < 120:  # 2 minutes par benchmark
                        if ser.in_waiting:
                            data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                            benchmark_data += data
                            
                            if f"{cmd}_complete" in benchmark_data:
                                break
                    
                    # Parser les résultats
                    metrics = self.parse_performance_data(benchmark_data)
                    if metrics:
                        self.store_performance_data(metrics)
                        benchmark_results[cmd] = metrics
                        self.log_message(f"{description}: {len(metrics)} métriques collectées", "SUCCESS")
                    else:
                        self.log_message(f"{description}: Aucune métrique collectée", "WARNING")
                    
                    time.sleep(2)  # Pause entre benchmarks
                
                return benchmark_results
                
        except Exception as e:
            self.log_message(f"Erreur benchmarks: {e}", "ERROR")
            return {}
    
    def analyze_bottlenecks(self):
        """Analyser les goulots d'étranglement"""
        self.log_message("🔍 Analyse des goulots d'étranglement...", "INFO")
        
        bottlenecks = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Identifier les métriques avec de mauvaises performances
            cursor.execute('''
                SELECT category, metric_name, AVG(performance_score) as avg_score, 
                       AVG(value) as avg_value, target_value, unit,
                       COUNT(*) as sample_count
                FROM performance_metrics 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY category, metric_name, target_value, unit
                HAVING avg_score < 70
                ORDER BY avg_score ASC
            ''')
            
            for row in cursor.fetchall():
                category, metric_name, avg_score, avg_value, target_value, unit, sample_count = row
                
                # Calculer l'écart par rapport à la cible
                if target_value > 0:
                    deviation_percent = ((avg_value - target_value) / target_value) * 100
                else:
                    deviation_percent = 0
                
                bottleneck = {
                    'category': category,
                    'metric': metric_name,
                    'avg_score': round(avg_score, 1),
                    'avg_value': round(avg_value, 2),
                    'target_value': target_value,
                    'unit': unit,
                    'deviation_percent': round(deviation_percent, 1),
                    'sample_count': sample_count,
                    'severity': 'CRITICAL' if avg_score < 30 else 'HIGH' if avg_score < 50 else 'MEDIUM'
                }
                
                bottlenecks.append(bottleneck)
        
        self.bottlenecks = bottlenecks
        
        # Afficher les goulots d'étranglement trouvés
        if bottlenecks:
            self.log_message(f"🔍 {len(bottlenecks)} goulots d'étranglement identifiés:", "WARNING")
            for bottleneck in bottlenecks:
                self.log_message(
                    f"  {bottleneck['severity']}: {bottleneck['category']}.{bottleneck['metric']} - "
                    f"Score: {bottleneck['avg_score']}%, Valeur: {bottleneck['avg_value']}{bottleneck['unit']} "
                    f"(Cible: {bottleneck['target_value']}{bottleneck['unit']})", 
                    "WARNING"
                )
        else:
            self.log_message("🔍 Aucun goulot d'étranglement majeur détecté", "SUCCESS")
        
        return bottlenecks
    
    def generate_optimization_recommendations(self):
        """Générer des recommandations d'optimisation"""
        self.log_message("💡 Génération des recommandations d'optimisation...", "INFO")
        
        recommendations = []
        
        for bottleneck in self.bottlenecks:
            category = bottleneck['category']
            metric = bottleneck['metric']
            severity = bottleneck['severity']
            
            # Recommandations spécifiques par catégorie
            if category == 'crypto_operations':
                if 'aes' in metric:
                    recommendations.append({
                        'type': 'CRYPTO_OPTIMIZATION',
                        'category': category,
                        'metric': metric,
                        'recommendation': 'Activer l\'accélération matérielle AES ESP32',
                        'expected_improvement': '70-80%',
                        'implementation': 'Configurer CONFIG_ESP32_AES_USE_HARDWARE=y',
                        'priority': severity
                    })
                elif 'sha' in metric:
                    recommendations.append({
                        'type': 'CRYPTO_OPTIMIZATION',
                        'category': category,
                        'metric': metric,
                        'recommendation': 'Activer l\'accélération matérielle SHA ESP32',
                        'expected_improvement': '60-70%',
                        'implementation': 'Configurer CONFIG_ESP32_SHA_USE_HARDWARE=y',
                        'priority': severity
                    })
            
            elif category == 'integrity_verification':
                if 'realtime' in metric:
                    recommendations.append({
                        'type': 'INTEGRITY_OPTIMIZATION',
                        'category': category,
                        'metric': metric,
                        'recommendation': 'Optimiser la taille des chunks de vérification',
                        'expected_improvement': '30-40%',
                        'implementation': 'Réduire INTEGRITY_CHUNK_SIZE ou implémenter vérification parallèle',
                        'priority': severity
                    })
                elif 'full' in metric:
                    recommendations.append({
                        'type': 'INTEGRITY_OPTIMIZATION',
                        'category': category,
                        'metric': metric,
                        'recommendation': 'Implémenter vérification incrémentale',
                        'expected_improvement': '50-60%',
                        'implementation': 'Activer CONFIG_INTEGRITY_INCREMENTAL=y',
                        'priority': severity
                    })
            
            elif category == 'ml_processing':
                recommendations.append({
                    'type': 'ML_OPTIMIZATION',
                    'category': category,
                    'metric': metric,
                    'recommendation': 'Optimiser le modèle ML pour ESP32',
                    'expected_improvement': '40-50%',
                    'implementation': 'Réduire la complexité du modèle ou utiliser quantization',
                    'priority': severity
                })
            
            elif category == 'system_metrics':
                if 'memory' in metric:
                    recommendations.append({
                        'type': 'MEMORY_OPTIMIZATION',
                        'category': category,
                        'metric': metric,
                        'recommendation': 'Optimiser l\'utilisation mémoire',
                        'expected_improvement': '20-30%',
                        'implementation': 'Réviser les allocations statiques et libérer la mémoire inutilisée',
                        'priority': severity
                    })
        
        self.optimizations = recommendations
        
        # Afficher les recommandations
        if recommendations:
            self.log_message(f"💡 {len(recommendations)} recommandations d'optimisation générées:", "INFO")
            for rec in recommendations:
                self.log_message(
                    f"  {rec['priority']}: {rec['recommendation']} "
                    f"(Amélioration attendue: {rec['expected_improvement']})", 
                    "INFO"
                )
        else:
            self.log_message("💡 Aucune optimisation nécessaire", "SUCCESS")
        
        return recommendations
    
    def continuous_monitoring(self, duration_minutes=30):
        """Monitoring continu de performance"""
        self.log_message(f"📊 Démarrage monitoring continu ({duration_minutes} minutes)...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=1) as ser:
                start_time = time.time()
                end_time = start_time + (duration_minutes * 60)
                
                buffer = ""
                metrics_collected = 0
                
                while time.time() < end_time and self.analysis_active:
                    if ser.in_waiting:
                        data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                        buffer += data
                        
                        # Traiter les lignes complètes
                        lines = buffer.split('\
')
                        buffer = lines[-1]  # Garder la ligne incomplète
                        
                        for line in lines[:-1]:
                            if line.strip():
                                metrics = self.parse_performance_data(line)
                                if metrics:
                                    self.store_performance_data(metrics)
                                    metrics_collected += len(metrics)
                    
                    time.sleep(0.1)  # 100ms polling
                
                self.log_message(f"📊 Monitoring terminé: {metrics_collected} métriques collectées", "SUCCESS")
                
        except Exception as e:
            self.log_message(f"Erreur monitoring: {e}", "ERROR")
    
    def generate_performance_report(self):
        """Générer un rapport de performance complet"""
        self.log_message("📋 Génération du rapport de performance...", "INFO")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'ENTERPRISE_PERFORMANCE_ANALYSIS',
            'summary': {},
            'benchmarks': {},
            'bottlenecks': self.bottlenecks,
            'optimizations': self.optimizations,
            'recommendations': []
        }
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Résumé par catégorie
            cursor.execute('''
                SELECT category, 
                       AVG(performance_score) as avg_score,
                       COUNT(*) as metric_count,
                       MIN(performance_score) as min_score,
                       MAX(performance_score) as max_score
                FROM performance_metrics 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY category
            ''')
            
            for row in cursor.fetchall():
                category, avg_score, count, min_score, max_score = row
                report['summary'][category] = {
                    'avg_score': round(avg_score, 1),
                    'metric_count': count,
                    'min_score': round(min_score, 1),
                    'max_score': round(max_score, 1),
                    'status': 'EXCELLENT' if avg_score >= 90 else 'GOOD' if avg_score >= 70 else 'POOR'
                }
            
            # Top 10 des meilleures et pires métriques
            cursor.execute('''
                SELECT metric_name, AVG(performance_score) as avg_score, AVG(value) as avg_value, unit
                FROM performance_metrics 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY metric_name, unit
                ORDER BY avg_score DESC
                LIMIT 5
            ''')
            
            report['top_performers'] = []
            for row in cursor.fetchall():
                report['top_performers'].append({
                    'metric': row[0],
                    'score': round(row[1], 1),
                    'avg_value': round(row[2], 2),
                    'unit': row[3]
                })
            
            cursor.execute('''
                SELECT metric_name, AVG(performance_score) as avg_score, AVG(value) as avg_value, unit
                FROM performance_metrics 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY metric_name, unit
                ORDER BY avg_score ASC
                LIMIT 5
            ''')
            
            report['worst_performers'] = []
            for row in cursor.fetchall():
                report['worst_performers'].append({
                    'metric': row[0],
                    'score': round(row[1], 1),
                    'avg_value': round(row[2], 2),
                    'unit': row[3]
                })
        
        # Calculer le score global
        if report['summary']:
            global_score = sum(cat['avg_score'] for cat in report['summary'].values()) / len(report['summary'])
            report['global_performance_score'] = round(global_score, 1)
        else:
            report['global_performance_score'] = 0
        
        # Sauvegarder le rapport
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        report_file = reports_dir / f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log_message(f"📋 Rapport sauvegardé: {report_file}", "SUCCESS")
        
        # Afficher le résumé
        self.log_message("📋 RÉSUMÉ DU RAPPORT DE PERFORMANCE", "INFO")
        self.log_message(f"Score global: {report['global_performance_score']}%", "INFO")
        
        for category, stats in report['summary'].items():
            self.log_message(f"  {category}: {stats['avg_score']}% ({stats['status']})", "INFO")
        
        return report_file
    
    def run_full_analysis(self, monitoring_duration=30):
        """Exécuter une analyse complète de performance"""
        self.log_message("🏢 === ANALYSE PERFORMANCE ENTERPRISE SECUREIOT-VIF ===", "INFO")
        
        self.analysis_active = True
        
        try:
            # 1. Suite de benchmarks
            benchmark_results = self.run_benchmark_suite()
            
            # 2. Monitoring continu
            if monitoring_duration > 0:
                monitoring_thread = threading.Thread(
                    target=self.continuous_monitoring, 
                    args=(monitoring_duration,)
                )
                monitoring_thread.start()
                monitoring_thread.join()
            
            # 3. Analyse des goulots d'étranglement
            self.analyze_bottlenecks()
            
            # 4. Recommandations d'optimisation
            self.generate_optimization_recommendations()
            
            # 5. Rapport final
            report_file = self.generate_performance_report()
            
            self.log_message("🏢 === ANALYSE PERFORMANCE TERMINÉE ===", "SUCCESS")
            self.log_message(f"Rapport disponible: {report_file}", "SUCCESS")
            
            return True
            
        except Exception as e:
            self.log_message(f"Erreur analyse: {e}", "ERROR")
            return False
        
        finally:
            self.analysis_active = False

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Analyseur de performance SecureIoT-VIF Enterprise")
    parser.add_argument("-p", "--port", default="/dev/ttyUSB0", help="Port série ESP32")
    parser.add_argument("-d", "--duration", default=30, type=int, help="Durée monitoring (minutes)")
    parser.add_argument("--benchmark-only", action="store_true", help="Benchmarks seulement")
    parser.add_argument("--monitor-only", action="store_true", help="Monitoring seulement")
    parser.add_argument("--analyze-only", action="store_true", help="Analyse des données existantes")
    
    args = parser.parse_args()
    
    # Créer l'analyseur
    analyzer = EnterprisePerformanceAnalyzer(args.port)
    
    try:
        if args.benchmark_only:
            analyzer.run_benchmark_suite()
        elif args.monitor_only:
            analyzer.analysis_active = True
            analyzer.continuous_monitoring(args.duration)
        elif args.analyze_only:
            analyzer.analyze_bottlenecks()
            analyzer.generate_optimization_recommendations()
            analyzer.generate_performance_report()
        else:
            # Analyse complète
            analyzer.run_full_analysis(args.duration)
        
        return 0
        
    except KeyboardInterrupt:
        print("\
🛑 Analyse interrompue par l'utilisateur")
        analyzer.analysis_active = False
        return 1
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())