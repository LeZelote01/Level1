#!/usr/bin/env python3
"""
Tests de vérification d'intégrité temps réel pour SecureIoT-VIF Enterprise Edition

Tests temps réel spécialisés :
- Vérification d'intégrité continue pendant l'exécution
- Tests de latence et réactivité
- Validation de la détection en temps réel
- Tests de corruption simulée
- Benchmarks de performance temps réel
"""

import unittest
import serial
import time
import re
import json
import threading
import statistics
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

class SecureIoTVIFRealTimeIntegrityTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests temps réel"""
        cls.serial_port = "/dev/ttyUSB0"
        cls.baudrate = 115200
        cls.timeout = 180  # 3 minutes pour tests temps réel
        cls.integrity_events = []
        cls.monitoring_active = False
        
    def setUp(self):
        """Configuration avant chaque test temps réel"""
        try:
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=self.timeout)
            time.sleep(3)
            self.integrity_events.clear()
        except serial.SerialException:
            self.skipTest(f"Port série {self.serial_port} non disponible")
    
    def tearDown(self):
        """Nettoyage après chaque test temps réel"""
        self.monitoring_active = False
        if hasattr(self, 'ser'):
            self.ser.close()
    
    def start_integrity_monitoring(self, duration=60):
        """Démarre le monitoring d'intégrité en arrière-plan"""
        def monitor():
            start_time = time.time()
            buffer = ""
            
            while self.monitoring_active and (time.time() - start_time) < duration:
                if self.ser.in_waiting:
                    data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                    buffer += data
                    
                    # Détecter les événements d'intégrité
                    integrity_matches = re.findall(r"INTEGRITY: (\w+) - Chunk:(\d+) - Time:(\d+)ms - Status:(\w+)", buffer)
                    for match in integrity_matches:
                        event = {
                            'type': match[0],
                            'chunk_id': int(match[1]),
                            'time_ms': int(match[2]),
                            'status': match[3],
                            'timestamp': time.time()
                        }
                        self.integrity_events.append(event)
                    
                    # Nettoyer le buffer
                    if len(buffer) > 5000:
                        buffer = buffer[-2000:]
                
                time.sleep(0.1)  # Polling rapide pour temps réel
        
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        return monitor_thread
    
    def read_serial_until_pattern(self, pattern, timeout=60):
        """Lit le port série jusqu'à trouver un pattern"""
        start_time = time.time()
        buffer = ""
        
        while time.time() - start_time < timeout:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                buffer += data
                
                if re.search(pattern, buffer, re.MULTILINE):
                    return buffer
        
        return buffer
    
    def test_01_realtime_integrity_activation(self):
        """Test d'activation de la vérification temps réel"""
        print("⏱️ Test activation vérification temps réel...")
        
        # Activer la vérification temps réel
        self.ser.write(b"enable_realtime_integrity\n")
        activation_log = self.read_serial_until_pattern(r"Vérification temps réel activée", timeout=30)
        
        # Vérifications activation
        activation_checks = [
            "Initialisation vérification temps réel",
            "Configuration chunks temps réel",
            "Timer périodique configuré",
            "Vérification temps réel activée"
        ]
        
        for check in activation_checks:
            self.assertIn(check, activation_log, f"Activation temps réel échoué: {check}")
        
        # Vérifier la configuration temps réel
        config_match = re.search(r"Intervalle: (\d+)ms, Chunks: (\d+), Méthode: (\w+)", activation_log)
        if config_match:
            interval, chunks, method = config_match.groups()
            interval = int(interval)
            chunks = int(chunks)
            
            print(f"  Configuration: {interval}ms, {chunks} chunks, méthode {method}")
            
            # Vérifications Enterprise
            self.assertLessEqual(interval, 60000, f"Intervalle trop long: {interval}ms > 60000ms")
            self.assertGreater(chunks, 50, f"Pas assez de chunks: {chunks} < 50")
            self.assertIn(method, ['HSM', 'HYBRID'], f"Méthode non-Enterprise: {method}")
        
        print("✅ Activation vérification temps réel OK")
    
    def test_02_continuous_integrity_monitoring(self):
        """Test de monitoring d'intégrité continu"""
        print("⏱️ Test monitoring d'intégrité continu...")
        
        # Activer le monitoring temps réel
        self.ser.write(b"start_continuous_monitoring\n")
        time.sleep(2)
        
        # Démarrer la collecte d'événements
        monitor_thread = self.start_integrity_monitoring(duration=120)
        
        # Attendre la collecte d'événements
        time.sleep(120)
        self.monitoring_active = False
        monitor_thread.join(timeout=5)
        
        # Analyser les événements collectés
        print(f"  Événements d'intégrité collectés: {len(self.integrity_events)}")
        
        # Vérifications du monitoring continu
        self.assertGreater(len(self.integrity_events), 5, "Pas assez d'événements temps réel détectés")
        
        # Analyser les types d'événements
        event_types = [event['type'] for event in self.integrity_events]
        unique_types = set(event_types)
        
        print(f"  Types d'événements: {', '.join(unique_types)}")
        
        # Vérifier la présence des événements temps réel
        expected_types = ['CHECK', 'VERIFY', 'VALIDATE']
        for event_type in expected_types:
            self.assertIn(event_type, unique_types, f"Type d'événement manquant: {event_type}")
        
        # Analyser les performances temps réel
        check_times = [event['time_ms'] for event in self.integrity_events if event['type'] == 'CHECK']
        if check_times:
            avg_check_time = statistics.mean(check_times)
            max_check_time = max(check_times)
            
            print(f"  Temps vérification: Moy={avg_check_time:.1f}ms, Max={max_check_time}ms")
            
            # Vérifications performance temps réel
            self.assertLess(avg_check_time, 200, f"Temps moyen trop élevé: {avg_check_time:.1f}ms > 200ms")
            self.assertLess(max_check_time, 500, f"Temps max trop élevé: {max_check_time}ms > 500ms")
        
        print("✅ Monitoring d'intégrité continu OK")
    
    def test_03_chunk_verification_coverage(self):
        """Test de couverture de vérification des chunks"""
        print("⏱️ Test couverture vérification chunks...")
        
        # Démarrer la vérification complète avec suivi
        self.ser.write(b"full_chunk_coverage_test\n")
        coverage_log = self.read_serial_until_pattern(r"Couverture chunks terminée", timeout=180)
        
        # Analyser la couverture des chunks
        chunk_verifications = re.findall(r"Chunk (\d+): (\w+) \((\d+)ms\)", coverage_log)
        
        self.assertGreater(len(chunk_verifications), 50, "Pas assez de chunks vérifiés")
        
        # Analyser les résultats par chunk
        verified_chunks = set()
        chunk_times = []
        failed_chunks = []
        
        for chunk_id_str, status, time_str in chunk_verifications:
            chunk_id = int(chunk_id_str)
            chunk_time = int(time_str)
            
            verified_chunks.add(chunk_id)
            chunk_times.append(chunk_time)
            
            if status != 'OK':
                failed_chunks.append(chunk_id)
        
        print(f"  Chunks vérifiés: {len(verified_chunks)}")
        print(f"  Chunks échoués: {len(failed_chunks)}")
        
        # Vérifications couverture Enterprise
        self.assertGreater(len(verified_chunks), 100, f"Couverture insuffisante: {len(verified_chunks)} chunks")
        self.assertLess(len(failed_chunks), len(verified_chunks) * 0.05, "Trop d'échecs de vérification")
        
        # Analyser les performances par chunk
        if chunk_times:
            avg_chunk_time = statistics.mean(chunk_times)
            max_chunk_time = max(chunk_times)
            
            print(f"  Temps par chunk: Moy={avg_chunk_time:.1f}ms, Max={max_chunk_time}ms")
            
            self.assertLess(avg_chunk_time, 50, f"Temps moyen par chunk: {avg_chunk_time:.1f}ms > 50ms")
            self.assertLess(max_chunk_time, 200, f"Temps max par chunk: {max_chunk_time}ms > 200ms")
        
        print("✅ Couverture vérification chunks OK")
    
    def test_04_corruption_detection_latency(self):
        """Test de latence de détection de corruption"""
        print("⏱️ Test latence détection corruption...")
        
        # Injecter des corruptions simulées
        corruption_tests = [
            ("inject_single_bit_flip", "Bit unique"),
            ("inject_byte_corruption", "Byte complet"),
            ("inject_chunk_corruption", "Chunk entier"),
            ("inject_signature_corruption", "Signature")
        ]
        
        detection_latencies = []
        
        for injection_cmd, corruption_type in corruption_tests:
            print(f"  Test corruption {corruption_type}...")
            
            # Injecter la corruption
            self.ser.write(f"{injection_cmd}\n".encode())
            
            # Mesurer le temps de détection
            start_time = time.time()
            detection_log = self.read_serial_until_pattern(r"CORRUPTION DÉTECTÉE", timeout=90)
            detection_time = (time.time() - start_time) * 1000  # en ms
            
            detection_latencies.append(detection_time)
            
            # Vérifier la détection
            self.assertIn("CORRUPTION DÉTECTÉE", detection_log, f"Corruption {corruption_type} non détectée")
            
            # Extraire les détails de détection
            detail_match = re.search(r"Type: (\w+), Chunk: (\d+), Temps: (\d+)ms", detection_log)
            if detail_match:
                detected_type, chunk_id, detection_time_reported = detail_match.groups()
                detection_time_reported = int(detection_time_reported)
                
                print(f"    Détectée en {detection_time:.0f}ms (rapporté: {detection_time_reported}ms)")
                
                # Vérifier la cohérence des temps
                self.assertLess(abs(detection_time - detection_time_reported), 1000, 
                              "Incohérence dans les temps de détection")
            
            # Attendre la récupération avant le test suivant
            recovery_log = self.read_serial_until_pattern(r"Récupération terminée", timeout=30)
            self.assertIn("Récupération terminée", recovery_log, f"Récupération après corruption {corruption_type}")
        
        # Analyser les latences globales
        if detection_latencies:
            avg_latency = statistics.mean(detection_latencies)
            max_latency = max(detection_latencies)
            
            print(f"  Latences détection: Moy={avg_latency:.0f}ms, Max={max_latency:.0f}ms")
            
            # Vérifications latence Enterprise (< 60s)
            self.assertLess(avg_latency, 60000, f"Latence moyenne excessive: {avg_latency:.0f}ms > 60000ms")
            self.assertLess(max_latency, 120000, f"Latence max excessive: {max_latency:.0f}ms > 120000ms")
        
        print("✅ Latence détection corruption OK")
    
    def test_05_predictive_integrity_analysis(self):
        """Test d'analyse prédictive d'intégrité"""
        print("⏱️ Test analyse prédictive d'intégrité...")
        
        # Activer l'analyse prédictive
        self.ser.write(b"enable_predictive_integrity\n")
        predictive_log = self.read_serial_until_pattern(r"Analyse prédictive activée", timeout=60)
        
        # Vérifications activation prédictive
        predictive_checks = [
            "Initialisation modèle prédictif",
            "Configuration ML intégrité",
            "Apprentissage comportemental démarré",
            "Analyse prédictive activée"
        ]
        
        for check in predictive_checks:
            self.assertIn(check, predictive_log, f"Analyse prédictive échoué: {check}")
        
        # Collecter les prédictions pendant 3 minutes
        prediction_log = self.read_serial_until_pattern(r"Prédictions collectées", timeout=180)
        
        # Extraire les prédictions
        predictions = re.findall(r"Prédiction: Chunk (\d+), Risque: (\d+)%, Confiance: (\d+)%", prediction_log)
        
        print(f"  Prédictions collectées: {len(predictions)}")
        
        if predictions:
            risk_scores = []
            confidence_scores = []
            
            for chunk_str, risk_str, confidence_str in predictions:
                risk = int(risk_str)
                confidence = int(confidence_str)
                
                risk_scores.append(risk)
                confidence_scores.append(confidence)
            
            # Analyser les scores
            avg_risk = statistics.mean(risk_scores)
            avg_confidence = statistics.mean(confidence_scores)
            high_risk_count = sum(1 for r in risk_scores if r > 70)
            
            print(f"  Risque moyen: {avg_risk:.1f}%, Confiance moyenne: {avg_confidence:.1f}%")
            print(f"  Chunks à haut risque: {high_risk_count}")
            
            # Vérifications prédictives
            self.assertLess(avg_risk, 30, f"Risque moyen élevé: {avg_risk:.1f}% > 30%")
            self.assertGreater(avg_confidence, 70, f"Confiance faible: {avg_confidence:.1f}% < 70%")
            self.assertLess(high_risk_count, len(predictions) * 0.1, "Trop de chunks à haut risque")
        
        print("✅ Analyse prédictive d'intégrité OK")
    
    def test_06_realtime_performance_benchmarks(self):
        """Test de benchmarks de performance temps réel"""
        print("⏱️ Test benchmarks performance temps réel...")
        
        # Lancer les benchmarks temps réel
        benchmark_tests = [
            ("benchmark_integrity_throughput", "Débit intégrité"),
            ("benchmark_detection_accuracy", "Précision détection"),
            ("benchmark_recovery_time", "Temps récupération"),
            ("benchmark_system_overhead", "Surcharge système")
        ]
        
        benchmark_results = {}
        
        for benchmark_cmd, benchmark_name in benchmark_tests:
            print(f"  Benchmark {benchmark_name}...")
            
            self.ser.write(f"{benchmark_cmd}\n".encode())
            benchmark_log = self.read_serial_until_pattern(f"Benchmark {benchmark_cmd} terminé", timeout=120)
            
            # Extraire les résultats selon le type de benchmark
            if "throughput" in benchmark_cmd:
                result_match = re.search(r"Débit: (\d+) chunks/s", benchmark_log)
                if result_match:
                    throughput = int(result_match.group(1))
                    benchmark_results[benchmark_name] = throughput
                    print(f"    Débit: {throughput} chunks/s")
                    self.assertGreater(throughput, 10, f"Débit insuffisant: {throughput} chunks/s")
            
            elif "accuracy" in benchmark_cmd:
                result_match = re.search(r"Précision: ([\d.]+)%", benchmark_log)
                if result_match:
                    accuracy = float(result_match.group(1))
                    benchmark_results[benchmark_name] = accuracy
                    print(f"    Précision: {accuracy}%")
                    self.assertGreater(accuracy, 99.0, f"Précision insuffisante: {accuracy}%")
            
            elif "recovery" in benchmark_cmd:
                result_match = re.search(r"Temps récupération: (\d+)ms", benchmark_log)
                if result_match:
                    recovery_time = int(result_match.group(1))
                    benchmark_results[benchmark_name] = recovery_time
                    print(f"    Temps récupération: {recovery_time}ms")
                    self.assertLess(recovery_time, 5000, f"Récupération lente: {recovery_time}ms > 5000ms")
            
            elif "overhead" in benchmark_cmd:
                result_match = re.search(r"Surcharge: ([\d.]+)%", benchmark_log)
                if result_match:
                    overhead = float(result_match.group(1))
                    benchmark_results[benchmark_name] = overhead
                    print(f"    Surcharge système: {overhead}%")
                    self.assertLess(overhead, 15.0, f"Surcharge excessive: {overhead}% > 15%")
        
        # Résumé des benchmarks
        print(f"  Benchmarks réalisés: {len(benchmark_results)}")
        for name, value in benchmark_results.items():
            print(f"    {name}: {value}")
        
        print("✅ Benchmarks performance temps réel OK")
    
    def test_07_adaptive_integrity_tuning(self):
        """Test d'ajustement adaptatif des paramètres"""
        print("⏱️ Test ajustement adaptatif intégrité...")
        
        # Activer l'ajustement adaptatif
        self.ser.write(b"enable_adaptive_tuning\n")
        adaptive_log = self.read_serial_until_pattern(r"Ajustement adaptatif activé", timeout=60)
        
        # Vérifier l'activation
        self.assertIn("Algorithme adaptatif initialisé", adaptive_log)
        self.assertIn("Paramètres initiaux configurés", adaptive_log)
        self.assertIn("Ajustement adaptatif activé", adaptive_log)
        
        # Simuler différentes charges système
        load_scenarios = [
            ("low_load", "Charge faible"),
            ("medium_load", "Charge moyenne"),
            ("high_load", "Charge élevée"),
            ("variable_load", "Charge variable")
        ]
        
        adaptation_results = []
        
        for load_cmd, load_desc in load_scenarios:
            print(f"  Test adaptation {load_desc}...")
            
            self.ser.write(f"simulate_{load_cmd}\n".encode())
            time.sleep(30)  # Laisser le système s'adapter
            
            # Obtenir les paramètres adaptés
            self.ser.write(b"get_adaptive_params\n")
            params_log = self.read_serial_until_pattern(r"Paramètres adaptés", timeout=30)
            
            # Extraire les paramètres
            param_match = re.search(r"Intervalle: (\d+)ms, Chunks: (\d+), Seuil: (\d+)", params_log)
            if param_match:
                interval, chunks, threshold = map(int, param_match.groups())
                
                adaptation_results.append({
                    'load': load_desc,
                    'interval': interval,
                    'chunks': chunks,
                    'threshold': threshold
                })
                
                print(f"    Paramètres adaptés: {interval}ms, {chunks} chunks, seuil {threshold}")
        
        # Vérifier que l'adaptation fonctionne
        if len(adaptation_results) >= 2:
            # Comparer charge faible vs charge élevée
            low_load_result = next((r for r in adaptation_results if 'faible' in r['load']), None)
            high_load_result = next((r for r in adaptation_results if 'élevée' in r['load']), None)
            
            if low_load_result and high_load_result:
                # En charge élevée, l'intervalle devrait augmenter ou les chunks diminuer
                interval_adapted = high_load_result['interval'] >= low_load_result['interval']
                chunks_adapted = high_load_result['chunks'] <= low_load_result['chunks']
                
                self.assertTrue(interval_adapted or chunks_adapted, 
                              "Pas d'adaptation détectée entre charge faible et élevée")
                
                print(f"    Adaptation détectée: Intervalle {low_load_result['interval']}→{high_load_result['interval']}ms")
        
        print("✅ Ajustement adaptatif intégrité OK")

def run_realtime_integrity_tests():
    """Exécute tous les tests d'intégrité temps réel"""
    print("⏱️ Démarrage des tests d'intégrité temps réel SecureIoT-VIF Enterprise")
    print("=" * 70)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFRealTimeIntegrityTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé des tests temps réel
    print("=" * 70)
    if result.wasSuccessful():
        print("✅ Tous les tests d'intégrité temps réel sont passés avec succès!")
        print("⏱️ SecureIoT-VIF Enterprise validation temps réel complète")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_realtime_integrity_tests()
    exit(0 if success else 1)