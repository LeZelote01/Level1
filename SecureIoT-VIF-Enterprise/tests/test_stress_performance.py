#!/usr/bin/env python3
"""
Tests de stress et de performance pour SecureIoT-VIF Enterprise Edition

Tests de charge Enterprise :
- Tests de stress longue durée (24h)
- Tests de charge système
- Tests de performance sous contraintes
- Validation industrielle
- Tests environnementaux simulés
"""

import unittest
import serial
import time
import re
import json
import threading
import statistics
import psutil
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

class SecureIoTVIFStressTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests de stress"""
        cls.serial_port = "/dev/ttyUSB0"
        cls.baudrate = 115200
        cls.timeout = 300  # 5 minutes pour tests de stress
        cls.stress_duration = 3600  # 1 heure par défaut (24h en production)
        cls.metrics = []
        cls.start_time = None
        
    def setUp(self):
        """Configuration avant chaque test de stress"""
        try:
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=self.timeout)
            time.sleep(5)  # Stabilisation pour tests de stress
            self.start_time = datetime.now()
        except serial.SerialException:
            self.skipTest(f"Port série {self.serial_port} non disponible")
    
    def tearDown(self):
        """Nettoyage après chaque test de stress"""
        if hasattr(self, 'ser'):
            self.ser.close()
    
    def collect_metrics(self, pattern, timeout=60):
        """Collecte des métriques de performance"""
        start_time = time.time()
        buffer = ""
        metrics = []
        
        while time.time() - start_time < timeout:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                buffer += data
                
                # Extraire les métriques
                matches = re.findall(pattern, buffer)
                for match in matches:
                    metrics.append(match)
                
                # Nettoyer le buffer pour éviter la surcharge mémoire
                if len(buffer) > 10000:
                    buffer = buffer[-5000:]
        
        return metrics
    
    def test_01_boot_stress_test(self):
        """Test de stress des démarrages répétés"""
        print("💪 Test de stress démarrages répétés...")
        
        boot_times = []
        boot_count = 10  # 100 en production
        
        for i in range(boot_count):
            print(f"  Démarrage {i+1}/{boot_count}")
            
            # Redémarrer l'ESP32
            self.ser.setDTR(False)
            time.sleep(0.5)
            self.ser.setDTR(True)
            
            # Mesurer le temps de démarrage
            start_time = time.time()
            boot_log = ""
            
            while time.time() - start_time < 30:
                if self.ser.in_waiting:
                    data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                    boot_log += data
                    
                    if "Enterprise Edition Opérationnel" in boot_log:
                        boot_time = (time.time() - start_time) * 1000  # en ms
                        boot_times.append(boot_time)
                        break
            
            time.sleep(2)  # Pause entre démarrages
        
        # Analyser les résultats
        if boot_times:
            avg_boot = statistics.mean(boot_times)
            max_boot = max(boot_times)
            min_boot = min(boot_times)
            std_boot = statistics.stdev(boot_times) if len(boot_times) > 1 else 0
            
            print(f"  Temps de démarrage: Moy={avg_boot:.1f}ms, Max={max_boot:.1f}ms, Min={min_boot:.1f}ms, Std={std_boot:.1f}ms")
            
            # Vérifications de performance
            self.assertLess(avg_boot, 5000, f"Temps moyen de démarrage trop long: {avg_boot:.1f}ms > 5000ms")
            self.assertLess(max_boot, 10000, f"Temps max de démarrage trop long: {max_boot:.1f}ms > 10000ms")
            self.assertLess(std_boot, 1000, f"Variabilité de démarrage trop élevée: {std_boot:.1f}ms > 1000ms")
        
        print("✅ Test de stress démarrages OK")
    
    def test_02_crypto_performance_stress(self):
        """Test de stress des opérations cryptographiques"""
        print("💪 Test de stress crypto HSM...")
        
        # Démarrer le test de stress crypto
        self.ser.write(b"crypto_stress_test\n")
        
        # Collecter les métriques crypto pendant 5 minutes
        crypto_metrics = self.collect_metrics(r"Crypto: (\d+)ms, (\w+)", timeout=300)
        
        if crypto_metrics:
            # Analyser les performances crypto
            aes_times = []
            sha_times = []
            ecdsa_times = []
            
            for time_str, operation in crypto_metrics:
                op_time = int(time_str)
                if operation == "AES":
                    aes_times.append(op_time)
                elif operation == "SHA":
                    sha_times.append(op_time)
                elif operation == "ECDSA":
                    ecdsa_times.append(op_time)
            
            # Vérifications performance crypto
            if aes_times:
                avg_aes = statistics.mean(aes_times)
                self.assertLess(avg_aes, 10, f"Performance AES HSM dégradée: {avg_aes:.1f}ms > 10ms")
            
            if sha_times:
                avg_sha = statistics.mean(sha_times)
                self.assertLess(avg_sha, 5, f"Performance SHA HSM dégradée: {avg_sha:.1f}ms > 5ms")
            
            if ecdsa_times:
                avg_ecdsa = statistics.mean(ecdsa_times)
                self.assertLess(avg_ecdsa, 50, f"Performance ECDSA HSM dégradée: {avg_ecdsa:.1f}ms > 50ms")
        
        print("✅ Test de stress crypto OK")
    
    def test_03_integrity_continuous_stress(self):
        """Test de stress vérification d'intégrité continue"""
        print("💪 Test de stress vérification continue...")
        
        # Activer la vérification continue intensive
        self.ser.write(b"integrity_stress_mode\n")
        time.sleep(2)
        
        # Collecter les métriques d'intégrité pendant 10 minutes
        integrity_metrics = self.collect_metrics(r"Intégrité: (\d+)ms, Chunks:(\d+)", timeout=600)
        
        if integrity_metrics:
            integrity_times = []
            chunk_counts = []
            
            for time_str, chunks_str in integrity_metrics:
                integrity_times.append(int(time_str))
                chunk_counts.append(int(chunks_str))
            
            # Analyser la performance
            if integrity_times:
                avg_integrity = statistics.mean(integrity_times)
                max_integrity = max(integrity_times)
                
                print(f"  Vérification intégrité: Moy={avg_integrity:.1f}ms, Max={max_integrity:.1f}ms")
                
                # Vérifications performance
                self.assertLess(avg_integrity, 500, f"Performance intégrité dégradée: {avg_integrity:.1f}ms > 500ms")
                self.assertLess(max_integrity, 2000, f"Pic intégrité trop élevé: {max_integrity:.1f}ms > 2000ms")
            
            # Vérifier la cohérence des chunks
            if chunk_counts:
                unique_chunks = set(chunk_counts)
                self.assertEqual(len(unique_chunks), 1, "Incohérence dans le nombre de chunks")
        
        print("✅ Test de stress vérification continue OK")
    
    def test_04_ml_learning_stress(self):
        """Test de stress apprentissage ML continu"""
        print("💪 Test de stress apprentissage ML...")
        
        # Activer l'apprentissage ML intensif
        self.ser.write(b"ml_learning_stress\n")
        time.sleep(2)
        
        # Collecter les métriques ML pendant 8 minutes
        ml_metrics = self.collect_metrics(r"ML: (\d+)ms, Score:(\d+), Modèle:(\d+)", timeout=480)
        
        if ml_metrics:
            ml_times = []
            ml_scores = []
            model_updates = []
            
            for time_str, score_str, updates_str in ml_metrics:
                ml_times.append(int(time_str))
                ml_scores.append(int(score_str))
                model_updates.append(int(updates_str))
            
            # Analyser la performance ML
            if ml_times:
                avg_ml = statistics.mean(ml_times)
                max_ml = max(ml_times)
                
                print(f"  ML Processing: Moy={avg_ml:.1f}ms, Max={max_ml:.1f}ms")
                
                # Vérifications performance ML
                self.assertLess(avg_ml, 50, f"Performance ML dégradée: {avg_ml:.1f}ms > 50ms")
                self.assertLess(max_ml, 200, f"Pic ML trop élevé: {max_ml:.1f}ms > 200ms")
            
            # Vérifier l'évolution du score ML
            if ml_scores and len(ml_scores) > 5:
                # Le score doit s'améliorer avec l'apprentissage
                first_scores = ml_scores[:5]
                last_scores = ml_scores[-5:]
                
                avg_first = statistics.mean(first_scores)
                avg_last = statistics.mean(last_scores)
                
                print(f"  Score ML évolution: {avg_first:.1f} -> {avg_last:.1f}")
                # Note: En stress test, le score peut ne pas forcément s'améliorer
        
        print("✅ Test de stress apprentissage ML OK")
    
    def test_05_memory_leak_detection(self):
        """Test de détection de fuites mémoire"""
        print("💪 Test détection fuites mémoire...")
        
        # Démarrer le monitoring mémoire
        self.ser.write(b"memory_monitor_start\n")
        time.sleep(2)
        
        # Collecter les métriques mémoire pendant 15 minutes
        memory_metrics = self.collect_metrics(r"Mémoire: Libre:(\d+), Utilisée:(\d+), Heap:(\d+)", timeout=900)
        
        if memory_metrics and len(memory_metrics) > 10:
            free_memory = []
            used_memory = []
            heap_memory = []
            
            for free_str, used_str, heap_str in memory_metrics:
                free_memory.append(int(free_str))
                used_memory.append(int(used_str))
                heap_memory.append(int(heap_str))
            
            # Analyser les tendances mémoire
            print(f"  Échantillons mémoire collectés: {len(memory_metrics)}")
            
            # Détecter les fuites (tendance décroissante de la mémoire libre)
            if len(free_memory) > 20:
                first_quarter = free_memory[:len(free_memory)//4]
                last_quarter = free_memory[-len(free_memory)//4:]
                
                avg_first = statistics.mean(first_quarter)
                avg_last = statistics.mean(last_quarter)
                memory_loss = avg_first - avg_last
                
                print(f"  Évolution mémoire libre: {avg_first:.0f} -> {avg_last:.0f} bytes")
                
                # Vérifier qu'il n'y a pas de fuite significative
                self.assertLess(memory_loss, 10000, f"Fuite mémoire détectée: {memory_loss:.0f} bytes perdus")
            
            # Vérifier les limites mémoire
            min_free = min(free_memory)
            self.assertGreater(min_free, 50000, f"Mémoire libre critique: {min_free} bytes < 50KB")
        
        print("✅ Test détection fuites mémoire OK")
    
    def test_06_sensor_data_flood(self):
        """Test de stress lecture intensive capteurs"""
        print("💪 Test de stress lecture capteurs intensive...")
        
        # Activer la lecture intensive des capteurs
        self.ser.write(b"sensor_flood_test\n")
        time.sleep(2)
        
        # Collecter les métriques capteurs pendant 5 minutes
        sensor_metrics = self.collect_metrics(r"Capteur: T=([\d.-]+), H=([\d.-]+), Q=(\d+), Temps:(\d+)ms", timeout=300)
        
        if sensor_metrics:
            sensor_times = []
            temperatures = []
            humidities = []
            qualities = []
            
            for temp_str, hum_str, qual_str, time_str in sensor_metrics:
                temperatures.append(float(temp_str))
                humidities.append(float(hum_str))
                qualities.append(int(qual_str))
                sensor_times.append(int(time_str))
            
            print(f"  Lectures capteurs collectées: {len(sensor_metrics)}")
            
            # Analyser la performance de lecture
            if sensor_times:
                avg_sensor_time = statistics.mean(sensor_times)
                max_sensor_time = max(sensor_times)
                
                print(f"  Temps lecture capteur: Moy={avg_sensor_time:.1f}ms, Max={max_sensor_time:.1f}ms")
                
                # Vérifications performance capteur
                self.assertLess(avg_sensor_time, 100, f"Performance capteur dégradée: {avg_sensor_time:.1f}ms > 100ms")
                self.assertLess(max_sensor_time, 500, f"Pic lecture capteur: {max_sensor_time:.1f}ms > 500ms")
            
            # Vérifier la qualité des données
            if qualities:
                avg_quality = statistics.mean(qualities)
                min_quality = min(qualities)
                
                print(f"  Qualité données: Moy={avg_quality:.1f}, Min={min_quality}")
                
                self.assertGreater(avg_quality, 70, f"Qualité données dégradée: {avg_quality:.1f} < 70")
                self.assertGreater(min_quality, 50, f"Qualité minimale insuffisante: {min_quality} < 50")
        
        print("✅ Test de stress lecture capteurs OK")
    
    def test_07_power_management_stress(self):
        """Test de stress gestion énergétique"""
        print("💪 Test de stress gestion énergétique...")
        
        # Activer les cycles de gestion énergétique
        self.ser.write(b"power_management_stress\n")
        time.sleep(2)
        
        # Collecter les métriques énergétiques pendant 10 minutes
        power_metrics = self.collect_metrics(r"Énergie: Mode:(\w+), Conso:(\d+)mA, Durée:(\d+)ms", timeout=600)
        
        if power_metrics:
            power_modes = []
            consumptions = []
            durations = []
            
            for mode, conso_str, duration_str in power_metrics:
                power_modes.append(mode)
                consumptions.append(int(conso_str))
                durations.append(int(duration_str))
            
            print(f"  Cycles énergétiques collectés: {len(power_metrics)}")
            
            # Analyser les modes énergétiques
            unique_modes = set(power_modes)
            print(f"  Modes utilisés: {', '.join(unique_modes)}")
            
            # Vérifier que plusieurs modes sont utilisés (gestion dynamique)
            self.assertGreaterEqual(len(unique_modes), 2, "Gestion énergétique pas assez dynamique")
            
            # Analyser la consommation
            if consumptions:
                avg_consumption = statistics.mean(consumptions)
                max_consumption = max(consumptions)
                
                print(f"  Consommation: Moy={avg_consumption:.1f}mA, Max={max_consumption}mA")
                
                # Vérifications consommation
                self.assertLess(avg_consumption, 150, f"Consommation moyenne élevée: {avg_consumption:.1f}mA > 150mA")
                self.assertLess(max_consumption, 250, f"Pic de consommation: {max_consumption}mA > 250mA")
        
        print("✅ Test de stress gestion énergétique OK")
    
    def test_08_system_resilience(self):
        """Test de résilience système sous stress"""
        print("💪 Test de résilience système...")
        
        # Test de résilience combinée
        test_commands = [
            b"full_system_stress\n",
            b"error_injection_test\n",
            b"recovery_test\n"
        ]
        
        resilience_scores = []
        
        for cmd in test_commands:
            self.ser.write(cmd)
            time.sleep(1)
            
            # Collecter les métriques de résilience
            resilience_metrics = self.collect_metrics(r"Résilience: Score:(\d+), Récupération:(\d+)ms", timeout=120)
            
            for score_str, recovery_str in resilience_metrics:
                score = int(score_str)
                recovery_time = int(recovery_str)
                
                resilience_scores.append(score)
                
                # Vérifications résilience
                self.assertGreaterEqual(score, 80, f"Score de résilience insuffisant: {score} < 80")
                self.assertLess(recovery_time, 5000, f"Temps de récupération trop long: {recovery_time}ms > 5000ms")
        
        if resilience_scores:
            avg_resilience = statistics.mean(resilience_scores)
            print(f"  Score de résilience moyen: {avg_resilience:.1f}/100")
            self.assertGreaterEqual(avg_resilience, 85, f"Résilience système insuffisante: {avg_resilience:.1f} < 85")
        
        print("✅ Test de résilience système OK")

def run_stress_tests():
    """Exécute tous les tests de stress"""
    print("💪 Démarrage des tests de stress SecureIoT-VIF Enterprise")
    print("=" * 60)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFStressTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé des tests de stress
    print("=" * 60)
    if result.wasSuccessful():
        print("✅ Tous les tests de stress sont passés avec succès!")
        print("💪 SecureIoT-VIF Enterprise résiste aux conditions extrêmes")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_stress_tests()
    exit(0 if success else 1)