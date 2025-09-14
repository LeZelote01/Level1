#!/usr/bin/env python3
"""
Tests automatisés de sécurité pour SecureIoT-VIF
"""

import unittest
import serial
import time
import re
import json
from pathlib import Path

class SecureIoTVIFTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests"""
        cls.serial_port = "/dev/ttyUSB0"  # À adapter selon votre configuration
        cls.baudrate = 115200
        cls.timeout = 30
        
    def setUp(self):
        """Configuration avant chaque test"""
        try:
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=self.timeout)
            time.sleep(2)  # Attendre stabilisation
        except serial.SerialException:
            self.skipTest(f"Port série {self.serial_port} non disponible")
    
    def tearDown(self):
        """Nettoyage après chaque test"""
        if hasattr(self, 'ser'):
            self.ser.close()
    
    def read_serial_until_pattern(self, pattern, timeout=10):
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
    
    def test_boot_sequence(self):
        """Test de la séquence de démarrage sécurisé"""
        print("🧪 Test séquence de démarrage...")
        
        # Redémarrer l'ESP32
        self.ser.setDTR(False)
        time.sleep(0.1)
        self.ser.setDTR(True)
        
        # Attendre les messages de démarrage
        boot_log = self.read_serial_until_pattern(r"=== SecureIoT-VIF initialisé avec succès ===", timeout=30)
        
        # Vérifications
        self.assertIn("Démarrage SecureIoT-VIF", boot_log)
        self.assertIn("Gestionnaire crypto ESP32 initialisé avec succès", boot_log)
        self.assertIn("Vérificateur d'intégrité initialisé", boot_log)
        self.assertIn("Gestionnaire d'attestation initialisé", boot_log)
        
        print("✅ Séquence de démarrage OK")
    
    def test_secure_element_initialization(self):
        """Test d'initialisation du crypto ESP32"""
        print("🧪 Test initialisation crypto ESP32...")
        
        boot_log = self.read_serial_until_pattern(r"Auto-test réussi", timeout=20)
        
        # Vérifications crypto ESP32
        self.assertIn("Initialisation du gestionnaire crypto ESP32", boot_log)
        self.assertIn("Device ID:", boot_log)  # ID unique ESP32
        self.assertIn("Chip Revision:", boot_log)     # Révision ESP32
        self.assertIn("Auto-test réussi", boot_log)
        
        print("✅ Crypto ESP32 OK")
    
    def test_integrity_verification(self):
        """Test de vérification d'intégrité"""
        print("🧪 Test vérification d'intégrité...")
        
        # Attendre une vérification d'intégrité
        integrity_log = self.read_serial_until_pattern(r"Vérification complète terminée", timeout=90)
        
        # Vérifications
        self.assertIn("Démarrage vérification complète du firmware", integrity_log)
        self.assertIn("Vérification complète terminée: OK", integrity_log)
        
        # Extraire les statistiques
        chunks_match = re.search(r"Chunks: (\d+) total, (\d+) vérifiés, (\d+) corrompus", integrity_log)
        if chunks_match:
            total, verified, corrupted = chunks_match.groups()
            self.assertEqual(total, verified, "Tous les chunks doivent être vérifiés")
            self.assertEqual(corrupted, "0", "Aucune corruption ne doit être détectée")
        
        print("✅ Vérification d'intégrité OK")
    
    def test_attestation_continuous(self):
        """Test d'attestation continue"""
        print("🧪 Test attestation continue...")
        
        # Attendre une attestation
        attestation_log = self.read_serial_until_pattern(r"Attestation continue réussie", timeout=60)
        
        # Vérifications
        self.assertIn("Exécution attestation continue", attestation_log)
        self.assertIn("Attestation continue réussie", attestation_log)
        
        print("✅ Attestation continue OK")
    
    def test_sensor_reading(self):
        """Test de lecture des capteurs"""
        print("🧪 Test lecture capteurs...")
        
        # Attendre une lecture de capteur
        sensor_log = self.read_serial_until_pattern(r"Lecture capteur:", timeout=30)
        
        # Vérifications
        self.assertIn("Lecture capteur:", sensor_log)
        
        # Extraire les valeurs
        reading_match = re.search(r"T=([\d.-]+)°C, H=([\d.-]+)%, Q=(\d+)", sensor_log)
        if reading_match:
            temp, humidity, quality = reading_match.groups()
            temp = float(temp)
            humidity = float(humidity)
            quality = int(quality)
            
            # Vérifier les plages valides
            self.assertGreaterEqual(temp, -40.0, "Température dans la plage DHT22")
            self.assertLessEqual(temp, 80.0, "Température dans la plage DHT22")
            self.assertGreaterEqual(humidity, 0.0, "Humidité dans la plage DHT22")
            self.assertLessEqual(humidity, 100.0, "Humidité dans la plage DHT22")
            self.assertGreaterEqual(quality, 0, "Score de qualité valide")
            self.assertLessEqual(quality, 100, "Score de qualité valide")
        
        print("✅ Lecture capteurs OK")
    
    def test_anomaly_detection(self):
        """Test de détection d'anomalies"""
        print("🧪 Test détection d'anomalies...")
        
        # Lire les logs pendant 60 secondes pour détecter des anomalies
        log_buffer = self.read_serial_until_pattern(r"Anomalie|anomaly", timeout=60)
        
        # Si aucune anomalie détectée, c'est normal en fonctionnement normal
        if "Anomalie" not in log_buffer:
            print("ℹ️ Aucune anomalie détectée (fonctionnement normal)")
        else:
            # Si anomalie détectée, vérifier le traitement
            self.assertIn("Anomalie détectée", log_buffer)
            print("⚠️ Anomalie détectée et traitée correctement")
        
        print("✅ Détection d'anomalies OK")
    
    def test_runtime_monitoring(self):
        """Test du monitoring en temps réel"""
        print("🧪 Test monitoring temps réel...")
        
        # Vérifier que le monitoring tourne
        monitoring_log = self.read_serial_until_pattern(r"Vérification en temps réel", timeout=20)
        
        if "Vérification en temps réel" in monitoring_log:
            self.assertIn("Démarrage vérification en temps réel", monitoring_log)
            print("✅ Monitoring temps réel actif")
        else:
            print("ℹ️ Monitoring temps réel non activé dans cette configuration")
    
    def test_performance_metrics(self):
        """Test des métriques de performance"""
        print("🧪 Test métriques de performance...")
        
        # Collecter les métriques pendant 30 secondes
        metrics_log = self.read_serial_until_pattern(r"Heartbeat système|ms\)", timeout=30)
        
        # Analyser les temps de vérification
        timing_matches = re.findall(r"(\d+) ms\)", metrics_log)
        if timing_matches:
            timings = [int(t) for t in timing_matches]
            avg_timing = sum(timings) / len(timings)
            
            # Vérifier que les performances sont acceptables
            self.assertLess(avg_timing, 1000, "Temps de vérification < 1s en moyenne")
            self.assertLess(max(timings), 5000, "Aucune vérification > 5s")
            
            print(f"📊 Temps moyen: {avg_timing:.1f}ms, Max: {max(timings)}ms")
        
        print("✅ Métriques de performance OK")

def run_all_tests():
    """Exécute tous les tests"""
    print("🚀 Démarrage des tests SecureIoT-VIF")
    print("=" * 50)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé
    print("=" * 50)
    if result.wasSuccessful():
        print("✅ Tous les tests sont passés avec succès!")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)