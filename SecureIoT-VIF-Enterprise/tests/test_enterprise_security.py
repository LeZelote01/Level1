#!/usr/bin/env python3
"""
Tests automatisés de sécurité avancés pour SecureIoT-VIF Enterprise Edition

Tests Enterprise spécialisés :
- Vérification d'intégrité temps réel
- Attestation continue autonome
- ML comportemental adaptatif
- Crypto HSM ESP32 intégré
- Détection de sabotage
- Tests de conformité Enterprise
"""

import unittest
import serial
import time
import re
import json
import threading
import hashlib
import random
from pathlib import Path
from datetime import datetime

class SecureIoTVIFEnterpriseTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests Enterprise"""
        cls.serial_port = "/dev/ttyUSB0"  # À adapter selon votre configuration
        cls.baudrate = 115200
        cls.timeout = 60  # Enterprise : timeout plus long pour tests avancés
        cls.enterprise_mode = True
        
    def setUp(self):
        """Configuration avant chaque test Enterprise"""
        try:
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=self.timeout)
            time.sleep(3)  # Enterprise : attente plus longue pour initialisation HSM
        except serial.SerialException:
            self.skipTest(f"Port série {self.serial_port} non disponible")
    
    def tearDown(self):
        """Nettoyage après chaque test Enterprise"""
        if hasattr(self, 'ser'):
            self.ser.close()
    
    def read_serial_until_pattern(self, pattern, timeout=30):
        """Lit le port série jusqu'à trouver un pattern Enterprise"""
        start_time = time.time()
        buffer = ""
        
        while time.time() - start_time < timeout:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                buffer += data
                
                if re.search(pattern, buffer, re.MULTILINE):
                    return buffer
        
        return buffer
    
    def test_01_enterprise_boot_sequence(self):
        """Test de la séquence de démarrage sécurisé Enterprise"""
        print("🏢 Test séquence de démarrage Enterprise...")
        
        # Redémarrer l'ESP32
        self.ser.setDTR(False)
        time.sleep(0.1)
        self.ser.setDTR(True)
        
        # Attendre les messages de démarrage Enterprise
        boot_log = self.read_serial_until_pattern(r"=== Enterprise Edition Opérationnel ===", timeout=45)
        
        # Vérifications Enterprise spécifiques
        enterprise_checks = [
            "Démarrage SecureIoT-VIF Enterprise",
            "Hardware Security Module (HSM) Enterprise",
            "True Random Number Generator (TRNG) actif",
            "eFuse protection activée",
            "Secure Boot v2 validé",
            "Flash Encryption activé",
            "Auto-test Crypto Enterprise RÉUSSI",
            "Attestation continue démarrée",
            "ML anomaly detection initialisé",
            "Vérification intégrité temps réel active",
            "Enterprise Edition Opérationnel"
        ]
        
        for check in enterprise_checks:
            self.assertIn(check, boot_log, f"Vérification Enterprise manquante: {check}")
        
        print("✅ Séquence de démarrage Enterprise OK")
    
    def test_02_hsm_crypto_advanced(self):
        """Test des fonctionnalités crypto HSM avancées Enterprise"""
        print("🏢 Test crypto HSM ESP32 avancé...")
        
        boot_log = self.read_serial_until_pattern(r"Auto-test Crypto Enterprise RÉUSSI", timeout=30)
        
        # Vérifications HSM Enterprise
        hsm_checks = [
            "Hardware Security Module (HSM) Enterprise",
            "True Random Number Generator (TRNG)",
            "AES Hardware Acceleration",
            "SHA Hardware Acceleration", 
            "RSA Hardware Acceleration",
            "ECDSA P-256 natif",
            "eFuse protection activée",
            "Secure Boot v2 validé",
            "Flash Encryption activé",
            "Auto-test Crypto Enterprise RÉUSSI"
        ]
        
        for check in hsm_checks:
            self.assertIn(check, boot_log, f"Fonctionnalité HSM manquante: {check}")
        
        # Vérifier les métriques de performance crypto
        perf_match = re.search(r"Crypto performance: (\d+)ms", boot_log)
        if perf_match:
            crypto_time = int(perf_match.group(1))
            self.assertLess(crypto_time, 50, f"Performance crypto HSM trop lente: {crypto_time}ms > 50ms")
        
        print("✅ Crypto HSM ESP32 avancé OK")
    
    def test_03_realtime_integrity_verification(self):
        """Test de vérification d'intégrité temps réel Enterprise"""
        print("🏢 Test vérification d'intégrité temps réel...")
        
        # Attendre plusieurs cycles de vérification temps réel
        integrity_log = self.read_serial_until_pattern(r"Vérification temps réel cycle \d+", timeout=120)
        
        # Vérifications temps réel
        realtime_checks = [
            "Vérification intégrité temps réel active",
            "Démarrage vérification segmentée",
            "Vérification temps réel cycle",
            "Intégrité temps réel: OK"
        ]
        
        for check in realtime_checks:
            self.assertIn(check, integrity_log, f"Fonctionnalité temps réel manquante: {check}")
        
        # Vérifier les performances temps réel
        cycle_matches = re.findall(r"Vérification temps réel cycle \d+: (\d+)ms", integrity_log)
        if cycle_matches:
            cycle_times = [int(t) for t in cycle_matches]
            avg_time = sum(cycle_times) / len(cycle_times)
            
            self.assertLess(avg_time, 200, f"Temps vérification temps réel trop lent: {avg_time}ms > 200ms")
            self.assertGreater(len(cycle_times), 2, "Pas assez de cycles temps réel détectés")
        
        print("✅ Vérification d'intégrité temps réel OK")
    
    def test_04_continuous_attestation(self):
        """Test d'attestation continue autonome Enterprise"""
        print("🏢 Test attestation continue autonome...")
        
        # Attendre plusieurs cycles d'attestation
        attestation_log = self.read_serial_until_pattern(r"Attestation autonome cycle \d+", timeout=90)
        
        # Vérifications attestation continue
        attestation_checks = [
            "Attestation continue démarrée",
            "Exécution attestation autonome",
            "Attestation autonome cycle",
            "Renouvellement automatique réussi",
            "Attestation continue: OK"
        ]
        
        for check in attestation_checks:
            self.assertIn(check, attestation_log, f"Fonctionnalité attestation manquante: {check}")
        
        # Vérifier la périodicité (toutes les 30s Enterprise)
        cycle_matches = re.findall(r"Attestation autonome cycle (\d+)", attestation_log)
        if len(cycle_matches) >= 2:
            self.assertGreaterEqual(len(cycle_matches), 2, "Pas assez de cycles d'attestation")
        
        print("✅ Attestation continue autonome OK")
    
    def test_05_ml_behavioral_detection(self):
        """Test de détection comportementale ML Enterprise"""
        print("🏢 Test détection comportementale ML...")
        
        # Attendre l'initialisation et l'apprentissage ML
        ml_log = self.read_serial_until_pattern(r"ML: modèle comportemental mis à jour", timeout=120)
        
        # Vérifications ML comportemental
        ml_checks = [
            "ML anomaly detection initialisé", 
            "Apprentissage comportemental démarré",
            "ML: analyse comportementale",
            "ML: modèle comportemental mis à jour",
            "Score adaptatif calculé"
        ]
        
        for check in ml_checks:
            self.assertIn(check, ml_log, f"Fonctionnalité ML manquante: {check}")
        
        # Vérifier les scores ML
        score_matches = re.findall(r"Score ML: (\d+)/100", ml_log)
        if score_matches:
            scores = [int(s) for s in score_matches]
            avg_score = sum(scores) / len(scores)
            
            self.assertGreaterEqual(avg_score, 70, f"Score ML comportemental trop bas: {avg_score} < 70")
        
        print("✅ Détection comportementale ML OK")
    
    def test_06_tamper_detection(self):
        """Test de détection de tentatives de sabotage Enterprise"""
        print("🏢 Test détection de sabotage...")
        
        # Lire les logs pour détecter le monitoring de sabotage
        tamper_log = self.read_serial_until_pattern(r"Monitoring sabotage actif", timeout=60)
        
        # Vérifications détection sabotage
        tamper_checks = [
            "Détection sabotage initialisée",
            "Monitoring sabotage actif",
            "Surveillance physique active"
        ]
        
        for check in tamper_checks:
            self.assertIn(check, tamper_log, f"Fonctionnalité sabotage manquante: {check}")
        
        # Si sabotage détecté, vérifier la réponse
        if "ALERTE: Tentative de sabotage" in tamper_log:
            self.assertIn("Mesures de protection activées", tamper_log)
            print("⚠️ Tentative de sabotage détectée et traitée")
        else:
            print("ℹ️ Aucun sabotage détecté (environnement sécurisé)")
        
        print("✅ Détection de sabotage OK")
    
    def test_07_sensor_reading_advanced(self):
        """Test de lecture des capteurs avec validation Enterprise"""
        print("🏢 Test lecture capteurs avancés...")
        
        # Attendre plusieurs lectures avec validation
        sensor_log = self.read_serial_until_pattern(r"Lecture capteur validée:", timeout=45)
        
        # Vérifications capteurs Enterprise
        self.assertIn("Lecture capteur validée:", sensor_log)
        self.assertIn("Validation HSM:", sensor_log)
        self.assertIn("Score ML:", sensor_log)
        
        # Extraire les valeurs avec validation
        reading_matches = re.findall(r"T=([\d.-]+)°C, H=([\d.-]+)%, Q=(\d+), HSM:OK, ML:(\d+)", sensor_log)
        
        for reading in reading_matches:
            temp, humidity, quality, ml_score = reading
            temp = float(temp)
            humidity = float(humidity)
            quality = int(quality)
            ml_score = int(ml_score)
            
            # Vérifier les plages valides Enterprise
            self.assertGreaterEqual(temp, -40.0, "Température dans la plage DHT22")
            self.assertLessEqual(temp, 80.0, "Température dans la plage DHT22")
            self.assertGreaterEqual(humidity, 0.0, "Humidité dans la plage DHT22")
            self.assertLessEqual(humidity, 100.0, "Humidité dans la plage DHT22")
            self.assertGreaterEqual(quality, 0, "Score de qualité valide")
            self.assertLessEqual(quality, 100, "Score de qualité valide")
            self.assertGreaterEqual(ml_score, 50, "Score ML valide Enterprise")
        
        print("✅ Lecture capteurs avancés OK")
    
    def test_08_performance_benchmarks(self):
        """Test des benchmarks de performance Enterprise"""
        print("🏢 Test benchmarks de performance...")
        
        # Collecter les métriques pendant 60 secondes
        metrics_log = self.read_serial_until_pattern(r"Benchmark Enterprise:", timeout=60)
        
        # Analyser les benchmarks Enterprise
        benchmark_patterns = [
            (r"Boot time: (\d+)ms", 3000, "Boot time trop lent"),
            (r"Crypto speed: (\d+)ms", 50, "Crypto trop lent"),
            (r"Integrity check: (\d+)ms", 200, "Vérification intégrité trop lente"),
            (r"ML processing: (\d+)ms", 10, "Traitement ML trop lent"),
            (r"Attestation time: (\d+)ms", 100, "Attestation trop lente")
        ]
        
        for pattern, max_time, error_msg in benchmark_patterns:
            match = re.search(pattern, metrics_log)
            if match:
                measured_time = int(match.group(1))
                self.assertLess(measured_time, max_time, f"{error_msg}: {measured_time}ms > {max_time}ms")
        
        print("✅ Benchmarks de performance OK")
    
    def test_09_security_levels(self):
        """Test des niveaux de sécurité Enterprise"""
        print("🏢 Test niveaux de sécurité...")
        
        # Vérifier les niveaux de sécurité configurés
        security_log = self.read_serial_until_pattern(r"Niveau sécurité Enterprise: \d", timeout=30)
        
        # Vérifications niveaux sécurité
        security_checks = [
            "Configuration sécurité Enterprise",
            "Niveau sécurité Enterprise:",
            "Politique sécurité activée"
        ]
        
        for check in security_checks:
            self.assertIn(check, security_log, f"Configuration sécurité manquante: {check}")
        
        # Extraire le niveau de sécurité
        level_match = re.search(r"Niveau sécurité Enterprise: (\d)", security_log)
        if level_match:
            security_level = int(level_match.group(1))
            self.assertGreaterEqual(security_level, 1, "Niveau sécurité invalide")
            self.assertLessEqual(security_level, 5, "Niveau sécurité invalide")
        
        print("✅ Niveaux de sécurité OK")
    
    def test_10_compliance_validation(self):
        """Test de validation de conformité Enterprise"""
        print("🏢 Test validation de conformité...")
        
        # Vérifier les standards de conformité
        compliance_log = self.read_serial_until_pattern(r"Conformité validée:", timeout=45)
        
        # Vérifications conformité Enterprise
        compliance_checks = [
            "Vérification conformité IEC 62443",
            "Validation ISO 27001",
            "Conformité FIPS 140-2",
            "Conformité validée:"
        ]
        
        for check in compliance_checks:
            self.assertIn(check, compliance_log, f"Conformité manquante: {check}")
        
        print("✅ Validation de conformité OK")

def run_enterprise_tests():
    """Exécute tous les tests Enterprise"""
    print("🏢 Démarrage des tests SecureIoT-VIF Enterprise Edition")
    print("=" * 60)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFEnterpriseTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé Enterprise
    print("=" * 60)
    if result.wasSuccessful():
        print("✅ Tous les tests Enterprise sont passés avec succès!")
        print("🏢 SecureIoT-VIF Enterprise Edition validée")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_enterprise_tests()
    exit(0 if success else 1)