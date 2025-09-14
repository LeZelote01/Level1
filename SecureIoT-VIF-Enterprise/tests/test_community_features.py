#!/usr/bin/env python3
"""
Tests des fonctionnalités de base (Community) pour SecureIoT-VIF Enterprise Edition

Tests Community adaptés pour Enterprise :
- Vérification que toutes les fonctionnalités Community sont présentes
- Tests de compatibilité descendante
- Validation de la coexistence Community/Enterprise
"""

import unittest
import serial
import time
import re
import json
from pathlib import Path

class SecureIoTVIFCommunityFeaturesTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests Community"""
        cls.serial_port = "/dev/ttyUSB0"
        cls.baudrate = 115200
        cls.timeout = 60
        
    def setUp(self):
        """Configuration avant chaque test Community"""
        try:
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=self.timeout)
            time.sleep(2)
        except serial.SerialException:
            self.skipTest(f"Port série {self.serial_port} non disponible")
    
    def tearDown(self):
        """Nettoyage après chaque test Community"""
        if hasattr(self, 'ser'):
            self.ser.close()
    
    def read_serial_until_pattern(self, pattern, timeout=30):
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
    
    def test_01_basic_boot_sequence(self):
        """Test de la séquence de démarrage basique Community"""
        print("🎓 Test séquence de démarrage basique...")
        
        # Redémarrer l'ESP32
        self.ser.setDTR(False)
        time.sleep(0.1)
        self.ser.setDTR(True)
        
        # Attendre les messages de démarrage de base
        boot_log = self.read_serial_until_pattern(r"Système initialisé", timeout=45)
        
        # Vérifications Community de base (doivent être présentes dans Enterprise)
        community_checks = [
            "Démarrage SecureIoT-VIF",
            "Initialisation du gestionnaire crypto",
            "Vérificateur d'intégrité initialisé", 
            "Gestionnaire d'attestation initialisé",
            "Gestionnaire de capteurs initialisé",
            "Système initialisé"
        ]
        
        for check in community_checks:
            self.assertIn(check, boot_log, f"Fonctionnalité Community manquante: {check}")
        
        print("✅ Séquence de démarrage basique OK")
    
    def test_02_basic_crypto_operations(self):
        """Test des opérations crypto de base Community"""
        print("🎓 Test opérations crypto de base...")
        
        # Tester les opérations crypto basiques
        self.ser.write(b"crypto_basic_test\n")
        crypto_log = self.read_serial_until_pattern(r"Tests crypto de base terminés", timeout=60)
        
        # Vérifications crypto Community
        crypto_checks = [
            "Test crypto de base démarré",
            "AES-256 encryption: OK",
            "AES-256 decryption: OK", 
            "SHA-256 hash: OK",
            "Random generation: OK",
            "Tests crypto de base terminés"
        ]
        
        for check in crypto_checks:
            self.assertIn(check, crypto_log, f"Opération crypto de base échouée: {check}")
        
        # Vérifier les performances de base (moins strictes que Enterprise)
        perf_match = re.search(r"Performance crypto: (\d+)ms", crypto_log)
        if perf_match:
            crypto_time = int(perf_match.group(1))
            self.assertLess(crypto_time, 500, f"Performance crypto de base lente: {crypto_time}ms > 500ms")
        
        print("✅ Opérations crypto de base OK")
    
    def test_03_basic_integrity_verification(self):
        """Test de vérification d'intégrité de base Community"""
        print("🎓 Test vérification d'intégrité de base...")
        
        # Tester la vérification d'intégrité au démarrage (Community)
        self.ser.write(b"integrity_basic_check\n")
        integrity_log = self.read_serial_until_pattern(r"Vérification de base terminée", timeout=90)
        
        # Vérifications intégrité Community
        integrity_checks = [
            "Démarrage vérification de base",
            "Lecture métadonnées firmware",
            "Calcul hash firmware",
            "Vérification signature",
            "Vérification de base terminée"
        ]
        
        for check in integrity_checks:
            self.assertIn(check, integrity_log, f"Vérification intégrité de base échouée: {check}")
        
        # Vérifier le résultat
        self.assertIn("Intégrité: OK", integrity_log, "Intégrité firmware compromise")
        
        # Extraire les statistiques de base
        stats_match = re.search(r"Firmware: (\d+) bytes, Hash: OK, Signature: OK, Temps: (\d+)ms", integrity_log)
        if stats_match:
            firmware_size = int(stats_match.group(1))
            verification_time = int(stats_match.group(2))
            
            print(f"  Firmware: {firmware_size} bytes, Temps: {verification_time}ms")
            
            # Vérifications Community (moins strictes)
            self.assertGreater(firmware_size, 100000, "Firmware trop petit")
            self.assertLess(verification_time, 10000, f"Vérification trop lente: {verification_time}ms > 10000ms")
        
        print("✅ Vérification d'intégrité de base OK")
    
    def test_04_basic_attestation(self):
        """Test d'attestation de base Community"""
        print("🎓 Test attestation de base...")
        
        # Tester l'attestation de base (sur demande)
        self.ser.write(b"attestation_basic_test\n")
        attestation_log = self.read_serial_until_pattern(r"Attestation de base terminée", timeout=60)
        
        # Vérifications attestation Community
        attestation_checks = [
            "Démarrage attestation de base",
            "Génération challenge",
            "Calcul réponse attestation",
            "Vérification réponse",
            "Attestation de base terminée"
        ]
        
        for check in attestation_checks:
            self.assertIn(check, attestation_log, f"Attestation de base échouée: {check}")
        
        # Vérifier le résultat
        self.assertIn("Attestation: VALIDE", attestation_log, "Attestation invalide")
        
        print("✅ Attestation de base OK")
    
    def test_05_basic_sensor_reading(self):
        """Test de lecture capteurs de base Community"""
        print("🎓 Test lecture capteurs de base...")
        
        # Tester la lecture des capteurs
        self.ser.write(b"sensor_basic_reading\n")
        sensor_log = self.read_serial_until_pattern(r"Lecture capteur terminée", timeout=30)
        
        # Vérifications capteurs Community
        sensor_checks = [
            "Initialisation capteur DHT22",
            "Configuration GPIO",
            "Lecture capteur démarrée",
            "Lecture capteur terminée"
        ]
        
        for check in sensor_checks:
            self.assertIn(check, sensor_log, f"Lecture capteur de base échouée: {check}")
        
        # Extraire les valeurs
        reading_match = re.search(r"Température: ([\d.-]+)°C, Humidité: ([\d.-]+)%", sensor_log)
        if reading_match:
            temp = float(reading_match.group(1))
            humidity = float(reading_match.group(2))
            
            print(f"  Lecture: {temp}°C, {humidity}%")
            
            # Vérifier les plages valides Community (DHT22)
            self.assertGreaterEqual(temp, -40.0, "Température hors plage DHT22")
            self.assertLessEqual(temp, 80.0, "Température hors plage DHT22")
            self.assertGreaterEqual(humidity, 0.0, "Humidité hors plage DHT22")
            self.assertLessEqual(humidity, 100.0, "Humidité hors plage DHT22")
        
        print("✅ Lecture capteurs de base OK")
    
    def test_06_basic_anomaly_detection(self):
        """Test de détection d'anomalies de base Community"""
        print("🎓 Test détection d'anomalies de base...")
        
        # Configurer la détection par seuils fixes (Community)
        self.ser.write(b"anomaly_basic_config\n")
        time.sleep(2)
        
        # Simuler des données pour détecter des anomalies
        self.ser.write(b"anomaly_basic_test\n")
        anomaly_log = self.read_serial_until_pattern(r"Test anomalies de base terminé", timeout=60)
        
        # Vérifications détection Community
        anomaly_checks = [
            "Configuration seuils fixes",
            "Seuil température:",
            "Seuil humidité:",
            "Test anomalies de base terminé"
        ]
        
        for check in anomaly_checks:
            self.assertIn(check, anomaly_log, f"Détection anomalies de base échouée: {check}")
        
        # Extraire la configuration des seuils
        temp_threshold_match = re.search(r"Seuil température: ([\d.]+)°C", anomaly_log)
        hum_threshold_match = re.search(r"Seuil humidité: ([\d.]+)%", anomaly_log)
        
        if temp_threshold_match and hum_threshold_match:
            temp_threshold = float(temp_threshold_match.group(1))
            hum_threshold = float(hum_threshold_match.group(1))
            
            print(f"  Seuils: ±{temp_threshold}°C, ±{hum_threshold}%")
            
            # Vérifier des seuils raisonnables
            self.assertGreater(temp_threshold, 0, "Seuil température invalide")
            self.assertGreater(hum_threshold, 0, "Seuil humidité invalide")
        
        print("✅ Détection d'anomalies de base OK")
    
    def test_07_basic_configuration(self):
        """Test de configuration de base Community"""
        print("🎓 Test configuration de base...")
        
        # Obtenir la configuration Community
        self.ser.write(b"get_basic_config\n")
        config_log = self.read_serial_until_pattern(r"Configuration de base", timeout=30)
        
        # Vérifications configuration Community
        config_checks = [
            "Mode: Community compatible",
            "Crypto: Software",
            "Intégrité: Boot seulement",
            "Attestation: Sur demande",
            "Anomalies: Seuils fixes"
        ]
        
        # Note: En Enterprise, ces modes peuvent être disponibles en compatibilité
        config_present = []
        for check in config_checks:
            if check in config_log:
                config_present.append(check)
        
        print(f"  Modes Community disponibles: {len(config_present)}/{len(config_checks)}")
        
        # En Enterprise, au moins quelques modes Community devraient être disponibles
        self.assertGreater(len(config_present), 2, "Pas assez de compatibilité Community")
        
        print("✅ Configuration de base OK")
    
    def test_08_backward_compatibility(self):
        """Test de compatibilité descendante Community"""
        print("🎓 Test compatibilité descendante...")
        
        # Tester les commandes Community classiques
        community_commands = [
            ("version", "Version"),
            ("status", "État système"),
            ("info", "Informations"),
            ("help", "Aide")
        ]
        
        compatible_commands = 0
        
        for cmd, desc in community_commands:
            self.ser.write(f"{cmd}\n".encode())
            response_log = self.read_serial_until_pattern(f"{desc}|{cmd.upper()}", timeout=15)
            
            if desc in response_log or cmd.upper() in response_log:
                compatible_commands += 1
                print(f"  Commande '{cmd}': OK")
            else:
                print(f"  Commande '{cmd}': Non supportée")
        
        # Vérifier qu'au moins la majorité des commandes Community fonctionnent
        compatibility_rate = (compatible_commands / len(community_commands)) * 100
        print(f"  Taux de compatibilité: {compatibility_rate:.1f}%")
        
        self.assertGreater(compatibility_rate, 75, f"Compatibilité insuffisante: {compatibility_rate:.1f}% < 75%")
        
        print("✅ Compatibilité descendante OK")
    
    def test_09_community_performance_baseline(self):
        """Test des performances de base Community"""
        print("🎓 Test performances de base Community...")
        
        # Mesurer les performances en mode Community
        self.ser.write(b"performance_community_baseline\n")
        perf_log = self.read_serial_until_pattern(r"Baseline Community terminé", timeout=90)
        
        # Extraire les métriques Community
        community_metrics = [
            (r"Boot time baseline: (\d+)ms", 15000, "Temps démarrage"),
            (r"Crypto baseline: (\d+)ms", 1000, "Crypto de base"),
            (r"Integrity baseline: (\d+)ms", 5000, "Intégrité de base"),
            (r"Sensor baseline: (\d+)ms", 2000, "Lecture capteur")
        ]
        
        baseline_results = {}
        
        for pattern, max_time, metric_name in community_metrics:
            match = re.search(pattern, perf_log)
            if match:
                measured_time = int(match.group(1))
                baseline_results[metric_name] = measured_time
                
                print(f"  {metric_name}: {measured_time}ms")
                
                # Vérifications plus souples pour Community
                self.assertLess(measured_time, max_time, 
                              f"{metric_name} Community trop lent: {measured_time}ms > {max_time}ms")
        
        print(f"  Métriques Community collectées: {len(baseline_results)}")
        
        print("✅ Performances de base Community OK")
    
    def test_10_community_feature_completeness(self):
        """Test de complétude des fonctionnalités Community"""
        print("🎓 Test complétude fonctionnalités Community...")
        
        # Vérifier que toutes les fonctionnalités Community sont présentes
        self.ser.write(b"list_community_features\n")
        features_log = self.read_serial_until_pattern(r"Fonctionnalités Community listées", timeout=30)
        
        # Liste des fonctionnalités Community attendues
        expected_features = [
            "Crypto Software",
            "Intégrité Boot",
            "Attestation Demande",
            "Capteurs DHT22",
            "Anomalies Seuils",
            "Configuration Basique",
            "Tests Unitaires",
            "Documentation"
        ]
        
        available_features = []
        
        for feature in expected_features:
            if feature in features_log:
                available_features.append(feature)
        
        completeness = (len(available_features) / len(expected_features)) * 100
        
        print(f"  Fonctionnalités Community disponibles: {len(available_features)}/{len(expected_features)}")
        print(f"  Complétude: {completeness:.1f}%")
        
        # En Enterprise, toutes les fonctionnalités Community devraient être disponibles
        self.assertGreater(completeness, 90, f"Complétude Community insuffisante: {completeness:.1f}% < 90%")
        
        for feature in available_features:
            print(f"    ✅ {feature}")
        
        missing_features = set(expected_features) - set(available_features)
        for feature in missing_features:
            print(f"    ❌ {feature}")
        
        print("✅ Complétude fonctionnalités Community OK")

def run_community_features_tests():
    """Exécute tous les tests de fonctionnalités Community"""
    print("🎓 Démarrage des tests de fonctionnalités Community dans Enterprise")
    print("=" * 65)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFCommunityFeaturesTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé des tests Community
    print("=" * 65)
    if result.wasSuccessful():
        print("✅ Tous les tests de fonctionnalités Community sont passés avec succès!")
        print("🎓 Compatibilité Community dans Enterprise validée")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_community_features_tests()
    exit(0 if success else 1)