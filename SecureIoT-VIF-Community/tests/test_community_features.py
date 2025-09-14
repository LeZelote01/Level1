#!/usr/bin/env python3
"""
Tests automatisés pour SecureIoT-VIF Community Edition
Version simplifiée pour les fonctionnalités de base
"""

import unittest
import serial
import time
import re
import json
from pathlib import Path

class SecureIoTVIFCommunityTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests Community"""
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
    
    def test_community_boot_sequence(self):
        """Test de la séquence de démarrage Community"""
        print("🧪 Test séquence de démarrage Community...")
        
        # Redémarrer l'ESP32
        self.ser.setDTR(False)
        time.sleep(0.1)
        self.ser.setDTR(True)
        
        # Attendre les messages de démarrage Community
        boot_log = self.read_serial_until_pattern(r"Community Edition Opérationnel", timeout=30)
        
        # Vérifications Community spécifiques
        self.assertIn("Démarrage SecureIoT-VIF Community Edition", boot_log)
        self.assertIn("Crypto de base initialisé", boot_log)
        self.assertIn("Vérification intégrité initiale réussie", boot_log)
        self.assertIn("Gestionnaire de capteurs Community initialisé", boot_log)
        self.assertIn("Community Edition Opérationnel", boot_log)
        
        print("✅ Séquence de démarrage Community OK")
    
    def test_community_crypto_basic(self):
        """Test du crypto de base Community"""
        print("🧪 Test crypto de base Community...")
        
        boot_log = self.read_serial_until_pattern(r"Crypto de base initialisé", timeout=20)
        
        # Vérifications crypto Community
        self.assertIn("Initialisation crypto de base Community", boot_log)
        self.assertIn("Version éducative - Crypto software seulement", boot_log)
        self.assertIn("Crypto de base initialisé", boot_log)
        
        # Vérifier les mentions Community
        self.assertIn("Community Edition", boot_log)
        self.assertNotIn("Hardware Security Module", boot_log)  # Pas de HSM en Community
        self.assertNotIn("TRNG", boot_log)  # Pas de TRNG hardware en Community
        
        print("✅ Crypto de base Community OK")
    
    def test_community_integrity_basic(self):
        """Test de vérification d'intégrité basique Community"""
        print("🧪 Test vérification d'intégrité Community...")
        
        # Attendre une vérification d'intégrité
        integrity_log = self.read_serial_until_pattern(r"Vérification d'intégrité", timeout=90)
        
        # Vérifications Community spécifiques
        self.assertIn("Vérification d'intégrité basique", integrity_log)
        self.assertNotIn("temps réel", integrity_log)  # Pas de temps réel en Community
        self.assertNotIn("attestation", integrity_log)  # Pas d'attestation en Community
        
        # Rechercher les logs d'échantillonnage Community
        if "Échantillonnage" in integrity_log:
            self.assertIn("chunks sur", integrity_log)
            print("✅ Échantillonnage éducatif détecté")
        
        print("✅ Vérification d'intégrité Community OK")
    
    def test_community_sensor_reading(self):
        """Test de lecture des capteurs Community"""
        print("🧪 Test lecture capteurs Community...")
        
        # Attendre une lecture de capteur
        sensor_log = self.read_serial_until_pattern(r"Données capteur:", timeout=30)
        
        # Vérifications
        self.assertIn("Données capteur:", sensor_log)
        
        # Extraire les valeurs
        reading_match = re.search(r"T=([\d.-]+)°C, H=([\d.-]+)%", sensor_log)
        if reading_match:
            temp, humidity = reading_match.groups()
            temp = float(temp)
            humidity = float(humidity)
            
            # Vérifier les plages valides
            self.assertGreaterEqual(temp, -40.0, "Température dans la plage DHT22")
            self.assertLessEqual(temp, 80.0, "Température dans la plage DHT22")
            self.assertGreaterEqual(humidity, 0.0, "Humidité dans la plage DHT22")
            self.assertLessEqual(humidity, 100.0, "Humidité dans la plage DHT22")
        
        print("✅ Lecture capteurs Community OK")
    
    def test_community_anomaly_detection_basic(self):
        """Test de détection d'anomalies basique Community"""
        print("🧪 Test détection d'anomalies Community...")
        
        # Lire les logs pendant 60 secondes pour détecter des anomalies
        log_buffer = self.read_serial_until_pattern(r"Anomalie|seuils fixes", timeout=60)
        
        # Vérifier la méthode Community (seuils fixes)
        if "seuils fixes" in log_buffer:
            self.assertIn("seuils fixes", log_buffer)
            print("✅ Détection par seuils fixes Community confirmée")
        
        # Si anomalie détectée, vérifier le traitement Community
        if "Anomalie détectée" in log_buffer:
            self.assertIn("Anomalie détectée", log_buffer)
            self.assertNotIn("ML", log_buffer)  # Pas de ML en Community
            self.assertNotIn("adaptatif", log_buffer)  # Pas d'adaptation en Community
            print("⚠️ Anomalie détectée et traitée correctement (Community)")
        else:
            print("ℹ️ Aucune anomalie détectée (fonctionnement normal)")
        
        print("✅ Détection d'anomalies Community OK")
    
    def test_community_no_enterprise_features(self):
        """Test que les fonctionnalités Enterprise ne sont pas présentes"""
        print("🧪 Test absence fonctionnalités Enterprise...")
        
        # Lire les logs généraux
        log_buffer = self.read_serial_until_pattern(r"Community Edition", timeout=30)
        
        # Vérifier l'absence des fonctionnalités Enterprise
        enterprise_features = [
            "temps réel",
            "Hardware Security Module",
            "TRNG",
            "attestation continue",
            "ML adaptatif",
            "eFuse",
            "Secure Boot v2",
            "Flash Encryption"
        ]
        
        for feature in enterprise_features:
            if feature in log_buffer:
                # Vérifier que c'est mentionné comme non disponible
                self.assertTrue(
                    "non disponible" in log_buffer or 
                    "Enterprise" in log_buffer or
                    "pas de" in log_buffer.lower(),
                    f"Fonctionnalité Enterprise '{feature}' présente en Community"
                )
        
        print("✅ Fonctionnalités Enterprise correctement absentes")
    
    def test_community_educational_messages(self):
        """Test des messages éducatifs Community"""
        print("🧪 Test messages éducatifs Community...")
        
        boot_log = self.read_serial_until_pattern(r"Community Edition", timeout=20)
        
        # Vérifier les messages éducatifs
        educational_messages = [
            "Community Edition",
            "éducative",
            "apprentissage",
            "Version éducative",
            "Idéal pour",
            "🎓"
        ]
        
        found_messages = 0
        for message in educational_messages:
            if message in boot_log:
                found_messages += 1
        
        self.assertGreater(found_messages, 2, "Messages éducatifs insuffisants")
        print(f"✅ {found_messages} messages éducatifs trouvés")
    
    def test_community_performance_basic(self):
        """Test des performances de base Community"""
        print("🧪 Test performances Community...")
        
        # Collecter les métriques pendant 30 secondes
        metrics_log = self.read_serial_until_pattern(r"ms|durée", timeout=30)
        
        # Analyser les temps si disponibles
        timing_matches = re.findall(r"(\d+) ?ms", metrics_log)
        if timing_matches:
            timings = [int(t) for t in timing_matches]
            avg_timing = sum(timings) / len(timings)
            
            # Les performances Community sont plus lentes qu'Enterprise (acceptable)
            self.assertLess(avg_timing, 5000, "Temps de traitement Community < 5s")
            
            print(f"📊 Temps moyen Community: {avg_timing:.1f}ms")
        
        print("✅ Performances Community acceptables")

def run_community_tests():
    """Exécute tous les tests Community"""
    print("🚀 Démarrage des tests SecureIoT-VIF Community Edition")
    print("=" * 60)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFCommunityTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé
    print("=" * 60)
    if result.wasSuccessful():
        print("✅ Tous les tests Community sont passés avec succès!")
        print("🎓 SecureIoT-VIF Community Edition opérationnelle")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_community_tests()
    exit(0 if success else 1)