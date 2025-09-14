#!/usr/bin/env python3
"""
Tests automatisés pour le simulateur SecureIoT-VIF
"""

import unittest
import subprocess
import os
import re
import time
import tempfile
from pathlib import Path

class SecureIoTVIFSimulatorTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests"""
        cls.project_dir = Path("/app/SecureIoT-VIF")
        cls.simulator_path = cls.project_dir / "build" / "simulator"
        cls.run_simulator_script = cls.project_dir / "run_simulator.sh"
        cls.generate_demo_script = cls.project_dir / "generate_demo.sh"
        
    def test_01_simulator_compilation(self):
        """Test de compilation du simulateur"""
        print("\n🧪 Test de compilation du simulateur...")
        
        # Supprimer le simulateur existant pour forcer la recompilation
        if self.simulator_path.exists():
            os.remove(self.simulator_path)
        
        # Exécuter le script de compilation
        result = subprocess.run(
            ["bash", str(self.run_simulator_script)],
            capture_output=True,
            text=True
        )
        
        # Vérifier que la compilation a réussi
        self.assertEqual(result.returncode, 0, f"Erreur de compilation: {result.stderr}")
        self.assertIn("Compilation réussie", result.stdout)
        
        # Vérifier que le simulateur existe
        self.assertTrue(self.simulator_path.exists(), "Le simulateur n'a pas été créé")
        self.assertTrue(os.access(self.simulator_path, os.X_OK), "Le simulateur n'est pas exécutable")
        
        print("✅ Compilation du simulateur réussie")
    
    def test_02_simulator_execution(self):
        """Test d'exécution du simulateur"""
        print("\n🧪 Test d'exécution du simulateur...")
        
        # Vérifier que le simulateur existe
        self.assertTrue(self.simulator_path.exists(), "Le simulateur n'existe pas")
        
        # Exécuter le simulateur
        result = subprocess.run(
            [str(self.simulator_path)],
            capture_output=True,
            text=True,
            timeout=60  # 60 secondes max
        )
        
        # Vérifier que l'exécution a réussi
        self.assertEqual(result.returncode, 0, f"Erreur d'exécution: {result.stderr}")
        
        # Vérifier les messages clés
        self.assertIn("SecureIoT-VIF Framework Simulator", result.stdout)
        self.assertIn("Initialisation du système de sécurité", result.stdout)
        self.assertIn("Système initialisé avec succès", result.stdout)
        self.assertIn("Tests de fonctionnement", result.stdout)
        self.assertIn("Simulation temps réel", result.stdout)
        self.assertIn("Statistiques de performance", result.stdout)
        self.assertIn("Démonstration SecureIoT-VIF terminée avec succès", result.stdout)
        
        print("✅ Exécution du simulateur réussie")
        return result.stdout
    
    def test_03_logs_coherence(self):
        """Test de cohérence des logs"""
        print("\n🧪 Test de cohérence des logs...")
        
        # Obtenir les logs d'exécution
        simulator_output = self.test_02_simulator_execution()
        
        # Vérifier la séquence d'initialisation
        init_sequence = [
            "Initialisation du gestionnaire crypto ESP32",
            "Gestionnaire crypto ESP32 initialisé avec succès",
            "Initialisation du vérificateur d'intégrité",
            "Vérificateur d'intégrité initialisé",
            "Initialisation gestionnaire d'attestation",
            "Initialisation gestionnaire de capteurs",
            "Initialisation détecteur d'anomalies",
            "Initialisation gestionnaire d'incidents",
            "SecureIoT-VIF initialisé avec succès"
        ]
        
        for message in init_sequence:
            self.assertIn(message, simulator_output, f"Message manquant: {message}")
        
        # Vérifier les tests de fonctionnement
        test_sequence = [
            "Testing ESP32 Crypto",
            "Auto-test crypto ESP32: Succès",
            "Testing Firmware Integrity Verification",
            "Vérification intégrité: OK",
            "Testing Continuous Attestation",
            "Attestation continue: Succès",
            "Tests de base réussis"
        ]
        
        for message in test_sequence:
            self.assertIn(message, simulator_output, f"Message manquant: {message}")
        
        # Vérifier la simulation temps réel
        self.assertRegex(simulator_output, r"Cycle \d+: T=\d+\.\d+°C, H=\d+\.\d+%")
        
        # Vérifier les statistiques finales
        stats_sequence = [
            "Statistiques de performance",
            "Durée simulation:",
            "Cycles d'exécution:",
            "Lectures capteurs:",
            "Vérifications intégrité:",
            "Attestations:",
            "État système:               ✅ SÉCURISÉ"
        ]
        
        for message in stats_sequence:
            self.assertIn(message, simulator_output, f"Message manquant: {message}")
        
        print("✅ Logs cohérents et complets")
    
    def test_04_demo_generation(self):
        """Test de génération de démo"""
        print("\n🧪 Test de génération de démo...")
        
        # Exécuter le script de génération de démo
        result = subprocess.run(
            ["bash", str(self.generate_demo_script)],
            capture_output=True,
            text=True,
            timeout=120  # 120 secondes max
        )
        
        # Vérifier que la génération a réussi
        self.assertEqual(result.returncode, 0, f"Erreur de génération: {result.stderr}")
        self.assertIn("Démo complète générée avec succès", result.stdout)
        
        # Vérifier que les fichiers de démo existent
        demo_dir = self.project_dir / "demo"
        self.assertTrue(demo_dir.exists(), "Répertoire demo non créé")
        
        # Vérifier le fichier de log de démo
        demo_logs = list(demo_dir.glob("secureiot_vif_demo_*.log"))
        self.assertTrue(len(demo_logs) > 0, "Aucun fichier de log de démo trouvé")
        
        # Vérifier le script de lecture
        play_script = demo_dir / "play_demo.sh"
        self.assertTrue(play_script.exists(), "Script de lecture non créé")
        self.assertTrue(os.access(play_script, os.X_OK), "Script de lecture non exécutable")
        
        # Vérifier le résumé
        summary_file = demo_dir / "DEMO_SUMMARY.md"
        self.assertTrue(summary_file.exists(), "Fichier de résumé non créé")
        
        # Lire le contenu du résumé
        with open(summary_file, 'r') as f:
            summary_content = f.read()
        
        # Vérifier le contenu du résumé
        self.assertIn("Démonstration SecureIoT-VIF", summary_content)
        self.assertIn("Phases de Démonstration", summary_content)
        self.assertIn("Innovations Démontrées", summary_content)
        self.assertIn("Métriques Performance", summary_content)
        
        print("✅ Génération de démo réussie")
    
    def test_05_simulated_components(self):
        """Test des composants simulés"""
        print("\n🧪 Test des composants simulés...")
        
        # Obtenir les logs d'exécution
        simulator_output = self.test_02_simulator_execution()
        
        # Tester le crypto ESP32
        crypto_patterns = [
            r"Initialisation du gestionnaire crypto ESP32",
            r"Auto-test crypto ESP32 réussi",
            r"Gestionnaire crypto ESP32 initialisé avec succès",
            r"Device ID: [0-9A-F:]+, Chip Revision: \d+"
        ]
        
        for pattern in crypto_patterns:
            self.assertRegex(simulator_output, pattern, f"Pattern crypto manquant: {pattern}")
        
        # Tester la vérification d'intégrité
        integrity_patterns = [
            r"Initialisation du vérificateur d'intégrité",
            r"Firmware: \d+ bytes, \d+ chunks",
            r"Démarrage vérification complète du firmware",
            r"Vérification complète terminée: OK \(\d+ ms\)",
            r"Chunks: \d+ total, \d+ vérifiés, \d+ corrompus"
        ]
        
        for pattern in integrity_patterns:
            self.assertRegex(simulator_output, pattern, f"Pattern intégrité manquant: {pattern}")
        
        # Tester les capteurs
        sensor_patterns = [
            r"Initialisation gestionnaire de capteurs",
            r"Configuration DHT22 sur GPIO \d+",
            r"Lecture capteur: T=\d+\.\d+°C, H=\d+\.\d+%, Q=\d+"
        ]
        
        for pattern in sensor_patterns:
            self.assertRegex(simulator_output, pattern, f"Pattern capteur manquant: {pattern}")
        
        # Tester l'attestation
        attestation_patterns = [
            r"Initialisation gestionnaire d'attestation",
            r"Attestation continue réussie"
        ]
        
        for pattern in attestation_patterns:
            self.assertRegex(simulator_output, pattern, f"Pattern attestation manquant: {pattern}")
        
        # Tester la détection d'anomalies
        anomaly_patterns = [
            r"Initialisation détecteur d'anomalies"
        ]
        
        for pattern in anomaly_patterns:
            self.assertRegex(simulator_output, pattern, f"Pattern anomalie manquant: {pattern}")
        
        print("✅ Tous les composants simulés fonctionnent correctement")
    
    def test_06_performance_metrics(self):
        """Test des métriques de performance"""
        print("\n🧪 Test des métriques de performance...")
        
        # Obtenir les logs d'exécution
        simulator_output = self.test_02_simulator_execution()
        
        # Extraire les métriques de performance
        integrity_time_match = re.search(r"Vérification complète terminée: OK \((\d+) ms\)", simulator_output)
        self.assertIsNotNone(integrity_time_match, "Temps de vérification d'intégrité non trouvé")
        
        integrity_time = int(integrity_time_match.group(1))
        self.assertLessEqual(integrity_time, 200, f"Temps de vérification d'intégrité trop long: {integrity_time}ms > 200ms")
        
        # Extraire les statistiques finales
        cycles_match = re.search(r"Cycles d'exécution:\s+(\d+)", simulator_output)
        self.assertIsNotNone(cycles_match, "Nombre de cycles non trouvé")
        
        cycles = int(cycles_match.group(1))
        self.assertGreaterEqual(cycles, 25, f"Nombre de cycles insuffisant: {cycles} < 25")
        
        # Vérifier les métriques dans le rapport final
        metrics_patterns = [
            r"Durée simulation:\s+\d+ secondes",
            r"Cycles d'exécution:\s+\d+",
            r"Lectures capteurs:\s+\d+",
            r"Vérifications intégrité:\s+\d+",
            r"Attestations:\s+\d+"
        ]
        
        for pattern in metrics_patterns:
            self.assertRegex(simulator_output, pattern, f"Métrique manquante: {pattern}")
        
        print("✅ Métriques de performance validées")
    
    def test_07_project_structure(self):
        """Test de la structure du projet"""
        print("\n🧪 Test de la structure du projet...")
        
        # Vérifier les répertoires principaux
        main_dirs = [
            "main",
            "components",
            "simulator",
            "tests",
            "docs",
            "build",
            "demo"
        ]
        
        for dir_name in main_dirs:
            dir_path = self.project_dir / dir_name
            self.assertTrue(dir_path.exists(), f"Répertoire {dir_name} manquant")
        
        # Vérifier les composants
        component_dirs = [
            "secure_element",
            "firmware_verification",
            "attestation",
            "sensor_interface",
            "security_monitor"
        ]
        
        for dir_name in component_dirs:
            dir_path = self.project_dir / "components" / dir_name
            self.assertTrue(dir_path.exists(), f"Composant {dir_name} manquant")
        
        # Vérifier les fichiers principaux
        main_files = [
            "run_simulator.sh",
            "generate_demo.sh",
            "ANALYSE_RAPPORT.md",
            "simulator/simulator.c"
        ]
        
        for file_name in main_files:
            file_path = self.project_dir / file_name
            self.assertTrue(file_path.exists(), f"Fichier {file_name} manquant")
        
        print("✅ Structure du projet validée")

def run_all_tests():
    """Exécute tous les tests"""
    print("\n🚀 Démarrage des tests du simulateur SecureIoT-VIF")
    print("=" * 60)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFSimulatorTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé
    print("=" * 60)
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