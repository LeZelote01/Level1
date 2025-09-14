#!/usr/bin/env python3
"""
Tests de validation matérielle pour SecureIoT-VIF Enterprise Edition

Validation hardware Enterprise :
- Tests conditions environnementales extrêmes
- Validation composants ESP32 avancés
- Tests résistance et fiabilité
- Validation certification industrielle
- Tests EMC/EMI
"""

import unittest
import serial
import time
import re
import json
import math
import statistics
from pathlib import Path
from datetime import datetime

class SecureIoTVIFHardwareTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests hardware"""
        cls.serial_port = "/dev/ttyUSB0"
        cls.baudrate = 115200
        cls.timeout = 120  # Timeout plus long pour tests hardware
        cls.hardware_info = {}
        
    def setUp(self):
        """Configuration avant chaque test hardware"""
        try:
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=self.timeout)
            time.sleep(3)
            self.collect_hardware_info()
        except serial.SerialException:
            self.skipTest(f"Port série {self.serial_port} non disponible")
    
    def tearDown(self):
        """Nettoyage après chaque test hardware"""
        if hasattr(self, 'ser'):
            self.ser.close()
    
    def collect_hardware_info(self):
        """Collecte les informations hardware ESP32"""
        self.ser.write(b"hardware_info\n")
        time.sleep(2)
        
        info_log = ""
        start_time = time.time()
        
        while time.time() - start_time < 10:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                info_log += data
                
                if "Hardware Info Complete" in info_log:
                    break
        
        # Extraire les informations hardware
        patterns = {
            'chip_model': r"Chip Model: (\w+)",
            'chip_revision': r"Chip Revision: (\d+)",
            'cpu_freq': r"CPU Frequency: (\d+) MHz",
            'flash_size': r"Flash Size: (\d+) MB",
            'psram_size': r"PSRAM Size: (\d+) MB",
            'mac_address': r"MAC Address: ([0-9A-F:]+)",
            'chip_id': r"Chip ID: ([0-9A-F]+)"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, info_log)
            if match:
                self.hardware_info[key] = match.group(1)
    
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
    
    def test_01_esp32_chip_validation(self):
        """Test de validation du chip ESP32"""
        print("🔧 Test validation chip ESP32...")
        
        # Vérifier les informations de base du chip
        self.assertIn('chip_model', self.hardware_info, "Modèle de chip non détecté")
        self.assertIn('chip_revision', self.hardware_info, "Révision de chip non détectée")
        
        chip_model = self.hardware_info.get('chip_model', '')
        chip_revision = int(self.hardware_info.get('chip_revision', '0'))
        
        print(f"  Chip: {chip_model}, Révision: {chip_revision}")
        
        # Vérifications Enterprise
        self.assertIn('ESP32', chip_model, "Chip ESP32 requis pour Enterprise")
        self.assertGreaterEqual(chip_revision, 1, "Révision chip trop ancienne pour Enterprise")
        
        # Vérifier la fréquence CPU
        if 'cpu_freq' in self.hardware_info:
            cpu_freq = int(self.hardware_info['cpu_freq'])
            self.assertGreaterEqual(cpu_freq, 240, f"Fréquence CPU insuffisante: {cpu_freq}MHz < 240MHz")
        
        print("✅ Validation chip ESP32 OK")
    
    def test_02_flash_memory_validation(self):
        """Test de validation de la mémoire flash"""
        print("🔧 Test validation mémoire flash...")
        
        # Test de lecture/écriture flash
        self.ser.write(b"flash_test_comprehensive\n")
        flash_log = self.read_serial_until_pattern(r"Test flash terminé", timeout=90)
        
        # Vérifications flash
        flash_checks = [
            "Test flash démarré",
            "Test écriture flash: OK",
            "Test lecture flash: OK", 
            "Test effacement flash: OK",
            "Test intégrité flash: OK",
            "Test flash terminé"
        ]
        
        for check in flash_checks:
            self.assertIn(check, flash_log, f"Test flash échoué: {check}")
        
        # Extraire les métriques de performance flash
        write_match = re.search(r"Écriture flash: (\d+) KB/s", flash_log)
        read_match = re.search(r"Lecture flash: (\d+) KB/s", flash_log)
        
        if write_match:
            write_speed = int(write_match.group(1))
            self.assertGreater(write_speed, 100, f"Vitesse écriture flash insuffisante: {write_speed} KB/s")
        
        if read_match:
            read_speed = int(read_match.group(1))
            self.assertGreater(read_speed, 500, f"Vitesse lecture flash insuffisante: {read_speed} KB/s")
        
        # Vérifier la taille flash
        if 'flash_size' in self.hardware_info:
            flash_size = int(self.hardware_info['flash_size'])
            self.assertGreaterEqual(flash_size, 4, f"Taille flash insuffisante: {flash_size}MB < 4MB")
        
        print("✅ Validation mémoire flash OK")
    
    def test_03_hsm_hardware_validation(self):
        """Test de validation hardware HSM ESP32"""
        print("🔧 Test validation HSM hardware...")
        
        # Test complet HSM hardware
        self.ser.write(b"hsm_hardware_test\n")
        hsm_log = self.read_serial_until_pattern(r"Test HSM hardware terminé", timeout=120)
        
        # Vérifications HSM hardware
        hsm_checks = [
            "Test HSM hardware démarré",
            "TRNG hardware: OK",
            "AES hardware: OK",
            "SHA hardware: OK",
            "RSA hardware: OK",
            "ECDSA hardware: OK",
            "eFuse lecture: OK",
            "eFuse écriture: OK",
            "Test HSM hardware terminé"
        ]
        
        for check in hsm_checks:
            self.assertIn(check, hsm_log, f"Test HSM hardware échoué: {check}")
        
        # Vérifier les performances crypto hardware
        crypto_benchmarks = [
            (r"AES-256 hardware: (\d+) ops/s", 10000, "Performance AES hardware"),
            (r"SHA-256 hardware: (\d+) ops/s", 5000, "Performance SHA hardware"),
            (r"ECDSA-P256 hardware: (\d+) ops/s", 100, "Performance ECDSA hardware"),
            (r"TRNG hardware: (\d+) KB/s", 50, "Performance TRNG hardware")
        ]
        
        for pattern, min_perf, desc in crypto_benchmarks:
            match = re.search(pattern, hsm_log)
            if match:
                performance = int(match.group(1))
                self.assertGreater(performance, min_perf, f"{desc} insuffisante: {performance}")
        
        print("✅ Validation HSM hardware OK")
    
    def test_04_power_consumption_validation(self):
        """Test de validation de la consommation énergétique"""
        print("🔧 Test validation consommation énergétique...")
        
        # Test des différents modes de consommation
        power_modes = [
            ("active_mode", 200, "Mode actif"),
            ("monitoring_mode", 100, "Mode monitoring"),
            ("light_sleep_mode", 50, "Mode sleep léger"),
            ("deep_sleep_mode", 10, "Mode sleep profond")
        ]
        
        power_measurements = {}
        
        for mode, max_consumption, description in power_modes:
            print(f"  Test {description}...")
            
            self.ser.write(f"{mode}_power_test\n".encode())
            power_log = self.read_serial_until_pattern(f"Test {mode} terminé", timeout=60)
            
            # Extraire la consommation
            consumption_match = re.search(rf"{mode}: (\d+)mA", power_log)
            if consumption_match:
                consumption = int(consumption_match.group(1))
                power_measurements[mode] = consumption
                
                print(f"    Consommation {description}: {consumption}mA")
                self.assertLess(consumption, max_consumption, 
                              f"Consommation {description} excessive: {consumption}mA > {max_consumption}mA")
        
        # Vérifier la progression logique des consommations
        modes_order = ["deep_sleep_mode", "light_sleep_mode", "monitoring_mode", "active_mode"]
        prev_consumption = 0
        
        for mode in modes_order:
            if mode in power_measurements:
                current = power_measurements[mode]
                self.assertGreater(current, prev_consumption, 
                                 f"Consommation incohérente: {mode} = {current}mA <= {prev_consumption}mA")
                prev_consumption = current
        
        print("✅ Validation consommation énergétique OK")
    
    def test_05_temperature_stress_validation(self):
        """Test de validation sous stress thermique"""
        print("🔧 Test validation stress thermique...")
        
        # Simuler différentes conditions de température
        temp_conditions = [
            (-20, "cold_stress"),
            (25, "normal_temp"),
            (70, "hot_stress"),
            (85, "extreme_hot")
        ]
        
        for target_temp, test_mode in temp_conditions:
            print(f"  Test température {target_temp}°C...")
            
            # Simuler la condition thermique
            self.ser.write(f"thermal_test_{test_mode}\n".encode())
            thermal_log = self.read_serial_until_pattern(f"Test thermique {test_mode} terminé", timeout=180)
            
            # Vérifications thermiques
            thermal_checks = [
                f"Test thermique {test_mode} démarré",
                "Stabilisation thermique: OK",
                "Performance crypto maintenue",
                "Intégrité système maintenue", 
                f"Test thermique {test_mode} terminé"
            ]
            
            for check in thermal_checks:
                self.assertIn(check, thermal_log, f"Test thermique {target_temp}°C échoué: {check}")
            
            # Vérifier que les performances restent acceptables
            perf_match = re.search(r"Performance dégradation: (\d+)%", thermal_log)
            if perf_match:
                degradation = int(perf_match.group(1))
                max_degradation = 20 if abs(target_temp - 25) > 40 else 10
                self.assertLess(degradation, max_degradation, 
                              f"Dégradation performance excessive à {target_temp}°C: {degradation}% > {max_degradation}%")
        
        print("✅ Validation stress thermique OK")
    
    def test_06_vibration_shock_validation(self):
        """Test de validation résistance vibrations et chocs"""
        print("🔧 Test validation vibrations et chocs...")
        
        # Simuler les tests de vibration/choc industriels
        vibration_tests = [
            ("low_vibration", "5G @ 10-55Hz"),
            ("medium_vibration", "10G @ 10-55Hz"),
            ("high_vibration", "15G @ 10-55Hz"),
            ("shock_test", "50G @ 11ms")
        ]
        
        for test_type, description in vibration_tests:
            print(f"  Test {description}...")
            
            self.ser.write(f"{test_type}\n".encode())
            vibration_log = self.read_serial_until_pattern(f"Test {test_type} terminé", timeout=120)
            
            # Vérifications post-vibration
            vibration_checks = [
                f"Test {test_type} démarré",
                "Système stable après vibration",
                "Capteur fonctionnel",
                "Intégrité mémoire OK",
                "Connexions stables",
                f"Test {test_type} terminé"
            ]
            
            for check in vibration_checks:
                self.assertIn(check, vibration_log, f"Test vibration {description} échoué: {check}")
            
            # Vérifier l'absence d'erreurs critiques
            self.assertNotIn("ERREUR CRITIQUE", vibration_log, f"Erreur critique après {description}")
            self.assertNotIn("SYSTÈME INSTABLE", vibration_log, f"Système instable après {description}")
        
        print("✅ Validation vibrations et chocs OK")
    
    def test_07_emc_emi_validation(self):
        """Test de validation compatibilité électromagnétique"""
        print("🔧 Test validation EMC/EMI...")
        
        # Tests de compatibilité électromagnétique
        emc_tests = [
            ("emi_emission", "Émissions EMI"),
            ("emi_susceptibility", "Susceptibilité EMI"),
            ("esd_protection", "Protection ESD"),
            ("surge_protection", "Protection surtensions")
        ]
        
        for test_type, description in emc_tests:
            print(f"  Test {description}...")
            
            self.ser.write(f"{test_type}_test\n".encode())
            emc_log = self.read_serial_until_pattern(f"Test {test_type} terminé", timeout=90)
            
            # Vérifications EMC
            emc_checks = [
                f"Test {test_type} démarré",
                "Mesures EMC en cours",
                "Niveaux conformes",
                "Système stable",
                f"Test {test_type} terminé"
            ]
            
            for check in emc_checks:
                self.assertIn(check, emc_log, f"Test EMC {description} échoué: {check}")
            
            # Extraire les niveaux de conformité
            conformity_match = re.search(r"Conformité: (\w+)", emc_log)
            if conformity_match:
                conformity = conformity_match.group(1)
                self.assertEqual(conformity, "PASSE", f"Non-conformité EMC {description}: {conformity}")
        
        print("✅ Validation EMC/EMI OK")
    
    def test_08_sensor_precision_validation(self):
        """Test de validation précision capteurs"""
        print("🔧 Test validation précision capteurs...")
        
        # Test de précision et calibration des capteurs
        self.ser.write(b"sensor_precision_test\n")
        sensor_log = self.read_serial_until_pattern(r"Test précision capteurs terminé", timeout=300)
        
        # Collecter les mesures de précision
        temp_measurements = re.findall(r"Temp mesure: ([\d.-]+)°C, Référence: ([\d.-]+)°C", sensor_log)
        humidity_measurements = re.findall(r"Hum mesure: ([\d.-]+)%, Référence: ([\d.-]+)%", sensor_log)
        
        # Analyser la précision température
        if temp_measurements:
            temp_errors = []
            for measured_str, reference_str in temp_measurements:
                measured = float(measured_str)
                reference = float(reference_str)
                error = abs(measured - reference)
                temp_errors.append(error)
            
            avg_temp_error = statistics.mean(temp_errors)
            max_temp_error = max(temp_errors)
            
            print(f"  Erreur température: Moy={avg_temp_error:.2f}°C, Max={max_temp_error:.2f}°C")
            
            # DHT22 précision: ±0.5°C
            self.assertLess(avg_temp_error, 0.5, f"Erreur moyenne température: {avg_temp_error:.2f}°C > 0.5°C")
            self.assertLess(max_temp_error, 1.0, f"Erreur max température: {max_temp_error:.2f}°C > 1.0°C")
        
        # Analyser la précision humidité
        if humidity_measurements:
            humidity_errors = []
            for measured_str, reference_str in humidity_measurements:
                measured = float(measured_str)
                reference = float(reference_str)
                error = abs(measured - reference)
                humidity_errors.append(error)
            
            avg_hum_error = statistics.mean(humidity_errors)
            max_hum_error = max(humidity_errors)
            
            print(f"  Erreur humidité: Moy={avg_hum_error:.2f}%, Max={max_hum_error:.2f}%")
            
            # DHT22 précision: ±2%
            self.assertLess(avg_hum_error, 2.0, f"Erreur moyenne humidité: {avg_hum_error:.2f}% > 2.0%")
            self.assertLess(max_hum_error, 3.0, f"Erreur max humidité: {max_hum_error:.2f}% > 3.0%")
        
        print("✅ Validation précision capteurs OK")
    
    def test_09_long_term_reliability(self):
        """Test de validation fiabilité long terme"""
        print("🔧 Test validation fiabilité long terme...")
        
        # Test de fiabilité sur 24h simulées (accéléré à 10 minutes)
        self.ser.write(b"reliability_test_accelerated\n")
        reliability_log = self.read_serial_until_pattern(r"Test fiabilité terminé", timeout=600)
        
        # Analyser les métriques de fiabilité
        reliability_metrics = {
            'uptime': r"Uptime: ([\d.]+)%",
            'error_rate': r"Taux erreur: ([\d.]+)%", 
            'performance_drift': r"Dérive performance: ([\d.]+)%",
            'memory_stability': r"Stabilité mémoire: ([\d.]+)%"
        }
        
        results = {}
        for metric, pattern in reliability_metrics.items():
            match = re.search(pattern, reliability_log)
            if match:
                value = float(match.group(1))
                results[metric] = value
                print(f"  {metric}: {value}%")
        
        # Vérifications fiabilité Enterprise
        if 'uptime' in results:
            self.assertGreater(results['uptime'], 99.9, f"Uptime insuffisant: {results['uptime']}% < 99.9%")
        
        if 'error_rate' in results:
            self.assertLess(results['error_rate'], 0.1, f"Taux erreur élevé: {results['error_rate']}% > 0.1%")
        
        if 'performance_drift' in results:
            self.assertLess(results['performance_drift'], 5.0, f"Dérive performance: {results['performance_drift']}% > 5.0%")
        
        if 'memory_stability' in results:
            self.assertGreater(results['memory_stability'], 99.5, f"Stabilité mémoire: {results['memory_stability']}% < 99.5%")
        
        print("✅ Validation fiabilité long terme OK")

def run_hardware_tests():
    """Exécute tous les tests de validation hardware"""
    print("🔧 Démarrage des tests de validation hardware SecureIoT-VIF Enterprise")
    print("=" * 70)
    
    # Créer la suite de tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(SecureIoTVIFHardwareTests)
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Résumé des tests hardware
    print("=" * 70)
    if result.wasSuccessful():
        print("✅ Tous les tests de validation hardware sont passés avec succès!")
        print("🔧 SecureIoT-VIF Enterprise validé pour usage industriel")
    else:
        print(f"❌ {len(result.failures)} tests échoués, {len(result.errors)} erreurs")
        
        for test, error in result.failures + result.errors:
            print(f"❌ {test}: {error}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_hardware_tests()
    exit(0 if success else 1)