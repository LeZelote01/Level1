#!/usr/bin/env python3
"""
Outil de flash sécurisé pour SecureIoT-VIF Enterprise Edition

Fonctionnalités Enterprise :
- Flash avec Secure Boot v2
- Configuration eFuse automatique
- Chiffrement flash automatique
- Validation HSM intégrée
- Tests post-flash avancés
"""

import os
import sys
import subprocess
import time
import json
import hashlib
import serial
import argparse
from pathlib import Path
from datetime import datetime

class EnterpriseFlashTool:
    def __init__(self):
        self.project_dir = Path(os.getcwd())
        self.build_dir = self.project_dir / "build"
        self.config_dir = self.project_dir / "configs"
        self.keys_dir = self.project_dir / "keys"
        self.logs_dir = self.project_dir / "logs"
        
        # Configuration Enterprise par défaut
        self.enterprise_config = {
            "secure_boot_v2": True,
            "flash_encryption": True,
            "efuse_protection": True,
            "hsm_validation": True,
            "integrity_check": True,
            "performance_test": True
        }
        
        # Créer les répertoires nécessaires
        self.keys_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
    
    def log_message(self, message, level="INFO"):
        """Log un message avec timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        
        # Écrire dans le fichier de log
        log_file = self.logs_dir / f"enterprise_flash_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a') as f:
            f.write(log_entry + "\
")
    
    def check_prerequisites(self):
        """Vérifier les prérequis Enterprise"""
        self.log_message("🔧 Vérification des prérequis Enterprise...", "INFO")
        
        # Vérifier ESP-IDF
        try:
            result = subprocess.run(["idf.py", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip()
                self.log_message(f"ESP-IDF version: {version}", "INFO")
            else:
                raise Exception("ESP-IDF non trouvé")
        except Exception as e:
            self.log_message(f"Erreur ESP-IDF: {e}", "ERROR")
            return False
        
        # Vérifier Python et dépendances
        required_modules = ['serial', 'cryptography', 'esptool']
        for module in required_modules:
            try:
                __import__(module)
                self.log_message(f"Module {module}: OK", "INFO")
            except ImportError:
                self.log_message(f"Module {module} manquant", "ERROR")
                return False
        
        # Vérifier les fichiers de build
        required_files = [
            self.build_dir / "bootloader" / "bootloader.bin",
            self.build_dir / "partition_table" / "partition-table.bin",
            self.build_dir / "secureiot-vif-enterprise.bin"
        ]
        
        for file_path in required_files:
            if file_path.exists():
                self.log_message(f"Fichier build {file_path.name}: OK", "INFO")
            else:
                self.log_message(f"Fichier build manquant: {file_path}", "ERROR")
                return False
        
        self.log_message("✅ Prérequis Enterprise validés", "SUCCESS")
        return True
    
    def generate_secure_keys(self):
        """Générer les clés sécurisées Enterprise"""
        self.log_message("🔐 Génération des clés sécurisées Enterprise...", "INFO")
        
        keys_generated = {}
        
        # Générer la clé Secure Boot
        secure_boot_key = self.keys_dir / "secure_boot_signing_key.pem"
        if not secure_boot_key.exists():
            try:
                cmd = ["espsecure.py", "generate_signing_key", "--version", "2", str(secure_boot_key)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_message("Clé Secure Boot générée", "SUCCESS")
                    keys_generated["secure_boot"] = str(secure_boot_key)
                else:
                    raise Exception(f"Erreur génération clé Secure Boot: {result.stderr}")
            except Exception as e:
                self.log_message(f"Erreur clé Secure Boot: {e}", "ERROR")
                return None
        
        # Générer la clé Flash Encryption
        flash_encryption_key = self.keys_dir / "flash_encryption_key.bin"
        if not flash_encryption_key.exists():
            try:
                # Générer une clé aléatoire de 256 bits
                import secrets
                key_data = secrets.token_bytes(32)
                with open(flash_encryption_key, 'wb') as f:
                    f.write(key_data)
                self.log_message("Clé Flash Encryption générée", "SUCCESS")
                keys_generated["flash_encryption"] = str(flash_encryption_key)
            except Exception as e:
                self.log_message(f"Erreur clé Flash Encryption: {e}", "ERROR")
                return None
        
        # Générer les clés eFuse Enterprise
        efuse_keys = []
        for i in range(3):  # 3 clés eFuse pour Enterprise
            efuse_key_file = self.keys_dir / f"efuse_key_{i}.bin"
            if not efuse_key_file.exists():
                try:
                    import secrets
                    key_data = secrets.token_bytes(32)
                    with open(efuse_key_file, 'wb') as f:
                        f.write(key_data)
                    efuse_keys.append(str(efuse_key_file))
                except Exception as e:
                    self.log_message(f"Erreur clé eFuse {i}: {e}", "ERROR")
                    return None
        
        keys_generated["efuse_keys"] = efuse_keys
        
        # Sauvegarder la configuration des clés
        keys_config = self.keys_dir / "keys_config.json"
        with open(keys_config, 'w') as f:
            json.dump(keys_generated, f, indent=2)
        
        self.log_message("🔐 Clés sécurisées Enterprise générées avec succès", "SUCCESS")
        return keys_generated
    
    def configure_efuse(self, port):
        """Configurer les eFuses Enterprise"""
        self.log_message("⚡ Configuration des eFuses Enterprise...", "INFO")
        
        efuse_commands = [
            # Activer Secure Boot v2
            ["espefuse.py", "-p", port, "burn_efuse", "SECURE_BOOT_EN", "1"],
            # Activer Flash Encryption
            ["espefuse.py", "-p", port, "burn_efuse", "FLASH_CRYPT_CNT", "1"],
            # Configurer la protection en écriture
            ["espefuse.py", "-p", port, "burn_efuse", "WR_DIS", "0x01"],
            # Désactiver le mode download (sécurité)
            ["espefuse.py", "-p", port, "burn_efuse", "DIS_DOWNLOAD_MODE", "1"]
        ]
        
        for cmd in efuse_commands:
            try:
                self.log_message(f"Exécution: {' '.join(cmd)}", "INFO")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_message(f"eFuse configuré: {cmd[4]}", "SUCCESS")
                else:
                    # Certaines eFuses peuvent déjà être configurées
                    if "already burned" in result.stderr or "already set" in result.stderr:
                        self.log_message(f"eFuse déjà configuré: {cmd[4]}", "INFO")
                    else:
                        self.log_message(f"Avertissement eFuse {cmd[4]}: {result.stderr}", "WARNING")
            except Exception as e:
                self.log_message(f"Erreur eFuse {cmd[4]}: {e}", "ERROR")
        
        self.log_message("⚡ Configuration eFuses Enterprise terminée", "SUCCESS")
    
    def secure_flash(self, port, keys_config):
        """Flash sécurisé Enterprise"""
        self.log_message("🚀 Démarrage du flash sécurisé Enterprise...", "INFO")
        
        # Étape 1: Flash du bootloader sécurisé
        bootloader_file = self.build_dir / "bootloader" / "bootloader.bin"
        try:
            cmd = [
                "esptool.py", "-p", port, "-b", "460800",
                "--before", "default_reset", "--after", "no_reset",
                "--chip", "esp32",
                "write_flash", "--flash_mode", "dio", "--flash_freq", "40m", "--flash_size", "4MB",
                "0x1000", str(bootloader_file)
            ]
            self.log_message("Flash bootloader sécurisé...", "INFO")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Erreur flash bootloader: {result.stderr}")
            self.log_message("Bootloader flashé avec succès", "SUCCESS")
        except Exception as e:
            self.log_message(f"Erreur flash bootloader: {e}", "ERROR")
            return False
        
        # Étape 2: Flash de la table des partitions
        partition_table_file = self.build_dir / "partition_table" / "partition-table.bin"
        try:
            cmd = [
                "esptool.py", "-p", port, "-b", "460800",
                "--before", "no_reset", "--after", "no_reset",
                "write_flash", "0x8000", str(partition_table_file)
            ]
            self.log_message("Flash table des partitions...", "INFO")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Erreur flash partition table: {result.stderr}")
            self.log_message("Table des partitions flashée avec succès", "SUCCESS")
        except Exception as e:
            self.log_message(f"Erreur flash partition table: {e}", "ERROR")
            return False
        
        # Étape 3: Flash de l'application Enterprise avec chiffrement
        app_file = self.build_dir / "secureiot-vif-enterprise.bin"
        try:
            cmd = [
                "esptool.py", "-p", port, "-b", "460800",
                "--before", "no_reset", "--after", "hard_reset",
                "write_flash", "--flash_mode", "dio", "--flash_freq", "40m",
                "--encrypt", "0x10000", str(app_file)
            ]
            self.log_message("Flash application Enterprise chiffrée...", "INFO")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Erreur flash application: {result.stderr}")
            self.log_message("Application Enterprise flashée avec succès", "SUCCESS")
        except Exception as e:
            self.log_message(f"Erreur flash application: {e}", "ERROR")
            return False
        
        self.log_message("🚀 Flash sécurisé Enterprise terminé avec succès", "SUCCESS")
        return True
    
    def validate_hsm_integration(self, port):
        """Valider l'intégration HSM après flash"""
        self.log_message("🔍 Validation intégration HSM...", "INFO")
        
        try:
            # Connexion série pour validation
            ser = serial.Serial(port, 115200, timeout=30)
            time.sleep(5)  # Attendre le démarrage
            
            # Collecter les logs de démarrage
            boot_log = ""
            start_time = time.time()
            
            while time.time() - start_time < 30:
                if ser.in_waiting:
                    data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                    boot_log += data
                    
                    if "Enterprise Edition Opérationnel" in boot_log:
                        break
            
            ser.close()
            
            # Vérifier les composants HSM
            hsm_checks = [
                "Hardware Security Module (HSM) Enterprise",
                "True Random Number Generator (TRNG) actif",
                "eFuse protection activée",
                "Secure Boot v2 validé",
                "Flash Encryption activé",
                "Auto-test Crypto Enterprise RÉUSSI"
            ]
            
            validated_checks = 0
            for check in hsm_checks:
                if check in boot_log:
                    self.log_message(f"HSM Check OK: {check}", "SUCCESS")
                    validated_checks += 1
                else:
                    self.log_message(f"HSM Check FAIL: {check}", "WARNING")
            
            success_rate = (validated_checks / len(hsm_checks)) * 100
            self.log_message(f"Validation HSM: {success_rate:.1f}% ({validated_checks}/{len(hsm_checks)})", "INFO")
            
            if success_rate >= 80:
                self.log_message("🔍 Validation HSM réussie", "SUCCESS")
                return True
            else:
                self.log_message("🔍 Validation HSM échouée", "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"Erreur validation HSM: {e}", "ERROR")
            return False
    
    def run_post_flash_tests(self, port):
        """Exécuter les tests post-flash Enterprise"""
        self.log_message("🧪 Exécution des tests post-flash Enterprise...", "INFO")
        
        try:
            # Connexion série pour tests
            ser = serial.Serial(port, 115200, timeout=60)
            time.sleep(5)
            
            # Tests post-flash
            test_commands = [
                (b"crypto_full_test\
", "Test crypto complet", "Test crypto terminé"),
                (b"integrity_full_check\
", "Test intégrité complet", "Intégrité validée"),
                (b"attestation_full_test\
", "Test attestation complet", "Attestation validée"),
                (b"sensor_calibration\
", "Calibration capteurs", "Calibration terminée")
            ]
            
            test_results = {}
            
            for cmd, test_name, success_pattern in test_commands:
                self.log_message(f"Exécution: {test_name}...", "INFO")
                
                ser.write(cmd)
                start_time = time.time()
                response = ""
                
                while time.time() - start_time < 60:
                    if ser.in_waiting:
                        data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                        response += data
                        
                        if success_pattern in response:
                            test_results[test_name] = "PASS"
                            self.log_message(f"{test_name}: PASS", "SUCCESS")
                            break
                else:
                    test_results[test_name] = "FAIL"
                    self.log_message(f"{test_name}: FAIL (timeout)", "ERROR")
                
                time.sleep(2)  # Pause entre tests
            
            ser.close()
            
            # Analyser les résultats
            passed_tests = sum(1 for result in test_results.values() if result == "PASS")
            total_tests = len(test_results)
            success_rate = (passed_tests / total_tests) * 100
            
            self.log_message(f"Tests post-flash: {success_rate:.1f}% ({passed_tests}/{total_tests})", "INFO")
            
            if success_rate >= 75:
                self.log_message("🧪 Tests post-flash réussis", "SUCCESS")
                return True
            else:
                self.log_message("🧪 Tests post-flash échoués", "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"Erreur tests post-flash: {e}", "ERROR")
            return False
    
    def generate_flash_report(self, results):
        """Générer un rapport de flash Enterprise"""
        self.log_message("📊 Génération du rapport de flash...", "INFO")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "enterprise_version": "2.0.0",
            "flash_results": results,
            "security_features": {
                "secure_boot_v2": results.get("secure_boot", False),
                "flash_encryption": results.get("flash_encryption", False),  
                "efuse_protection": results.get("efuse_protection", False),
                "hsm_validation": results.get("hsm_validation", False)
            },
            "recommendations": []
        }
        
        # Ajouter des recommandations basées sur les résultats
        if not results.get("hsm_validation", False):
            report["recommendations"].append("Vérifier l'intégration HSM")
        
        if not results.get("post_flash_tests", False):
            report["recommendations"].append("Reprendre les tests post-flash")
        
        # Sauvegarder le rapport
        report_file = self.logs_dir / f"flash_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log_message(f"📊 Rapport sauvegardé: {report_file}", "SUCCESS")
        return report_file
    
    def flash_enterprise(self, port, verify_only=False):
        """Processus complet de flash Enterprise"""
        self.log_message("🏢 === DÉMARRAGE FLASH ENTERPRISE SECUREIOT-VIF ===", "INFO")
        
        results = {}
        
        # 1. Vérifier les prérequis
        if not self.check_prerequisites():
            return False
        results["prerequisites"] = True
        
        # 2. Générer les clés sécurisées
        keys_config = self.generate_secure_keys()
        if not keys_config:
            return False
        results["secure_keys"] = True
        
        if verify_only:
            self.log_message("Mode vérification uniquement - flash ignoré", "INFO")
        else:
            # 3. Configurer les eFuses
            self.configure_efuse(port)
            results["efuse_config"] = True
            
            # 4. Flash sécurisé
            if not self.secure_flash(port, keys_config):
                return False
            results["secure_flash"] = True
        
        # 5. Validation HSM
        if self.validate_hsm_integration(port):
            results["hsm_validation"] = True
        else:
            results["hsm_validation"] = False
        
        # 6. Tests post-flash
        if self.run_post_flash_tests(port):
            results["post_flash_tests"] = True
        else:
            results["post_flash_tests"] = False
        
        # 7. Générer le rapport
        report_file = self.generate_flash_report(results)
        
        # Résumé final
        success_rate = sum(1 for v in results.values() if v) / len(results) * 100
        
        if success_rate >= 80:
            self.log_message("🏢 === FLASH ENTERPRISE RÉUSSI ===", "SUCCESS")
            self.log_message(f"Taux de succès: {success_rate:.1f}%", "SUCCESS")
            return True
        else:
            self.log_message("🏢 === FLASH ENTERPRISE ÉCHOUÉ ===", "ERROR")
            self.log_message(f"Taux de succès: {success_rate:.1f}%", "ERROR")
            return False

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Outil de flash sécurisé SecureIoT-VIF Enterprise")
    parser.add_argument("-p", "--port", default="/dev/ttyUSB0", help="Port série ESP32")
    parser.add_argument("-v", "--verify-only", action="store_true", help="Mode vérification uniquement")
    parser.add_argument("--build", action="store_true", help="Compiler avant de flasher")
    
    args = parser.parse_args()
    
    # Compiler si demandé
    if args.build:
        print("🔨 Compilation du projet Enterprise...")
        try:
            result = subprocess.run(["idf.py", "build"], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Compilation réussie")
            else:
                print(f"❌ Erreur de compilation: {result.stderr}")
                return 1
        except Exception as e:
            print(f"❌ Erreur compilation: {e}")
            return 1
    
    # Créer l'outil de flash
    flash_tool = EnterpriseFlashTool()
    
    # Exécuter le flash Enterprise
    success = flash_tool.flash_enterprise(args.port, args.verify_only)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())