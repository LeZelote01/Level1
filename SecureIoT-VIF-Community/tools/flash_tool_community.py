#!/usr/bin/env python3
"""
Outil de flash et configuration pour SecureIoT-VIF Community Edition
Version simplifiée pour l'apprentissage et l'éducation
"""

import os
import sys
import subprocess
import argparse
import json
from pathlib import Path
import time

def run_command(cmd, check=True):
    """Exécute une commande et affiche le résultat"""
    print(f"🔧 Exécution: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr and result.returncode != 0:
        print(f"❌ Erreur: {result.stderr}")
    
    if check and result.returncode != 0:
        sys.exit(1)
    
    return result

def check_environment():
    """Vérifie l'environnement ESP-IDF et version Community"""
    print("🔍 Vérification environnement ESP-IDF Community...")
    
    # Vérifier ESP-IDF
    result = run_command("idf.py --version", check=False)
    if result.returncode != 0:
        print("❌ ESP-IDF non trouvé. Veuillez configurer votre environnement.")
        print("💡 Exécutez: source $HOME/esp/esp-idf/export.sh")
        sys.exit(1)
    
    print("✅ ESP-IDF configuré correctement")
    
    # Vérifier version SecureIoT-VIF Community
    if os.path.exists("main/app_config.h"):
        with open("main/app_config.h", "r") as f:
            content = f.read()
            if "1.0.0-COMMUNITY" in content:
                print("✅ SecureIoT-VIF Community Edition détectée")
            elif "2.0.0-ESP32-CRYPTO" in content:
                print("⚠️ SecureIoT-VIF Enterprise détectée - Utilisez l'outil Enterprise")
                print("💡 Vous êtes dans le mauvais répertoire pour Community")
            else:
                print("❓ Version SecureIoT-VIF non identifiée")

def configure_project(args):
    """Configure le projet Community avec optimisations éducatives"""
    print("⚙️ Configuration SecureIoT-VIF Community Edition...")
    
    if args.auto_config:
        # Configuration automatique Community
        config = {
            # Configuration Community Edition (éducative)
            "CONFIG_SECURE_IOT_COMMUNITY_EDITION": "y",
            "CONFIG_SECURE_IOT_BASIC_CRYPTO_ONLY": "y",
            "CONFIG_SECURE_IOT_SECURITY_LEVEL": "2",
            
            # Configuration capteurs (DHT22 seulement)
            "CONFIG_SECURE_IOT_DHT22_GPIO": "4",
            "CONFIG_SECURE_IOT_DHT22_POWER_GPIO": "5",
            
            # Intervalles Community (moins fréquents)
            "CONFIG_SECURE_IOT_INTEGRITY_CHECK_INTERVAL": "300",
            "CONFIG_SECURE_IOT_SENSOR_READ_INTERVAL": "5",
            
            # Crypto Community (software seulement)
            "CONFIG_MBEDTLS_HARDWARE_AES": "n",
            "CONFIG_MBEDTLS_HARDWARE_SHA": "n", 
            "CONFIG_MBEDTLS_ECDSA_C": "y",
            "CONFIG_MBEDTLS_ECP_C": "y",
            
            # Configuration ESP32 Community (basique)
            "CONFIG_ESP32_DEFAULT_CPU_FREQ_160": "y",
            "CONFIG_ESP32_ENABLE_COREDUMP": "n",
            "CONFIG_ESP32_PANIC_HANDLER_REBOOT": "y",
            
            # Désactiver fonctionnalités Enterprise
            "CONFIG_SECURE_BOOT": "n",
            "CONFIG_SECURE_FLASH_ENC_ENABLED": "n"
        }
        
        # Écrire la configuration Community
        print("📝 Application configuration Community...")
        with open("sdkconfig", "w") as f:
            for key, value in config.items():
                f.write(f"{key}={value}\n")
        
        print("✅ Configuration Community appliquée")
        
        # Afficher les fonctionnalités Community
        print("🎓 Fonctionnalités Community activées:")
        print("  ✅ Crypto de base (software mbedTLS)")
        print("  ✅ Vérification intégrité au boot seulement")
        print("  ✅ Détection anomalies par seuils fixes")
        print("  ✅ Interface capteurs DHT22 complète")
        print("  ✅ Intervalles optimisés pour éducation")
        print("  🎓 Parfait pour apprendre la sécurité IoT !")
        
    else:
        # Configuration interactive
        print("🔧 Lancement configuration interactive...")
        run_command("idf.py menuconfig")

def build_project():
    """Compile le projet Community avec optimisations éducatives"""
    print("🔨 Compilation SecureIoT-VIF Community Edition...")
    
    start_time = time.time()
    run_command("idf.py build")
    build_time = time.time() - start_time
    
    print(f"✅ Compilation terminée en {build_time:.1f}s")
    
    # Afficher les informations de build Community
    if os.path.exists("build/bootloader/bootloader.bin"):
        print("📊 Taille des binaires Community:")
        
        # Taille bootloader
        bootloader_size = os.path.getsize("build/bootloader/bootloader.bin")
        print(f"  📦 Bootloader: {bootloader_size:,} bytes")
        
        # Taille application
        app_files = ["build/SecureIoT-VIF-Community.bin"]
        for app_file in app_files:
            if os.path.exists(app_file):
                app_size = os.path.getsize(app_file)
                print(f"  📦 Application: {app_size:,} bytes")
                
        print("💡 Optimisations Community:")
        print("  🎓 Taille réduite pour éducation")
        print("  📚 Fonctionnalités de base seulement")
        print("  ⚡ Compilation rapide pour itérations")

def flash_project(port):
    """Flash le firmware Community"""
    print(f"⚡ Flash SecureIoT-VIF Community sur {port}...")
    
    start_time = time.time()
    run_command(f"idf.py -p {port} flash")
    flash_time = time.time() - start_time
    
    print(f"✅ Flash terminé en {flash_time:.1f}s")
    print("🎉 SecureIoT-VIF Community Edition déployé !")
    
    # Instructions post-flash Community
    print("\n📋 Prochaines étapes:")
    print("  1️⃣ Lancer le monitoring: python tools/flash_tool_community.py monitor")
    print("  2️⃣ Vérifier les logs crypto de base")
    print("  3️⃣ Confirmer la lecture DHT22")
    print("  4️⃣ Tester la détection d'anomalies par seuils")
    print("\n🎓 Version éducative parfaite pour apprendre !")

def monitor_project(port):
    """Monitor les logs Community avec affichage éducatif"""
    print(f"📺 Monitoring SecureIoT-VIF Community sur {port}...")
    print("🔍 Recherchez ces logs de succès Community:")
    print("  ✅ 'Démarrage SecureIoT-VIF Community Edition'")
    print("  ✅ 'Crypto de base initialisé'") 
    print("  ✅ 'Version éducative - Crypto software seulement'")
    print("  ✅ 'Vérification intégrité initiale réussie'")
    print("  ✅ 'Community Edition Opérationnel'")
    print("\n💡 Appuyez sur Ctrl+] pour quitter")
    
    run_command(f"idf.py -p {port} monitor")

def detect_port():
    """Détecte automatiquement le port série ESP32"""
    try:
        import serial.tools.list_ports
        
        ports = list(serial.tools.list_ports.comports())
        
        # Rechercher spécifiquement ESP32
        esp32_ports = []
        for p in ports:
            desc_lower = p.description.lower()
            if any(keyword in desc_lower for keyword in ['cp210', 'ch340', 'ftdi', 'silicon labs', 'esp32']):
                esp32_ports.append(p.device)
        
        if esp32_ports:
            selected_port = esp32_ports[0]
            if len(esp32_ports) > 1:
                print(f"🔍 {len(esp32_ports)} ports ESP32 détectés:")
                for i, port in enumerate(esp32_ports):
                    print(f"  {i+1}. {port}")
                print(f"📌 Sélection automatique: {selected_port}")
            return selected_port
        elif ports:
            return ports[0].device
        else:
            return "/dev/ttyUSB0"  # Défaut Linux
            
    except ImportError:
        print("⚠️ pyserial non installé, utilisation port par défaut")
        return "/dev/ttyUSB0"

def run_tests():
    """Exécute les tests Community simplifiés"""
    print("🧪 Tests SecureIoT-VIF Community Edition...")
    
    # Tests de compilation Community
    print("📋 Test compilation Community...")
    start_time = time.time()
    run_command("idf.py build")
    build_time = time.time() - start_time
    print(f"✅ Compilation réussie en {build_time:.1f}s")
    
    # Tests de configuration Community
    print("📋 Test configuration Community...")
    if os.path.exists("sdkconfig"):
        with open("sdkconfig", "r") as f:
            config = f.read()
            
        # Vérifier les configurations Community clés
        community_configs = [
            "CONFIG_SECURE_IOT_COMMUNITY_EDITION=y",
            "CONFIG_SECURE_IOT_BASIC_CRYPTO_ONLY=y",
            "CONFIG_SECURE_BOOT=n",
            "CONFIG_SECURE_FLASH_ENC_ENABLED=n"
        ]
        
        missing_configs = []
        for config_item in community_configs:
            if config_item not in config:
                missing_configs.append(config_item)
        
        if missing_configs:
            print("⚠️ Configurations Community manquantes:")
            for config_item in missing_configs:
                print(f"  ❌ {config_item}")
        else:
            print("✅ Configuration Community complète")
    else:
        print("❌ Fichier sdkconfig manquant")
    
    # Test structure projet Community
    print("📋 Test structure projet Community...")
    community_files = [
        "components/secure_element/crypto_operations_basic.c",
        "components/secure_element/include/crypto_operations_basic.h", 
        "main/app_config.h"
    ]
    
    missing_files = []
    for file_path in community_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ Fichiers Community manquants:")
        for file_path in missing_files:
            print(f"  ❌ {file_path}")
    else:
        print("✅ Structure projet Community complète")
    
    print("🎉 Tests Community terminés")

def clean_project():
    """Nettoie le projet Community"""
    print("🧹 Nettoyage SecureIoT-VIF Community...")
    
    run_command("idf.py clean")
    
    # Supprimer les fichiers temporaires Community
    temp_files = ["sdkconfig", "sdkconfig.old", "dependencies.lock"]
    for f in temp_files:
        if os.path.exists(f):
            os.remove(f)
            print(f"🗑️ Supprimé: {f}")
    
    print("✅ Nettoyage Community terminé")

def show_version_info():
    """Affiche les informations de version Community"""
    print("📋 === Informations SecureIoT-VIF Community ===")
    
    # Détection version
    version = "Non détectée"
    if os.path.exists("main/app_config.h"):
        with open("main/app_config.h", "r") as f:
            content = f.read()
            if "1.0.0-COMMUNITY" in content:
                version = "v1.0.0 - Community Edition 🎓"
            elif "2.0.0-ESP32-CRYPTO" in content:
                version = "v2.0.0 - Enterprise Edition (Mauvais outil)"
    
    print(f"Version: {version}")
    
    # Afficher les fonctionnalités Community
    if "Community" in version:
        print("\n🎓 Fonctionnalités Community Edition:")
        print("  📚 Idéal pour apprentissage et éducation")
        print("  🔐 Crypto de base (software mbedTLS)")
        print("  ✅ Vérification intégrité au démarrage")
        print("  🎯 Détection anomalies par seuils fixes")
        print("  🌡️ Interface capteurs DHT22 complète")
        print("  📊 Statistiques et monitoring basiques")
        
        print("\n🎯 Usage Recommandé:")
        print("  🎓 Étudiants en cybersécurité")
        print("  👨‍🏫 Enseignants et formateurs")
        print("  🔬 Chercheurs académiques")
        print("  🛠️ Prototypage et expérimentation")
        
        print("\n🚫 Limitations Community:")
        print("  ❌ Pas de crypto hardware (HSM, TRNG)")
        print("  ❌ Pas de vérification temps réel")
        print("  ❌ Pas d'attestation continue")
        print("  ❌ Pas de ML adaptatif")
        print("  ❌ Usage commercial interdit")

def main():
    parser = argparse.ArgumentParser(description="Outil de développement SecureIoT-VIF Community Edition")
    parser.add_argument("action", 
                        choices=["build", "flash", "monitor", "all", "config", "test", "clean", "info"],
                        help="Action à exécuter")
    parser.add_argument("-p", "--port", help="Port série (auto-détection si non spécifié)")
    parser.add_argument("--auto-config", action="store_true", 
                        help="Configuration automatique Community (optimisée éducation)")
    parser.add_argument("--auto-port", action="store_true",
                        help="Détection automatique du port ESP32")
    
    args = parser.parse_args()
    
    # Banner Community
    print("🎓 ===============================================")
    print("📚 SecureIoT-VIF Community Edition")
    print("🎯 Version éducative pour apprentissage")
    print("💡 Parfait pour étudiants et chercheurs")
    print("🚀 Démarrage en 5 minutes")
    print("🎓 ===============================================\n")
    
    # Vérifier l'environnement
    check_environment()
    
    # Détecter le port si demandé ou non spécifié
    if args.auto_port or not args.port:
        args.port = detect_port()
        print(f"🔍 Port ESP32 détecté: {args.port}")
    
    # Exécuter l'action demandée
    try:
        if args.action == "info":
            show_version_info()
        elif args.action == "config":
            configure_project(args)
        elif args.action == "build":
            build_project()
        elif args.action == "flash":
            build_project()
            flash_project(args.port)
        elif args.action == "monitor":
            monitor_project(args.port)
        elif args.action == "all":
            configure_project(args)
            build_project()
            flash_project(args.port)
            print("\n⏳ Attente 3s avant monitoring...")
            time.sleep(3)
            monitor_project(args.port)
        elif args.action == "test":
            run_tests()
        elif args.action == "clean":
            clean_project()
        
    except KeyboardInterrupt:
        print("\n🛑 Opération interrompue par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()