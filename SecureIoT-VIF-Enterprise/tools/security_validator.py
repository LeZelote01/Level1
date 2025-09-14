#!/usr/bin/env python3
"""
Validateur de sécurité pour SecureIoT-VIF Enterprise Edition

Fonctionnalités Enterprise :
- Validation de conformité sécurité
- Tests de pénétration automatisés
- Audit de configuration sécurité
- Vérification des standards industriels
- Validation des politiques de sécurité
- Génération de rapports de conformité
"""

import os
import sys
import json
import time
import serial
import hashlib
import re
import sqlite3
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class EnterpriseSecurityValidator:
    def __init__(self, serial_port="/dev/ttyUSB0", baudrate=115200):
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.validation_active = False
        self.security_tests = {}
        self.compliance_results = {}
        self.vulnerabilities = []
        self.security_score = 0
        
        # Standards de sécurité Enterprise
        self.security_standards = {
            'IEC_62443': {
                'name': 'IEC 62443 - Industrial Communication Networks Security',
                'requirements': [
                    'secure_communication',
                    'access_control',
                    'system_integrity',
                    'data_confidentiality',
                    'restricted_data_flow',
                    'timely_response',
                    'resource_availability'
                ]
            },
            'ISO_27001': {
                'name': 'ISO 27001 - Information Security Management',
                'requirements': [
                    'information_security_policy',
                    'risk_management',
                    'asset_management',
                    'access_control',
                    'cryptography',
                    'physical_security',
                    'incident_management'
                ]
            },
            'NIST_CSF': {
                'name': 'NIST Cybersecurity Framework',
                'requirements': [
                    'identify_assets',
                    'protect_systems',
                    'detect_events', 
                    'respond_incidents',
                    'recover_operations'
                ]
            },
            'FIPS_140_2': {
                'name': 'FIPS 140-2 - Cryptographic Module Validation',
                'requirements': [
                    'cryptographic_algorithms',
                    'key_management',
                    'authentication',
                    'finite_state_model',
                    'physical_security',
                    'operational_environment'
                ]
            }
        }
        
        # Tests de sécurité automatisés
        self.security_test_suite = {
            'crypto_validation': {
                'name': 'Validation Cryptographique',
                'tests': [
                    'test_aes_implementation',
                    'test_sha_implementation', 
                    'test_ecdsa_implementation',
                    'test_rng_quality',
                    'test_key_derivation',
                    'test_secure_storage'
                ]
            },
            'integrity_validation': {
                'name': 'Validation Intégrité',
                'tests': [
                    'test_firmware_integrity',
                    'test_realtime_verification',
                    'test_tampering_detection',
                    'test_recovery_mechanisms'
                ]
            },
            'attestation_validation': {
                'name': 'Validation Attestation',
                'tests': [
                    'test_attestation_generation',
                    'test_attestation_verification',
                    'test_continuous_attestation',
                    'test_attestation_freshness'
                ]
            },
            'access_control': {
                'name': 'Contrôle d\'Accès',
                'tests': [
                    'test_authentication',
                    'test_authorization',
                    'test_privilege_escalation',
                    'test_session_management'
                ]
            },
            'communication_security': {
                'name': 'Sécurité Communication',
                'tests': [
                    'test_tls_implementation',
                    'test_certificate_validation',
                    'test_secure_protocols',
                    'test_encryption_strength'
                ]
            },
            'physical_security': {
                'name': 'Sécurité Physique',
                'tests': [
                    'test_tamper_detection',
                    'test_debug_protection',
                    'test_side_channel_resistance',
                    'test_fault_injection_resistance'
                ]
            }
        }
        
        # Base de données pour les résultats de validation
        self.db_path = Path("security_validation.db")
        self.setup_database()
    
    def setup_database(self):
        """Configurer la base de données de validation sécurité"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des tests de sécurité
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_category TEXT NOT NULL,
                    test_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    score INTEGER,
                    details TEXT,
                    recommendations TEXT
                )
            ''')
            
            # Table de conformité
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    standard_name TEXT NOT NULL,
                    requirement TEXT NOT NULL,
                    compliance_status TEXT NOT NULL,
                    compliance_score INTEGER,
                    evidence TEXT,
                    gaps TEXT
                )
            ''')
            
            # Table des vulnérabilités
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    impact TEXT,
                    mitigation TEXT,
                    status TEXT DEFAULT 'OPEN',
                    cvss_score REAL
                )
            ''')
            
            conn.commit()
    
    def log_message(self, message, level="INFO"):
        """Log un message avec timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def test_aes_implementation(self):
        """Test de l'implémentation AES"""
        self.log_message("🔐 Test implémentation AES...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=30) as ser:
                # Test AES-256
                ser.write(b"security_test_aes\
")
                response = self.read_response(ser, "AES test complete", 30)
                
                # Analyser la réponse
                if "AES-256 hardware: OK" in response:
                    if "Test vectors: PASS" in response and "Performance: OK" in response:
                        return {'status': 'PASS', 'score': 100, 'details': 'AES-256 hardware conforme'}
                    else:
                        return {'status': 'PARTIAL', 'score': 70, 'details': 'AES hardware OK mais tests partiels'}
                else:
                    return {'status': 'FAIL', 'score': 0, 'details': 'AES hardware non fonctionnel'}
                    
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test AES: {e}'}
    
    def test_sha_implementation(self):
        """Test de l'implémentation SHA"""
        self.log_message("🔐 Test implémentation SHA...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=30) as ser:
                ser.write(b"security_test_sha\
")
                response = self.read_response(ser, "SHA test complete", 30)
                
                if "SHA-256 hardware: OK" in response and "Test vectors: PASS" in response:
                    return {'status': 'PASS', 'score': 100, 'details': 'SHA-256 hardware conforme'}
                else:
                    return {'status': 'FAIL', 'score': 0, 'details': 'SHA hardware non conforme'}
                    
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test SHA: {e}'}
    
    def test_ecdsa_implementation(self):
        """Test de l'implémentation ECDSA"""
        self.log_message("🔐 Test implémentation ECDSA...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=60) as ser:
                ser.write(b"security_test_ecdsa\
")
                response = self.read_response(ser, "ECDSA test complete", 60)
                
                if "ECDSA P-256: OK" in response and "Signature verification: PASS" in response:
                    return {'status': 'PASS', 'score': 100, 'details': 'ECDSA P-256 conforme'}
                else:
                    return {'status': 'FAIL', 'score': 0, 'details': 'ECDSA non conforme'}
                    
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test ECDSA: {e}'}
    
    def test_rng_quality(self):
        """Test de la qualité du générateur aléatoire"""
        self.log_message("🎲 Test qualité RNG...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=45) as ser:
                ser.write(b"security_test_rng_quality\
")
                response = self.read_response(ser, "RNG quality test complete", 45)
                
                # Analyser les tests statistiques
                if "NIST randomness tests: PASS" in response:
                    entropy_match = re.search(r"Entropy: ([\d.]+) bits/byte", response)
                    if entropy_match:
                        entropy = float(entropy_match.group(1))
                        if entropy >= 7.9:  # Très bon
                            return {'status': 'PASS', 'score': 100, 'details': f'RNG de qualité excellente (entropie: {entropy})'}
                        elif entropy >= 7.5:  # Acceptable
                            return {'status': 'PASS', 'score': 85, 'details': f'RNG de qualité acceptable (entropie: {entropy})'}
                        else:
                            return {'status': 'PARTIAL', 'score': 60, 'details': f'RNG qualité faible (entropie: {entropy})'}
                    else:
                        return {'status': 'PARTIAL', 'score': 70, 'details': 'Tests NIST OK mais entropie non mesurée'}
                else:
                    return {'status': 'FAIL', 'score': 0, 'details': 'RNG échoue aux tests NIST'}
                    
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test RNG: {e}'}
    
    def test_firmware_integrity(self):
        """Test de l'intégrité du firmware"""
        self.log_message("🛡️ Test intégrité firmware...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=90) as ser:
                ser.write(b"security_test_firmware_integrity\
")
                response = self.read_response(ser, "Firmware integrity test complete", 90)
                
                checks = [
                    ("Secure Boot signature: VALID", 25),
                    ("Flash encryption: ACTIVE", 25),
                    ("Firmware hash: VALID", 25),
                    ("Anti-rollback: ENABLED", 25)
                ]
                
                score = 0
                details = []
                
                for check, points in checks:
                    if check in response:
                        score += points
                        details.append(f"✓ {check}")
                    else:
                        details.append(f"✗ {check}")
                
                status = 'PASS' if score >= 75 else 'PARTIAL' if score >= 50 else 'FAIL'
                return {'status': status, 'score': score, 'details': '; '.join(details)}
                
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test intégrité: {e}'}
    
    def test_tampering_detection(self):
        """Test de détection de sabotage"""
        self.log_message("🚨 Test détection sabotage...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=60) as ser:
                ser.write(b"security_test_tampering\
")
                response = self.read_response(ser, "Tampering test complete", 60)
                
                if "Tamper detection: ACTIVE" in response:
                    if "Physical tamper: DETECTED" in response:
                        return {'status': 'PASS', 'score': 100, 'details': 'Détection sabotage fonctionnelle'}
                    else:
                        return {'status': 'PARTIAL', 'score': 70, 'details': 'Détection sabotage active mais non testée'}
                else:
                    return {'status': 'FAIL', 'score': 0, 'details': 'Détection sabotage non active'}
                    
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test sabotage: {e}'}
    
    def test_attestation_generation(self):
        """Test de génération d'attestation"""
        self.log_message("📋 Test génération attestation...", "INFO")
        
        try:
            with serial.Serial(self.serial_port, self.baudrate, timeout=60) as ser:
                ser.write(b"security_test_attestation_gen\
")
                response = self.read_response(ser, "Attestation generation test complete", 60)
                
                if "Attestation generated: OK" in response and "Signature valid: OK" in response:
                    return {'status': 'PASS', 'score': 100, 'details': 'Génération attestation conforme'}
                else:
                    return {'status': 'FAIL', 'score': 0, 'details': 'Génération attestation défaillante'}
                    
        except Exception as e:
            return {'status': 'ERROR', 'score': 0, 'details': f'Erreur test attestation: {e}'}
    
    def read_response(self, ser, end_pattern, timeout):
        """Lire la réponse série jusqu'au pattern de fin"""
        start_time = time.time()
        response = ""
        
        while time.time() - start_time < timeout:
            if ser.in_waiting:
                data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                response += data
                
                if end_pattern in response:
                    break
        
        return response
    
    def run_security_test_suite(self):
        """Exécuter la suite complète de tests de sécurité"""
        self.log_message("🔒 Démarrage de la suite de tests de sécurité Enterprise", "INFO")
        
        test_results = {}
        
        # Tests cryptographiques
        crypto_tests = [
            ('aes', self.test_aes_implementation),
            ('sha', self.test_sha_implementation),
            ('ecdsa', self.test_ecdsa_implementation),
            ('rng', self.test_rng_quality)
        ]
        
        for test_name, test_func in crypto_tests:
            self.log_message(f"Exécution test: {test_name}", "INFO")
            result = test_func()
            test_results[f"crypto_{test_name}"] = result
            self.store_test_result("crypto_validation", test_name, result)
        
        # Tests d'intégrité
        integrity_tests = [
            ('firmware_integrity', self.test_firmware_integrity),
            ('tampering_detection', self.test_tampering_detection)
        ]
        
        for test_name, test_func in integrity_tests:
            self.log_message(f"Exécution test: {test_name}", "INFO")
            result = test_func()
            test_results[f"integrity_{test_name}"] = result
            self.store_test_result("integrity_validation", test_name, result)
        
        # Tests d'attestation
        attestation_tests = [
            ('attestation_generation', self.test_attestation_generation)
        ]
        
        for test_name, test_func in attestation_tests:
            self.log_message(f"Exécution test: {test_name}", "INFO")
            result = test_func()
            test_results[f"attestation_{test_name}"] = result
            self.store_test_result("attestation_validation", test_name, result)
        
        return test_results
    
    def store_test_result(self, category, test_name, result):
        """Stocker un résultat de test dans la base"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_tests (test_category, test_name, status, score, details, recommendations)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                category,
                test_name,
                result['status'],
                result['score'],
                result['details'],
                result.get('recommendations', '')
            ))
            conn.commit()
    
    def validate_compliance(self, standard_name):
        """Valider la conformité à un standard de sécurité"""
        self.log_message(f"📋 Validation conformité {standard_name}...", "INFO")
        
        if standard_name not in self.security_standards:
            return {'error': f'Standard {standard_name} non supporté'}
        
        standard = self.security_standards[standard_name]
        compliance_results = {}
        
        # Évaluer chaque exigence du standard
        for requirement in standard['requirements']:
            compliance_result = self.evaluate_requirement(standard_name, requirement)
            compliance_results[requirement] = compliance_result
            
            # Stocker le résultat
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO compliance_results (standard_name, requirement, compliance_status, compliance_score, evidence, gaps)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    standard_name,
                    requirement,
                    compliance_result['status'],
                    compliance_result['score'],
                    compliance_result.get('evidence', ''),
                    compliance_result.get('gaps', '')
                ))
                conn.commit()
        
        # Calculer le score global de conformité
        total_score = sum(result['score'] for result in compliance_results.values())
        avg_score = total_score / len(compliance_results) if compliance_results else 0
        
        return {
            'standard': standard_name,
            'global_score': round(avg_score, 1),
            'requirements': compliance_results,
            'status': 'COMPLIANT' if avg_score >= 80 else 'PARTIAL' if avg_score >= 60 else 'NON_COMPLIANT'
        }
    
    def evaluate_requirement(self, standard_name, requirement):
        """Évaluer une exigence spécifique d'un standard"""
        # Cette fonction devrait contenir la logique spécifique pour chaque exigence
        # Pour la démo, on utilise une logique simplifiée basée sur les tests existants
        
        if requirement in ['secure_communication', 'cryptography', 'cryptographic_algorithms']:
            # Basé sur les tests crypto
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT AVG(score) FROM security_tests 
                    WHERE test_category = 'crypto_validation' AND timestamp > datetime('now', '-1 hour')
                ''')
                result = cursor.fetchone()
                score = result[0] if result[0] else 0
                
                return {
                    'status': 'COMPLIANT' if score >= 80 else 'PARTIAL' if score >= 60 else 'NON_COMPLIANT',
                    'score': score,
                    'evidence': 'Tests cryptographiques automatisés',
                    'gaps': 'Aucun' if score >= 80 else 'Améliorations crypto nécessaires'
                }
        
        elif requirement in ['system_integrity', 'protect_systems']:
            # Basé sur les tests d'intégrité
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT AVG(score) FROM security_tests 
                    WHERE test_category = 'integrity_validation' AND timestamp > datetime('now', '-1 hour')
                ''')
                result = cursor.fetchone()
                score = result[0] if result[0] else 0
                
                return {
                    'status': 'COMPLIANT' if score >= 80 else 'PARTIAL' if score >= 60 else 'NON_COMPLIANT',
                    'score': score,
                    'evidence': 'Tests intégrité automatisés',
                    'gaps': 'Aucun' if score >= 80 else 'Renforcement intégrité nécessaire'
                }
        
        else:
            # Évaluation générique pour les autres exigences
            return {
                'status': 'PARTIAL',
                'score': 70,
                'evidence': 'Évaluation manuelle requise',
                'gaps': 'Validation détaillée nécessaire'
            }
    
    def generate_security_report(self):
        """Générer un rapport de sécurité complet"""
        self.log_message("📊 Génération du rapport de sécurité...", "INFO")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'ENTERPRISE_SECURITY_VALIDATION',
            'global_security_score': 0,
            'test_results': {},
            'compliance_results': {},
            'vulnerabilities': [],
            'recommendations': [],
            'certificate_readiness': {}
        }
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Résultats des tests par catégorie
            cursor.execute('''
                SELECT test_category, AVG(score) as avg_score, COUNT(*) as test_count
                FROM security_tests 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY test_category
            ''')
            
            category_scores = []
            for row in cursor.fetchall():
                category, avg_score, count = row
                report['test_results'][category] = {
                    'avg_score': round(avg_score, 1),
                    'test_count': count,
                    'status': 'PASS' if avg_score >= 80 else 'PARTIAL' if avg_score >= 60 else 'FAIL'
                }
                category_scores.append(avg_score)
            
            # Score global de sécurité
            if category_scores:
                report['global_security_score'] = round(sum(category_scores) / len(category_scores), 1)
            
            # Résultats de conformité
            cursor.execute('''
                SELECT standard_name, AVG(compliance_score) as avg_score
                FROM compliance_results 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY standard_name
            ''')
            
            for row in cursor.fetchall():
                standard, score = row
                report['compliance_results'][standard] = {
                    'score': round(score, 1),
                    'status': 'COMPLIANT' if score >= 80 else 'PARTIAL' if score >= 60 else 'NON_COMPLIANT'
                }
            
            # Vulnérabilités
            cursor.execute('''
                SELECT vulnerability_type, severity, description, cvss_score
                FROM vulnerabilities 
                WHERE status = 'OPEN' AND timestamp > datetime('now', '-24 hours')
                ORDER BY cvss_score DESC
            ''')
            
            for row in cursor.fetchall():
                vuln_type, severity, description, cvss = row
                report['vulnerabilities'].append({
                    'type': vuln_type,
                    'severity': severity,
                    'description': description,
                    'cvss_score': cvss
                })
        
        # Recommandations basées sur les résultats
        if report['global_security_score'] < 80:
            report['recommendations'].append("Améliorer les mesures de sécurité globales")
        
        if 'crypto_validation' in report['test_results'] and report['test_results']['crypto_validation']['avg_score'] < 90:
            report['recommendations'].append("Renforcer l'implémentation cryptographique")
        
        # Préparation à la certification
        for standard, result in report['compliance_results'].items():
            report['certificate_readiness'][standard] = {
                'ready': result['status'] == 'COMPLIANT',
                'score': result['score'],
                'gaps': 'Aucun' if result['status'] == 'COMPLIANT' else 'Amélioration nécessaire'
            }
        
        # Sauvegarder le rapport
        reports_dir = Path("security_reports")
        reports_dir.mkdir(exist_ok=True)
        
        report_file = reports_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log_message(f"📊 Rapport sauvegardé: {report_file}", "SUCCESS")
        
        # Afficher le résumé
        self.log_message("📊 RÉSUMÉ DU RAPPORT DE SÉCURITÉ", "INFO")
        self.log_message(f"Score global de sécurité: {report['global_security_score']}%", "INFO")
        
        for category, result in report['test_results'].items():
            self.log_message(f"  {category}: {result['avg_score']}% ({result['status']})", "INFO")
        
        if report['vulnerabilities']:
            self.log_message(f"Vulnérabilités ouvertes: {len(report['vulnerabilities'])}", "WARNING")
        
        return report_file
    
    def run_full_validation(self):
        """Exécuter une validation complète de sécurité"""
        self.log_message("🔒 === VALIDATION SÉCURITÉ ENTERPRISE SECUREIOT-VIF ===", "INFO")
        
        self.validation_active = True
        
        try:
            # 1. Suite de tests de sécurité
            test_results = self.run_security_test_suite()
            
            # 2. Validation de conformité pour chaque standard
            for standard_name in self.security_standards.keys():
                compliance_result = self.validate_compliance(standard_name)
                self.log_message(f"Conformité {standard_name}: {compliance_result['status']} ({compliance_result['global_score']}%)", "INFO")
            
            # 3. Rapport de sécurité final
            report_file = self.generate_security_report()
            
            self.log_message("🔒 === VALIDATION SÉCURITÉ TERMINÉE ===", "SUCCESS")
            self.log_message(f"Rapport disponible: {report_file}", "SUCCESS")
            
            return True
            
        except Exception as e:
            self.log_message(f"Erreur validation: {e}", "ERROR")
            return False
        
        finally:
            self.validation_active = False

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Validateur de sécurité SecureIoT-VIF Enterprise")
    parser.add_argument("-p", "--port", default="/dev/ttyUSB0", help="Port série ESP32")
    parser.add_argument("--test-only", action="store_true", help="Tests seulement")
    parser.add_argument("--compliance-only", action="store_true", help="Validation conformité seulement")
    parser.add_argument("--standard", help="Standard spécifique à valider")
    
    args = parser.parse_args()
    
    # Créer le validateur
    validator = EnterpriseSecurityValidator(args.port)
    
    try:
        if args.test_only:
            validator.run_security_test_suite()
        elif args.compliance_only:
            if args.standard:
                result = validator.validate_compliance(args.standard)
                print(json.dumps(result, indent=2))
            else:
                for standard in validator.security_standards.keys():
                    validator.validate_compliance(standard)
        else:
            # Validation complète
            validator.run_full_validation()
        
        return 0
        
    except KeyboardInterrupt:
        print("\
🛑 Validation interrompue par l'utilisateur")
        validator.validation_active = False
        return 1
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())