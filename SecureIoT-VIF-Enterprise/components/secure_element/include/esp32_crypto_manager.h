/**
 * @file esp32_crypto_manager.h
 * @brief Gestionnaire cryptographique ESP32 Enterprise Edition
 * 
 * Version complète Enterprise avec toutes les fonctionnalités avancées :
 * - HSM ESP32 intégré complet avec 8 blocs eFuse
 * - TRNG optimisé haute performance
 * - Fonctionnalités temps réel avancées
 * - Monitoring et métriques Enterprise
 * - Support cryptographie post-quantique (préparation)
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef ESP32_CRYPTO_MANAGER_H
#define ESP32_CRYPTO_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_efuse.h"
#include "esp_random.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// ================================
// Constantes Enterprise
// ================================

#define ESP32_SERIAL_NUMBER_SIZE        (6)     // MAC Address comme ID unique
#define ESP32_PUBLIC_KEY_SIZE           (64)    // ECDSA P-256
#define ESP32_PRIVATE_KEY_SIZE          (32)    // ECDSA P-256
#define ESP32_SIGNATURE_SIZE            (64)    // ECDSA P-256
#define ESP32_CERTIFICATE_SIZE          (1024)  // Certificat Enterprise étendu
#define ESP32_RANDOM_BYTES_SIZE         (32)    // TRNG output
#define ESP32_AES_KEY_SIZE              (32)    // AES-256
#define ESP32_SHA256_SIZE               (32)    // SHA-256 digest
#define ESP32_SHA512_SIZE               (64)    // SHA-512 digest Enterprise

// eFuse blocks Enterprise (8 blocs au lieu de 4)
#define ESP32_EFUSE_DEVICE_KEY_BLOCK     (0)    // Clé privée principale
#define ESP32_EFUSE_ATTESTATION_BLOCK    (1)    // Clé d'attestation
#define ESP32_EFUSE_ENCRYPTION_BLOCK     (2)    // Clé de chiffrement
#define ESP32_EFUSE_HMAC_BLOCK           (3)    // Clé HMAC
#define ESP32_EFUSE_BACKUP_KEY_BLOCK     (4)    // Clé de sauvegarde Enterprise
#define ESP32_EFUSE_SESSION_KEY_BLOCK    (5)    // Clé de session Enterprise
#define ESP32_EFUSE_ML_MODEL_BLOCK       (6)    // Clé modèle ML Enterprise
#define ESP32_EFUSE_RESERVED_BLOCK       (7)    // Réservé futur

// États du gestionnaire crypto ESP32 Enterprise
typedef enum {
    ESP32_CRYPTO_STATE_UNINITIALIZED = 0,
    ESP32_CRYPTO_STATE_INITIALIZING,
    ESP32_CRYPTO_STATE_CONFIGURED,
    ESP32_CRYPTO_STATE_SECURE_BOOT_ENABLED,
    ESP32_CRYPTO_STATE_ERROR,
    ESP32_CRYPTO_STATE_FLASH_ENCRYPTED,
    ESP32_CRYPTO_STATE_ENTERPRISE_READY,        // Nouveau Enterprise
    ESP32_CRYPTO_STATE_TAMPER_DETECTED,         // Nouveau Enterprise
    ESP32_CRYPTO_STATE_EMERGENCY_MODE           // Nouveau Enterprise
} esp32_crypto_state_t;

// Types d'opérations cryptographiques ESP32 Enterprise
typedef enum {
    ESP32_CRYPTO_SIGN = 0,
    ESP32_CRYPTO_VERIFY,
    ESP32_CRYPTO_ENCRYPT_AES,
    ESP32_CRYPTO_DECRYPT_AES,
    ESP32_CRYPTO_ECDH,
    ESP32_CRYPTO_HMAC_SHA256,
    ESP32_CRYPTO_RANDOM_TRNG,
    ESP32_CRYPTO_HASH_SHA256,
    ESP32_CRYPTO_HASH_SHA512,                   // Nouveau Enterprise
    ESP32_CRYPTO_RSA_ENCRYPT,
    ESP32_CRYPTO_RSA_DECRYPT,
    ESP32_CRYPTO_ATTESTATION_CONTINUOUS,        // Nouveau Enterprise
    ESP32_CRYPTO_ML_SIGNATURE,                  // Nouveau Enterprise
    ESP32_CRYPTO_QUANTUM_RESISTANT              // Préparation futur
} esp32_crypto_operation_t;

// Résultat des opérations crypto ESP32 Enterprise
typedef enum {
    ESP32_CRYPTO_SUCCESS = 0,
    ESP32_CRYPTO_ERROR_INVALID_PARAM = -1,
    ESP32_CRYPTO_ERROR_NOT_INITIALIZED = -2,
    ESP32_CRYPTO_ERROR_MEMORY = -3,
    ESP32_CRYPTO_ERROR_EFUSE_PROGRAMMING = -4,
    ESP32_CRYPTO_ERROR_VERIFICATION_FAILED = -5,
    ESP32_CRYPTO_ERROR_EXECUTION_FAILED = -6,
    ESP32_CRYPTO_ERROR_ENTROPY_FAILED = -7,
    ESP32_CRYPTO_ERROR_KEY_GENERATION = -8,
    ESP32_CRYPTO_ERROR_FLASH_ENCRYPTION = -9,
    ESP32_CRYPTO_ERROR_SECURE_BOOT = -10,
    ESP32_CRYPTO_ERROR_TAMPER_DETECTED = -11,   // Nouveau Enterprise
    ESP32_CRYPTO_ERROR_PERFORMANCE_DEGRADED = -12, // Nouveau Enterprise
    ESP32_CRYPTO_ERROR_COMPLIANCE_VIOLATION = -13  // Nouveau Enterprise
} esp32_crypto_result_t;

// ================================
// Structures de données Enterprise
// ================================

/**
 * @brief Configuration du gestionnaire crypto ESP32 Enterprise
 */
typedef struct {
    bool enable_secure_boot;            // Activer Secure Boot v2
    bool enable_flash_encryption;       // Activer chiffrement flash
    bool enable_hardware_random;        // Utiliser TRNG matériel
    bool enable_efuse_protection;       // Protéger les eFuses
    uint8_t entropy_source;             // Source d'entropie
    uint32_t rsa_key_size;              // Taille clé RSA (1024, 2048, 4096)
    bool enable_debug_mode;             // Mode debug (toujours désactivé en Enterprise)
    uint8_t max_retries;                // Tentatives max pour opérations
    
    // Paramètres Enterprise avancés
    bool enable_tamper_detection;       // Détection de manipulation
    bool enable_performance_monitoring; // Monitoring performance
    bool enable_continuous_health_check; // Vérification santé continue
    uint32_t health_check_interval_ms;  // Intervalle vérification santé
    bool enable_quantum_resistance;     // Préparation crypto post-quantique
    uint8_t security_level;             // Niveau sécurité (1-5, 5=max)
} esp32_crypto_config_t;

/**
 * @brief Informations sur le crypto ESP32 Enterprise
 */
typedef struct {
    uint8_t device_id[ESP32_SERIAL_NUMBER_SIZE];  // ID unique (MAC)
    uint32_t chip_revision;                        // Révision du chip
    bool secure_boot_enabled;                      // État Secure Boot
    bool flash_encryption_enabled;                 // État chiffrement flash
    bool efuse_keys_programmed;                    // Clés eFuse programmées
    esp32_crypto_state_t state;                    // État actuel
    uint32_t error_count;                          // Compteur d'erreurs
    uint32_t operation_count;                      // Compteur d'opérations
    uint64_t last_operation_time;                  // Dernière opération
    uint32_t available_entropy;                    // Entropie disponible
    
    // Informations Enterprise spécifiques
    uint32_t hardware_version;                     // Version matérielle
    uint32_t firmware_version;                     // Version firmware
    uint8_t security_level;                        // Niveau sécurité actuel
    float performance_score;                       // Score performance (0.0-1.0)
    bool tamper_detected;                          // Détection manipulation
    uint32_t total_uptime_seconds;                 // Temps fonctionnement total
} esp32_crypto_info_t;

/**
 * @brief Structure pour les clés ESP32 Enterprise (8 slots)
 */
typedef struct {
    uint8_t key_id;                                // ID de la clé (0-7)
    uint8_t key_type;                              // Type (ECDSA, AES, RSA, HMAC)
    size_t key_size;                               // Taille de la clé
    uint8_t key_data[ESP32_PUBLIC_KEY_SIZE];       // Données de clé (publique)
    bool is_in_efuse;                              // Stockée dans eFuse
    bool is_protected;                             // Protection activée
    uint32_t usage_count;                          // Compteur d'utilisation
    uint8_t efuse_block;                           // Block eFuse utilisé (0-7)
    
    // Métadonnées Enterprise
    uint32_t creation_time;                        // Timestamp création
    uint32_t last_used_time;                       // Dernière utilisation
    uint8_t security_level;                        // Niveau sécurité clé
    bool is_quantum_resistant;                     // Résistance quantique
} esp32_key_info_t;

/**
 * @brief Structure pour les signatures ESP32 Enterprise
 */
typedef struct {
    uint8_t signature[ESP32_SIGNATURE_SIZE];       // Signature ECDSA
    size_t signature_size;                         // Taille de la signature
    uint8_t message_hash[ESP32_SHA256_SIZE];       // Hash SHA-256 du message
    bool is_valid;                                 // État de validation
    uint32_t timestamp;                            // Timestamp de création
    
    // Métadonnées Enterprise
    uint8_t key_id;                                // ID clé utilisée
    uint8_t security_level;                        // Niveau sécurité
    float confidence_score;                        // Score confiance
    uint32_t verification_time_us;                 // Temps vérification
} esp32_signature_t;

/**
 * @brief Structure pour l'attestation ESP32 Enterprise
 */
typedef struct {
    uint8_t challenge[32];                         // Challenge reçu
    uint8_t response[ESP32_SIGNATURE_SIZE];        // Réponse signée
    uint8_t device_cert[ESP32_CERTIFICATE_SIZE];   // Certificat Enterprise
    uint32_t timestamp;                            // Timestamp attestation
    uint8_t device_id[ESP32_SERIAL_NUMBER_SIZE];   // ID unique ESP32
    bool is_valid;                                 // État de validation
    uint32_t boot_count;                           // Compteur de démarrages
    
    // Métadonnées Enterprise étendues
    uint8_t security_level;                        // Niveau sécurité
    uint32_t firmware_version;                     // Version firmware
    uint32_t hardware_version;                     // Version matérielle
    float performance_score;                       // Score performance
    bool tamper_detected;                          // Détection manipulation
    uint32_t total_operations;                     // Opérations totales
} esp32_attestation_t;

/**
 * @brief Métriques de performance Enterprise
 */
typedef struct {
    uint64_t init_time;                            // Temps initialisation
    uint64_t total_uptime;                         // Temps fonctionnement
    
    // Métriques opérations
    uint32_t total_random_generations;             // Générations aléatoires
    uint64_t total_random_bytes;                   // Bytes aléatoires générés
    uint64_t avg_random_generation_time_us;        // Temps moyen génération
    
    uint32_t total_hash_operations;                // Opérations hash
    uint64_t total_hash_bytes;                     // Bytes hashés
    uint64_t avg_hash_time_us;                     // Temps moyen hash
    
    uint32_t total_signatures;                     // Signatures générées
    uint64_t avg_signature_time_us;                // Temps moyen signature
    
    uint32_t total_verifications;                  // Vérifications
    uint64_t avg_verification_time_us;             // Temps moyen vérification
    
    uint32_t total_key_generations;                // Générations de clés
    uint64_t avg_key_generation_time_us;           // Temps moyen génération clé
    
    uint32_t total_attestations;                   // Attestations
    uint64_t avg_attestation_time_us;              // Temps moyen attestation
    uint64_t last_attestation_time;                // Dernière attestation
    
    // Métriques Enterprise spécifiques
    uint32_t total_health_checks;                  // Vérifications santé
    uint32_t health_check_failures;                // Échecs vérification
    uint64_t avg_health_check_time_us;             // Temps moyen vérification
    uint64_t last_health_check;                    // Dernière vérification
    
    uint32_t total_self_tests;                     // Auto-tests
    uint64_t avg_self_test_time_us;                // Temps moyen auto-test
    uint64_t last_self_test_time;                  // Dernier auto-test
    
    uint32_t entropy_failures;                     // Échecs entropie
    uint32_t tamper_detections;                    // Détections manipulation
    uint32_t performance_degradations;             // Dégradations performance
} esp32_crypto_metrics_t;

// ================================
// Fonctions principales Enterprise
// ================================

/**
 * @brief Initialise le gestionnaire crypto ESP32 Enterprise
 * 
 * @param config Configuration crypto Enterprise (NULL pour défaut)
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t esp32_crypto_manager_init_enterprise(const esp32_crypto_config_t* config);

/**
 * @brief Dé-initialise le gestionnaire crypto ESP32 Enterprise
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t esp32_crypto_manager_deinit_enterprise(void);

/**
 * @brief Vérifie l'état de santé du crypto ESP32 Enterprise
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si tout est OK
 */
esp32_crypto_result_t esp32_crypto_health_check_enterprise(void);

// ================================
// Gestion des clés Enterprise
// ================================

/**
 * @brief Génère une paire de clés ECDSA Enterprise dans eFuse
 * 
 * @param key_id ID de la clé (0-7) Enterprise
 * @param public_key Buffer pour la clé publique (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_generate_ecdsa_keypair_enterprise(uint8_t key_id, uint8_t* public_key);

// ================================
// Opérations cryptographiques Enterprise
// ================================

/**
 * @brief Génère des bytes aléatoires sécurisés avec TRNG Enterprise
 * 
 * @param random_bytes Buffer pour les bytes aléatoires
 * @param length Nombre de bytes à générer
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_generate_random_enterprise(uint8_t* random_bytes, size_t length);

/**
 * @brief Calcule un hash SHA-256 matériel Enterprise
 * 
 * @param data Données à hasher
 * @param data_length Longueur des données
 * @param hash Buffer pour le hash (32 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_sha256_enterprise(const uint8_t* data, size_t data_length, uint8_t* hash);

/**
 * @brief Calcule un hash SHA-512 matériel Enterprise
 * 
 * @param data Données à hasher
 * @param data_length Longueur des données
 * @param hash Buffer pour le hash (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_sha512_enterprise(const uint8_t* data, size_t data_length, uint8_t* hash);

/**
 * @brief Signe un message avec ECDSA Enterprise
 * 
 * @param key_id ID de la clé privée dans eFuse (0-7)
 * @param message_hash Hash SHA-256 du message (32 bytes)
 * @param signature Buffer pour la signature (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_ecdsa_sign_enterprise(uint8_t key_id, const uint8_t* message_hash, uint8_t* signature);

/**
 * @brief Vérifie une signature ECDSA Enterprise
 * 
 * @param public_key Clé publique ECDSA (64 bytes)
 * @param message_hash Hash SHA-256 du message (32 bytes)
 * @param signature Signature à vérifier (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si valide
 */
esp32_crypto_result_t esp32_crypto_ecdsa_verify_enterprise(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature);

/**
 * @brief Effectue une attestation Enterprise de l'appareil ESP32
 * 
 * @param challenge Challenge reçu du vérifieur
 * @param challenge_size Taille du challenge
 * @param attestation Structure d'attestation Enterprise à remplir
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_perform_attestation_enterprise(const uint8_t* challenge, size_t challenge_size, 
                                                                  esp32_attestation_t* attestation);

/**
 * @brief Auto-test complet crypto ESP32 Enterprise
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si tous les tests passent
 */
esp32_crypto_result_t esp32_crypto_self_test_enterprise(void);

// ================================
// Gestion d'état et monitoring Enterprise
// ================================

/**
 * @brief Met à jour le heartbeat Enterprise dans les eFuses
 * 
 * @param counter Compteur de heartbeat
 * @param security_score Score de sécurité (0-100)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_update_heartbeat_enterprise(uint32_t counter, uint32_t security_score);

/**
 * @brief Stocke l'état d'urgence Enterprise dans la NVS
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_store_emergency_state_enterprise(void);

/**
 * @brief Obtient les métriques de performance Enterprise
 * 
 * @param metrics Buffer pour les métriques
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_get_metrics_enterprise(esp32_crypto_metrics_t* metrics);

/**
 * @brief Obtient le nombre d'opérations par seconde
 * 
 * @return uint32_t Opérations par seconde
 */
uint32_t esp32_crypto_get_ops_per_second(void);

// ================================
// Utilitaires et debugging Enterprise
// ================================

/**
 * @brief Convertit un code d'erreur en string
 * 
 * @param error Code d'erreur ESP32 crypto
 * @return const char* Description de l'erreur
 */
const char* esp32_crypto_error_to_string(esp32_crypto_result_t error);

/**
 * @brief Affiche les informations du crypto ESP32 Enterprise (debug)
 */
void esp32_crypto_print_device_info_enterprise(void);

// ================================
// Fonctions de compatibilité API de base
// ================================

/**
 * @brief Initialise le gestionnaire crypto ESP32 (wrapper Enterprise)
 */
esp_err_t esp32_crypto_manager_init(const esp32_crypto_config_t* config);

/**
 * @brief Dé-initialise le gestionnaire crypto ESP32 (wrapper Enterprise)
 */
esp_err_t esp32_crypto_manager_deinit(void);

/**
 * @brief Obtient les informations du crypto ESP32 (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_get_device_info(esp32_crypto_info_t* info);

/**
 * @brief Vérifie l'état de santé du crypto ESP32 (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_health_check(void);

/**
 * @brief Génère des bytes aléatoires sécurisés (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_generate_random(uint8_t* random_bytes, size_t length);

/**
 * @brief Calcule un hash SHA-256 matériel (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_sha256(const uint8_t* data, size_t data_length, uint8_t* hash);

/**
 * @brief Génère une paire de clés ECDSA (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_generate_ecdsa_keypair(uint8_t key_id, uint8_t* public_key);

/**
 * @brief Obtient la clé publique depuis eFuse (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_get_public_key(uint8_t key_id, uint8_t* public_key);

/**
 * @brief Signe un message avec ECDSA (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_ecdsa_sign(uint8_t key_id, const uint8_t* message_hash, uint8_t* signature);

/**
 * @brief Vérifie une signature ECDSA (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_ecdsa_verify(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature);

/**
 * @brief Effectue une attestation de l'appareil (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_perform_attestation(const uint8_t* challenge, size_t challenge_size, 
                                                       esp32_attestation_t* attestation);

/**
 * @brief Vérifie l'intégrité du système crypto (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_verify_integrity(void);

/**
 * @brief Met à jour le heartbeat (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_update_heartbeat(uint32_t counter);

/**
 * @brief Stocke l'état d'urgence (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_store_emergency_state(void);

/**
 * @brief Teste les fonctionnalités crypto de base (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_self_test(void);

/**
 * @brief Affiche les informations du crypto ESP32 (wrapper Enterprise)
 */
void esp32_crypto_print_device_info(void);

/**
 * @brief Obtient les statistiques d'utilisation (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_get_statistics(uint32_t* operations_count, uint32_t* error_count, 
                                                   uint64_t* last_operation_time);

/**
 * @brief Obtient l'ID unique de l'appareil (wrapper Enterprise)
 */
esp32_crypto_result_t esp32_crypto_get_device_id(uint8_t* device_id);

#ifdef __cplusplus
}
#endif

#endif /* ESP32_CRYPTO_MANAGER_H */