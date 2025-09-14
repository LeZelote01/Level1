/**
 * @file esp32_crypto_manager.h
 * @brief Gestionnaire cryptographique ESP32 Enterprise Edition
 * 
 * Interface complète pour l'utilisation maximale des capacités crypto ESP32 :
 * HSM complet, TRNG optimisé, eFuse protection, accélérations matérielles.
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

// ================================
// Constantes Enterprise
// ================================

#define ESP32_SERIAL_NUMBER_SIZE        (6)
#define ESP32_PUBLIC_KEY_SIZE           (65)   // Format non compressé ECDSA P-256
#define ESP32_PRIVATE_KEY_SIZE          (32)   
#define ESP32_SIGNATURE_SIZE            (64)   // ECDSA P-256 (r + s)
#define ESP32_HASH_SIZE                 (32)   // SHA-256
#define ESP32_CERTIFICATE_SIZE          (512)  // Certificat simple
#define ESP32_CHALLENGE_SIZE            (32)   // Challenge attestation
#define ESP32_RANDOM_MAX_SIZE           (256)  // Max génération aléatoire par appel

// Nouveaux Enterprise
#define ESP32_EFUSE_KEY_BLOCKS          (8)    // 8 blocs eFuse Enterprise
#define ESP32_HSM_MAX_OPERATIONS        (1000) // Opérations/s HSM optimisé
#define ESP32_TRNG_ENTROPY_POOL_SIZE    (2048) // Pool entropie Enterprise
#define ESP32_SECURE_KEY_ROTATION_SIZE  (384)  // Rotation clés Enterprise

// ================================
// Types et énumérations Enterprise
// ================================

/**
 * @brief Codes de résultat crypto ESP32 Enterprise
 */
typedef enum {
    ESP32_CRYPTO_SUCCESS = 0,
    ESP32_CRYPTO_ERROR_INVALID_PARAM,
    ESP32_CRYPTO_ERROR_NOT_INITIALIZED,
    ESP32_CRYPTO_ERROR_MEMORY,
    ESP32_CRYPTO_ERROR_EFUSE_PROGRAMMING,
    ESP32_CRYPTO_ERROR_VERIFICATION_FAILED,
    ESP32_CRYPTO_ERROR_EXECUTION_FAILED,
    ESP32_CRYPTO_ERROR_ENTROPY_FAILED,
    ESP32_CRYPTO_ERROR_KEY_GENERATION,
    ESP32_CRYPTO_ERROR_FLASH_ENCRYPTION,
    ESP32_CRYPTO_ERROR_SECURE_BOOT,
    // Nouveaux codes Enterprise
    ESP32_CRYPTO_ERROR_HSM_OPERATION_FAILED,
    ESP32_CRYPTO_ERROR_TRNG_INSUFFICIENT_ENTROPY,
    ESP32_CRYPTO_ERROR_KEY_ROTATION_FAILED,
    ESP32_CRYPTO_ERROR_TAMPER_DETECTED,
    ESP32_CRYPTO_ERROR_PERFORMANCE_DEGRADED,
    ESP32_CRYPTO_ERROR_COMPLIANCE_VIOLATION,
    ESP32_CRYPTO_ERROR_EMERGENCY_SHUTDOWN
} esp32_crypto_result_t;

/**
 * @brief États du système crypto Enterprise
 */
typedef enum {
    ESP32_CRYPTO_STATE_UNINITIALIZED = 0,
    ESP32_CRYPTO_STATE_INITIALIZING,
    ESP32_CRYPTO_STATE_CONFIGURED,
    ESP32_CRYPTO_STATE_OPERATIONAL,
    ESP32_CRYPTO_STATE_PERFORMANCE_MODE,    // Nouveau Enterprise
    ESP32_CRYPTO_STATE_HIGH_SECURITY_MODE,  // Nouveau Enterprise
    ESP32_CRYPTO_STATE_MAINTENANCE_MODE,    // Nouveau Enterprise
    ESP32_CRYPTO_STATE_EMERGENCY_SHUTDOWN,  // Nouveau Enterprise
    ESP32_CRYPTO_STATE_ERROR
} esp32_crypto_state_t;

/**
 * @brief Types d'opérations crypto Enterprise
 */
typedef enum {
    ESP32_CRYPTO_OP_HASH = 0,
    ESP32_CRYPTO_OP_ENCRYPT,
    ESP32_CRYPTO_OP_DECRYPT,
    ESP32_CRYPTO_OP_SIGN,
    ESP32_CRYPTO_OP_VERIFY,
    ESP32_CRYPTO_OP_RANDOM,
    ESP32_CRYPTO_OP_KEY_DERIVE,
    // Nouvelles opérations Enterprise
    ESP32_CRYPTO_OP_ATTESTATION_CONTINUOUS,
    ESP32_CRYPTO_OP_INTEGRITY_REALTIME,
    ESP32_CRYPTO_OP_KEY_ROTATION,
    ESP32_CRYPTO_OP_BEHAVIORAL_ANALYSIS,
    ESP32_CRYPTO_OP_PERFORMANCE_MONITORING
} esp32_crypto_operation_t;

/**
 * @brief Configuration crypto ESP32 Enterprise
 */
typedef struct {
    bool enable_secure_boot;
    bool enable_flash_encryption;
    bool enable_hardware_random;
    bool enable_efuse_protection;
    bool enable_hsm_max_performance;      // Nouveau Enterprise
    bool enable_trng_continuous_test;     // Nouveau Enterprise
    bool enable_key_rotation;             // Nouveau Enterprise
    bool enable_tamper_detection;         // Nouveau Enterprise
    bool enable_performance_monitoring;   // Nouveau Enterprise
    bool enable_compliance_mode;          // Nouveau Enterprise
    uint8_t entropy_source;
    uint16_t rsa_key_size;
    uint32_t hsm_operation_timeout_ms;    // Nouveau Enterprise
    uint32_t trng_entropy_threshold;      // Nouveau Enterprise
    bool enable_debug_mode;
    uint8_t max_retries;
} esp32_crypto_config_t;

/**
 * @brief Informations du dispositif crypto ESP32 Enterprise
 */
typedef struct {
    uint8_t device_id[ESP32_SERIAL_NUMBER_SIZE];
    uint32_t chip_revision;
    bool secure_boot_enabled;
    bool flash_encryption_enabled;
    bool efuse_protection_enabled;        // Nouveau Enterprise
    bool hsm_max_performance_enabled;     // Nouveau Enterprise
    bool trng_continuous_test_enabled;    // Nouveau Enterprise
    bool tamper_detection_enabled;        // Nouveau Enterprise
    esp32_crypto_state_t state;
    uint32_t operation_count;
    uint32_t error_count;
    uint64_t last_operation_time;
    uint32_t available_entropy;
    // Métriques Enterprise
    uint32_t hsm_operations_per_second;   // Nouveau Enterprise
    uint32_t trng_entropy_rate;           // Nouveau Enterprise
    float performance_score;              // Nouveau Enterprise
    uint32_t security_score;              // Nouveau Enterprise
    uint32_t compliance_level;            // Nouveau Enterprise
    uint64_t uptime_seconds;              // Nouveau Enterprise
} esp32_crypto_info_t;

/**
 * @brief Informations de clé Enterprise avec métadonnées étendues
 */
typedef struct {
    uint8_t key_id;
    uint8_t key_type;
    uint16_t key_size;
    bool is_in_efuse;
    bool is_protected;
    bool is_rotatable;                    // Nouveau Enterprise
    bool is_backup_available;             // Nouveau Enterprise
    uint8_t efuse_block;
    uint32_t usage_count;
    uint64_t creation_time;               // Nouveau Enterprise
    uint64_t last_rotation_time;          // Nouveau Enterprise
    uint32_t rotation_interval_hours;     // Nouveau Enterprise
    uint8_t security_level;               // Nouveau Enterprise
    uint8_t key_data[64];                 // Public key ou métadonnées
} esp32_key_info_t;

/**
 * @brief Structure d'attestation ESP32 Enterprise étendue
 */
typedef struct {
    uint8_t challenge[ESP32_CHALLENGE_SIZE];
    uint8_t device_id[ESP32_SERIAL_NUMBER_SIZE];
    uint32_t timestamp;
    uint32_t boot_count;
    uint8_t response[ESP32_SIGNATURE_SIZE];
    uint8_t device_cert[ESP32_CERTIFICATE_SIZE];
    bool is_valid;
    // Extensions Enterprise
    uint32_t firmware_version;            // Nouveau Enterprise
    uint32_t security_level;              // Nouveau Enterprise
    uint8_t hardware_config_hash[32];     // Nouveau Enterprise
    uint32_t performance_metrics;         // Nouveau Enterprise
    uint8_t compliance_status;            // Nouveau Enterprise
    uint64_t continuous_operation_time;   // Nouveau Enterprise
} esp32_attestation_t;

/**
 * @brief Métriques de performance crypto Enterprise
 */
typedef struct {
    uint32_t operations_per_second;
    uint32_t average_operation_time_us;
    uint32_t peak_operation_time_us;
    uint32_t entropy_generation_rate;
    uint32_t cache_hit_ratio_percent;
    uint32_t error_rate_per_million;
    uint32_t temperature_celsius;
    uint32_t power_consumption_mw;
    float efficiency_score;
} esp32_crypto_performance_t;

// ================================
// Fonctions principales Enterprise
// ================================

/**
 * @brief Initialise le gestionnaire crypto ESP32 Enterprise
 * @param config Configuration Enterprise (NULL pour défaut)
 * @return Code de résultat
 */
esp_err_t esp32_crypto_manager_init_enterprise(const esp32_crypto_config_t* config);

/**
 * @brief Dé-initialise le gestionnaire crypto Enterprise
 * @return Code de résultat
 */
esp_err_t esp32_crypto_manager_deinit_enterprise(void);

/**
 * @brief Obtient les informations détaillées du dispositif Enterprise
 * @param info Structure d'informations à remplir
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_get_device_info_enterprise(esp32_crypto_info_t* info);

/**
 * @brief Vérification de santé crypto Enterprise complète
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_health_check_enterprise(void);

/**
 * @brief Auto-test crypto ESP32 Enterprise complet
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_self_test_enterprise(void);

// ================================
// Fonctions de génération de clés Enterprise
// ================================

/**
 * @brief Génère une paire de clés ECDSA dans eFuse Enterprise
 * @param key_id ID du slot de clé
 * @param public_key Buffer pour la clé publique
 * @param key_metadata Métadonnées de clé Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_generate_ecdsa_keypair_enterprise(uint8_t key_id, uint8_t* public_key, esp32_key_info_t* key_metadata);

/**
 * @brief Rotation automatique des clés Enterprise
 * @param key_id ID du slot de clé
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_rotate_key_enterprise(uint8_t key_id);

/**
 * @brief Sauvegarde sécurisée des clés Enterprise
 * @param key_id ID du slot de clé
 * @param backup_location Emplacement de sauvegarde
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_backup_key_enterprise(uint8_t key_id, uint8_t backup_location);

// ================================
// Fonctions cryptographiques Enterprise avancées
// ================================

/**
 * @brief Génération aléatoire TRNG optimisée Enterprise
 * @param random_bytes Buffer de sortie
 * @param length Longueur requise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_generate_random_enterprise(uint8_t* random_bytes, size_t length);

/**
 * @brief Test continu TRNG Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_trng_continuous_test(void);

/**
 * @brief Calcul SHA-256 avec accélération matérielle maximale
 * @param data Données d'entrée
 * @param data_length Longueur des données
 * @param hash Hash de sortie
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_sha256_enterprise(const uint8_t* data, size_t data_length, uint8_t* hash);

/**
 * @brief Signature ECDSA avec HSM optimisé Enterprise
 * @param key_id ID de la clé dans eFuse
 * @param message_hash Hash du message
 * @param signature Signature de sortie
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_ecdsa_sign_enterprise(uint8_t key_id, const uint8_t* message_hash, uint8_t* signature);

/**
 * @brief Vérification ECDSA optimisée Enterprise
 * @param public_key Clé publique
 * @param message_hash Hash du message
 * @param signature Signature à vérifier
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_ecdsa_verify_enterprise(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature);

// ================================
// Fonctions d'attestation Enterprise
// ================================

/**
 * @brief Attestation complète Enterprise avec métadonnées étendues
 * @param challenge Challenge d'entrée
 * @param challenge_size Taille du challenge
 * @param attestation Structure d'attestation Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_perform_attestation_enterprise(const uint8_t* challenge, size_t challenge_size, esp32_attestation_t* attestation);

/**
 * @brief Attestation continue autonome Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_continuous_attestation(void);

/**
 * @brief Renouvellement automatique d'attestation Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_attestation_renewal(void);

// ================================
// Fonctions de monitoring Enterprise
// ================================

/**
 * @brief Monitoring de performance crypto en temps réel
 * @param performance Métriques de performance
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_get_performance_metrics(esp32_crypto_performance_t* performance);

/**
 * @brief Optimisation automatique des performances
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_optimize_performance(void);

/**
 * @brief Détection de tampering matériel
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_tamper_detection(void);

// ================================
// Fonctions de gestion d'énergie Enterprise
// ================================

/**
 * @brief Gestion énergétique adaptative Enterprise
 * @param power_mode Mode de consommation
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_adaptive_power_management(uint8_t power_mode);

/**
 * @brief Surveillance de la température crypto
 * @param temperature_celsius Température actuelle
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_temperature_monitoring(uint32_t* temperature_celsius);

// ================================
// Fonctions de conformité Enterprise
// ================================

/**
 * @brief Vérification de conformité sécurité
 * @param compliance_level Niveau de conformité atteint
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_compliance_check(uint32_t* compliance_level);

/**
 * @brief Audit de sécurité automatique
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_security_audit(void);

// ================================
// Fonctions utilitaires Enterprise
// ================================

/**
 * @brief Convertit un code d'erreur en chaîne lisible
 * @param error Code d'erreur
 * @return Chaîne descriptive
 */
const char* esp32_crypto_error_to_string(esp32_crypto_result_t error);

/**
 * @brief Affiche les informations détaillées du dispositif Enterprise
 */
void esp32_crypto_print_device_info_enterprise(void);

/**
 * @brief Obtient les statistiques détaillées Enterprise
 * @param operations_count Nombre d'opérations
 * @param error_count Nombre d'erreurs
 * @param last_operation_time Temps de la dernière opération
 * @param performance_score Score de performance
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_get_statistics_enterprise(uint32_t* operations_count, uint32_t* error_count, uint64_t* last_operation_time, float* performance_score);

/**
 * @brief Obtient l'ID unique du dispositif
 * @param device_id Buffer pour l'ID du dispositif
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_get_device_id(uint8_t* device_id);

/**
 * @brief Obtient les opérations par seconde HSM
 * @return Opérations par seconde
 */
uint32_t esp32_crypto_get_ops_per_second(void);

// ================================
// Fonctions de compatibilité Enterprise
// ================================

/**
 * @brief Vérification d'intégrité Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_verify_integrity_enterprise(void);

/**
 * @brief Mise à jour heartbeat Enterprise avec métriques
 * @param counter Compteur heartbeat
 * @param security_score Score de sécurité
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_update_heartbeat_enterprise(uint32_t counter, uint32_t security_score);

/**
 * @brief Stockage d'état d'urgence Enterprise
 * @return Code de résultat
 */
esp32_crypto_result_t esp32_crypto_store_emergency_state_enterprise(void);

// ================================
// Alias de compatibilité (héritage Community/Full)
// ================================

// Maintient la compatibilité avec les versions précédentes
#define esp32_crypto_manager_init(config) esp32_crypto_manager_init_enterprise(config)
#define esp32_crypto_manager_deinit() esp32_crypto_manager_deinit_enterprise()
#define esp32_crypto_get_device_info(info) esp32_crypto_get_device_info_enterprise(info)
#define esp32_crypto_health_check() esp32_crypto_health_check_enterprise()
#define esp32_crypto_self_test() esp32_crypto_self_test_enterprise()
#define esp32_crypto_generate_ecdsa_keypair(key_id, public_key) esp32_crypto_generate_ecdsa_keypair_enterprise(key_id, public_key, NULL)
#define esp32_crypto_generate_random(buffer, length) esp32_crypto_generate_random_enterprise(buffer, length)
#define esp32_crypto_sha256(data, length, hash) esp32_crypto_sha256_enterprise(data, length, hash)
#define esp32_crypto_ecdsa_sign(key_id, hash, signature) esp32_crypto_ecdsa_sign_enterprise(key_id, hash, signature)
#define esp32_crypto_ecdsa_verify(public_key, hash, signature) esp32_crypto_ecdsa_verify_enterprise(public_key, hash, signature)
#define esp32_crypto_perform_attestation(challenge, size, attestation) esp32_crypto_perform_attestation_enterprise(challenge, size, attestation)
#define esp32_crypto_verify_integrity() esp32_crypto_verify_integrity_enterprise()
#define esp32_crypto_update_heartbeat(counter) esp32_crypto_update_heartbeat_enterprise(counter, 100)
#define esp32_crypto_store_emergency_state() esp32_crypto_store_emergency_state_enterprise()

#ifdef __cplusplus
}
#endif

#endif /* ESP32_CRYPTO_MANAGER_H */