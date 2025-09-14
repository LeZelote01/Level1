/**
 * @file signature_verifier.h
 * @brief Vérificateur de signatures Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec accélération matérielle ESP32 HSM,
 * vérification parallèle, signatures composites et cache optimisé.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef SIGNATURE_VERIFIER_H
#define SIGNATURE_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "integrity_checker.h"

// ================================
// Constantes Enterprise
// ================================

#define SIGNATURE_VERIFICATION_VERSION_ENTERPRISE "2.0.0"
#define INTEGRITY_SIGNATURE_SIZE_ENTERPRISE       (128)   // Signatures étendues
#define SIGNATURE_COMPOSITE_SIZE_ENTERPRISE       (320)   // Signatures composites
#define MAX_FAILED_CHUNKS_ENTERPRISE              (32)    // Chunks en échec max

// Compatibilité version standard
#define SIGNATURE_VERIFICATION_VERSION "1.0.0"

// ================================
// Types Enterprise
// ================================

/**
 * @brief Méthodes de vérification de signature Enterprise
 */
typedef enum {
    SIGNATURE_METHOD_HASH_ONLY = 0,         // Hash uniquement
    SIGNATURE_METHOD_ECDSA_P256,            // ECDSA P-256 standard
    SIGNATURE_METHOD_ECDSA_P384,            // ECDSA P-384 haute sécurité
    SIGNATURE_METHOD_RSA_2048,              // RSA-2048
    SIGNATURE_METHOD_RSA_4096,              // RSA-4096 haute sécurité
    SIGNATURE_METHOD_COMPOSITE,             // Signature composite Enterprise
    SIGNATURE_METHOD_QUANTUM_RESISTANT      // Post-quantique (futur)
} signature_verification_method_t;

/**
 * @brief Configuration du vérificateur Enterprise
 */
typedef struct {
    bool hardware_acceleration;             // Accélération HSM ESP32
    bool parallel_verification;             // Vérification parallèle
    bool cache_enabled;                     // Cache signatures
    bool composite_signatures;              // Support signatures composites
    bool realtime_validation;              // Validation temps réel
    bool efuse_key_validation;             // Validation clés eFuse
    bool performance_optimization;          // Optimisations performance
    signature_verification_method_t preferred_method; // Méthode préférée
} signature_verifier_config_enterprise_t;

/**
 * @brief Entrée du cache de signatures
 */
typedef struct {
    uint8_t hash[INTEGRITY_HASH_SIZE];
    signature_verification_result_enterprise_t result;
    uint32_t timestamp;
    uint32_t hit_count;
    uint32_t last_access;
} signature_cache_entry_t;

/**
 * @brief Résultat de vérification Enterprise étendu
 */
typedef struct {
    // Champs de base
    bool is_valid;
    uint8_t signature[INTEGRITY_SIGNATURE_SIZE_ENTERPRISE];
    uint32_t verification_time_ms;
    uint32_t timestamp;
    
    // Extensions Enterprise
    signature_verification_method_t verification_method;
    bool hardware_accelerated;
    bool efuse_validated;
    bool cache_hit;
    bool chunk_verification;
    uint32_t chunk_id;
    
    // Signatures composites
    bool has_composite_signature;
    bool composite_signature_valid;
    uint8_t composite_signature[SIGNATURE_COMPOSITE_SIZE_ENTERPRISE];
    
    // Métadonnées de validation
    uint8_t verified_hash[INTEGRITY_HASH_SIZE];
    bool efuse_integrity_ok;
    float crypto_performance_score;
    uint8_t security_strength;           // Niveau de sécurité (1-5)
    
    // Debugging et monitoring
    uint32_t crypto_operations_count;
    uint32_t memory_usage_bytes;
} signature_verification_result_enterprise_t;

/**
 * @brief Résultat de vérification batch (parallèle)
 */
typedef struct {
    uint32_t total_chunks;
    uint32_t verified_chunks;
    uint32_t failed_chunks;
    uint32_t failed_chunk_ids[MAX_FAILED_CHUNKS_ENTERPRISE];
    uint8_t failed_chunk_count;
    float success_rate;
    uint32_t processing_time_ms;
    float avg_time_per_chunk_ms;
    uint32_t start_timestamp;
    bool parallel_processing;
} signature_batch_result_enterprise_t;

/**
 * @brief Statistiques du vérificateur Enterprise
 */
typedef struct {
    uint32_t total_verifications;
    uint32_t successful_verifications;  
    uint32_t failed_verifications;
    float success_rate;
    float avg_verification_time_ms;
    uint32_t cache_entries;
    float cache_hit_rate;
    uint32_t uptime_seconds;
} signature_verifier_stats_enterprise_t;

/**
 * @brief Métadonnées d'intégrité Enterprise étendues
 */
typedef struct {
    uint8_t global_hash[INTEGRITY_HASH_SIZE];
    uint8_t global_signature[INTEGRITY_SIGNATURE_SIZE_ENTERPRISE];
    bool has_composite_signature;
    uint8_t composite_signature[SIGNATURE_COMPOSITE_SIZE_ENTERPRISE];
    signature_verification_method_t signature_method;
    uint32_t key_version;
    bool efuse_protected;
} integrity_metadata_enterprise_t;

/**
 * @brief Informations de chunk Enterprise étendues
 */
typedef struct {
    uint32_t chunk_id;
    uint8_t hash[INTEGRITY_HASH_SIZE];
    uint8_t signature[INTEGRITY_SIGNATURE_SIZE_ENTERPRISE];
    signature_verification_method_t signature_method;
    bool is_critical;
    uint8_t priority;
} integrity_chunk_info_enterprise_t;

/**
 * @brief Structure de base pour compatibilité
 */
typedef struct {
    bool is_valid;
    uint8_t signature[64];
    uint32_t verification_time_ms;
} signature_verification_result_t;

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation du vérificateur de signatures Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verifier_init_enterprise(void);

/**
 * @brief Dé-initialisation du vérificateur Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verifier_deinit_enterprise(void);

/**
 * @brief Vérification de signature firmware Enterprise complète
 * @param metadata Métadonnées du firmware Enterprise
 * @param result Résultat de la vérification Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verify_firmware_enterprise(const integrity_metadata_enterprise_t* metadata, signature_verification_result_enterprise_t* result);

/**
 * @brief Vérification de signature chunk Enterprise avec optimisations
 * @param chunk Informations du chunk Enterprise
 * @param result Résultat de la vérification Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verify_chunk_enterprise(const integrity_chunk_info_enterprise_t* chunk, signature_verification_result_enterprise_t* result);

/**
 * @brief Vérification parallèle de multiple chunks (Innovation Enterprise)
 * @param chunks Tableau de chunks à vérifier
 * @param chunk_count Nombre de chunks
 * @param batch_result Résultat de la vérification batch
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verify_chunks_parallel_enterprise(const integrity_chunk_info_enterprise_t* chunks, uint32_t chunk_count, signature_batch_result_enterprise_t* batch_result);

/**
 * @brief Configuration du vérificateur Enterprise
 * @param config Configuration Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verifier_configure_enterprise(const signature_verifier_config_enterprise_t* config);

/**
 * @brief Obtention des statistiques du vérificateur Enterprise
 * @return Statistiques complètes
 */
signature_verifier_stats_enterprise_t signature_verifier_get_stats_enterprise(void);

/**
 * @brief Nettoyage du cache de signatures Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t signature_verifier_clear_cache_enterprise(void);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Vérification de signature firmware (compatibilité)
 */
esp_err_t signature_verify_firmware(const integrity_metadata_t* metadata, signature_verification_result_t* result);

/**
 * @brief Vérification de signature chunk (compatibilité)
 */
esp_err_t signature_verify_chunk(const integrity_chunk_info_t* chunk, signature_verification_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_VERIFIER_H */