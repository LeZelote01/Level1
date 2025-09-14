/**
 * @file attestation_manager.h
 * @brief Gestionnaire d'attestation continue Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec attestation continue, renouvellement autonome,
 * analyse comportementale et intégration HSM ESP32 complète.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef ATTESTATION_MANAGER_H
#define ATTESTATION_MANAGER_H

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

#define ATTESTATION_CHALLENGE_SIZE_ENTERPRISE   (64)    // Doublé vs Community
#define ATTESTATION_RESPONSE_SIZE_ENTERPRISE    (256)   // Doublé vs Community
#define ATTESTATION_CERT_SIZE_ENTERPRISE        (1024)  // Doublé vs Community
#define ATTESTATION_COMPOSITE_SIG_SIZE          (320)   // Signature composite Enterprise

// Compatibilité avec version standard
#define ATTESTATION_CHALLENGE_SIZE  (32)
#define ATTESTATION_RESPONSE_SIZE   (128)
#define ATTESTATION_CERT_SIZE       (512)

// ================================
// Types d'erreur Enterprise étendus
// ================================

typedef enum {
    ATTESTATION_SUCCESS = 0,
    ATTESTATION_ERROR_INVALID_CHALLENGE = -1,
    ATTESTATION_ERROR_SIGNATURE_FAILED = -2,
    ATTESTATION_ERROR_CERTIFICATE_INVALID = -3,
    ATTESTATION_ERROR_TIMEOUT = -4,
    ATTESTATION_ERROR_COMMUNICATION = -5,
    // Erreurs Enterprise spécifiques
    ATTESTATION_ERROR_NOT_INITIALIZED = -10,
    ATTESTATION_ERROR_CRYPTO_FAILURE = -11,
    ATTESTATION_ERROR_INTEGRITY_FAILED = -12,
    ATTESTATION_ERROR_HSM_UNAVAILABLE = -13,
    ATTESTATION_ERROR_EFUSE_CORRUPTION = -14,
    ATTESTATION_ERROR_BEHAVIORAL_ANOMALY = -15,
    ATTESTATION_ERROR_COMPLIANCE_VIOLATION = -16
} attestation_status_t;

// ================================
// Structures Enterprise
// ================================

/**
 * @brief Fonctionnalités Enterprise de l'attestation
 */
typedef struct {
    bool continuous_mode;           // Mode continu activé
    bool autonomous_renewal;        // Renouvellement autonome
    bool hsm_accelerated;          // Accéléré par HSM ESP32
    bool efuse_protected;          // Clés protégées eFuse
    bool trng_generated;           // Challenge généré par TRNG
    bool hardware_accelerated;     // Crypto matériel
    bool integrity_verified;       // Intégrité vérifiée en parallèle
    bool self_attestation;         // Auto-attestation
    bool behavioral_analysis;      // Analyse comportementale
    bool compliance_audit;         // Audit conformité
} attestation_enterprise_features_t;

/**
 * @brief Résultat d'attestation Enterprise étendu
 */
typedef struct {
    // Champs standards
    attestation_status_t status;
    uint8_t challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE];
    uint8_t response[ATTESTATION_RESPONSE_SIZE_ENTERPRISE];
    uint8_t device_certificate[ATTESTATION_CERT_SIZE_ENTERPRISE];
    uint32_t timestamp;
    bool is_valid;
    uint32_t sequence_number;
    
    // Extensions Enterprise
    attestation_enterprise_features_t enterprise_features;
    uint8_t composite_signature[ATTESTATION_COMPOSITE_SIG_SIZE];
    uint32_t response_time_ms;
    float behavior_score;           // Score comportemental (0.0-1.0)
    uint8_t integrity_status;       // État intégrité
    uint32_t crypto_performance_ms; // Performance crypto
    
    // Métadonnées de débogage Enterprise
    uint32_t heap_free_bytes;
    uint8_t cpu_usage_percent;
    uint32_t uptime_seconds;
} attestation_result_t;

/**
 * @brief Configuration Enterprise du gestionnaire d'attestation
 */
typedef struct {
    bool continuous_enabled;                // Attestation continue
    bool autonomous_renewal_enabled;        // Renouvellement autonome
    bool behavioral_analysis_enabled;       // Analyse comportementale
    bool high_frequency_mode;              // Mode haute fréquence
    bool performance_optimization;          // Optimisation performance
    bool compliance_logging;               // Logs conformité
    bool remote_verification_enabled;      // Vérification distante
    uint32_t autonomous_renewal_interval_ms; // Intervalle renouvellement (défaut: 300000ms)
} attestation_config_enterprise_t;

/**
 * @brief Statistiques d'attestation Enterprise
 */
typedef struct {
    uint32_t total_attestations;
    uint32_t autonomous_renewals;
    float success_rate;
    uint32_t current_sequence;
    float behavior_score;
    uint32_t uptime_seconds;
    uint32_t avg_response_time_ms;
    uint32_t min_response_time_ms;
    uint32_t max_response_time_ms;
} attestation_stats_enterprise_t;

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation du gestionnaire d'attestation Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t attestation_manager_init_enterprise(void);

/**
 * @brief Dé-initialisation du gestionnaire Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t attestation_manager_deinit_enterprise(void);

/**
 * @brief Attestation continue Enterprise avec fonctionnalités avancées
 * @return Résultat d'attestation avec métadonnées Enterprise
 */
attestation_result_t attestation_perform_continuous_enterprise(void);

/**
 * @brief Renouvellement autonome d'attestation (Innovation Enterprise)
 * @return Résultat du renouvellement
 */
attestation_result_t attestation_autonomous_renewal(void);

/**
 * @brief Réponse au challenge avec fonctionnalités Enterprise
 * @param challenge Challenge à traiter
 * @param challenge_size Taille du challenge
 * @param result Résultat de l'attestation
 * @return ESP_OK en cas de succès
 */
esp_err_t attestation_respond_to_challenge_enterprise(const uint8_t* challenge, size_t challenge_size, attestation_result_t* result);

/**
 * @brief Génération d'auto-attestation Enterprise avancée
 * @param result Résultat de l'auto-attestation
 * @return ESP_OK en cas de succès
 */
esp_err_t attestation_generate_self_attestation_enterprise(attestation_result_t* result);

/**
 * @brief Obtention des statistiques d'attestation Enterprise
 * @return Statistiques complètes
 */
attestation_stats_enterprise_t attestation_get_stats_enterprise(void);

/**
 * @brief Configuration Enterprise du gestionnaire d'attestation
 * @param config Configuration Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t attestation_configure_enterprise(const attestation_config_enterprise_t* config);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Initialisation (compatibilité)
 */
esp_err_t attestation_manager_init(void);

/**
 * @brief Dé-initialisation (compatibilité)
 */
esp_err_t attestation_manager_deinit(void);

/**
 * @brief Attestation continue (compatibilité)
 */
attestation_result_t attestation_perform_continuous(void);

/**
 * @brief Réponse au challenge (compatibilité)
 */
esp_err_t attestation_respond_to_challenge(const uint8_t* challenge, size_t challenge_size, attestation_result_t* result);

/**
 * @brief Auto-attestation (compatibilité)
 */
esp_err_t attestation_generate_self_attestation(attestation_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* ATTESTATION_MANAGER_H */