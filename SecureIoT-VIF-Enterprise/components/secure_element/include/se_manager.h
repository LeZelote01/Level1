/**
 * @file se_manager.h
 * @brief Aliases de compatibilité Enterprise pour SecureIoT-VIF ESP32 Crypto
 * 
 * Version Enterprise avec extensions complètes pour l'utilisation maximale
 * du crypto ESP32 intégré : HSM complet, TRNG optimisé, eFuse protection.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef SE_MANAGER_H
#define SE_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

// Inclure l'interface ESP32 crypto intégré Enterprise
#include "esp32_crypto_manager.h"

// ================================
// Aliases de Types Enterprise
// ================================

typedef esp32_crypto_result_t se_result_t;
typedef esp32_crypto_info_t se_device_info_t;
typedef esp32_key_info_t se_key_info_t;
typedef esp32_attestation_t se_attestation_t;
typedef esp32_crypto_performance_t se_performance_metrics_t;  // Nouveau Enterprise

// États Enterprise étendus
#define SE_SUCCESS                          ESP32_CRYPTO_SUCCESS
#define SE_ERROR_INVALID_PARAM              ESP32_CRYPTO_ERROR_INVALID_PARAM
#define SE_ERROR_NOT_INITIALIZED            ESP32_CRYPTO_ERROR_NOT_INITIALIZED
#define SE_ERROR_VERIFICATION_FAILED        ESP32_CRYPTO_ERROR_VERIFICATION_FAILED
#define SE_ERROR_EXECUTION_FAILED           ESP32_CRYPTO_ERROR_EXECUTION_FAILED
#define SE_ERROR_MEMORY                     ESP32_CRYPTO_ERROR_MEMORY
// Nouveaux codes Enterprise
#define SE_ERROR_HSM_OPERATION_FAILED       ESP32_CRYPTO_ERROR_HSM_OPERATION_FAILED
#define SE_ERROR_TRNG_INSUFFICIENT_ENTROPY  ESP32_CRYPTO_ERROR_TRNG_INSUFFICIENT_ENTROPY
#define SE_ERROR_KEY_ROTATION_FAILED        ESP32_CRYPTO_ERROR_KEY_ROTATION_FAILED
#define SE_ERROR_TAMPER_DETECTED            ESP32_CRYPTO_ERROR_TAMPER_DETECTED
#define SE_ERROR_PERFORMANCE_DEGRADED       ESP32_CRYPTO_ERROR_PERFORMANCE_DEGRADED
#define SE_ERROR_COMPLIANCE_VIOLATION       ESP32_CRYPTO_ERROR_COMPLIANCE_VIOLATION
#define SE_ERROR_EMERGENCY_SHUTDOWN         ESP32_CRYPTO_ERROR_EMERGENCY_SHUTDOWN

// Constantes Enterprise étendues
#define SE_SERIAL_NUMBER_SIZE               ESP32_SERIAL_NUMBER_SIZE
#define SE_PUBLIC_KEY_SIZE                  ESP32_PUBLIC_KEY_SIZE
#define SE_PRIVATE_KEY_SIZE                 ESP32_PRIVATE_KEY_SIZE
#define SE_SIGNATURE_SIZE                   ESP32_SIGNATURE_SIZE
#define SE_CERTIFICATE_SIZE                 ESP32_CERTIFICATE_SIZE
#define SE_RANDOM_MAX_SIZE                  ESP32_RANDOM_MAX_SIZE
// Nouvelles constantes Enterprise
#define SE_EFUSE_KEY_BLOCKS                 ESP32_EFUSE_KEY_BLOCKS
#define SE_HSM_MAX_OPERATIONS               ESP32_HSM_MAX_OPERATIONS
#define SE_TRNG_ENTROPY_POOL_SIZE           ESP32_TRNG_ENTROPY_POOL_SIZE

// Slots eFuse Enterprise (8 blocs)
#define SE_SLOT_DEVICE_PRIVATE_KEY          (0)    // Clé privée principale
#define SE_SLOT_ATTESTATION_KEY             (1)    // Clé d'attestation
#define SE_SLOT_ENCRYPTION_KEY              (2)    // Clé de chiffrement
#define SE_SLOT_HMAC_KEY                    (3)    // Clé HMAC
#define SE_SLOT_BACKUP_KEY                  (4)    // Clé de sauvegarde Enterprise
#define SE_SLOT_SESSION_KEY                 (5)    // Clé de session Enterprise
#define SE_SLOT_ML_MODEL_KEY                (6)    // Clé modèle ML Enterprise
#define SE_SLOT_RESERVED                    (7)    // Réservé futur Enterprise

// ================================
// Aliases de Fonctions Enterprise
// ================================

// Gestion générale Enterprise
#define se_manager_init()                           esp32_crypto_manager_init_enterprise(NULL)
#define se_manager_init_enterprise(config)          esp32_crypto_manager_init_enterprise(config)
#define se_manager_deinit()                         esp32_crypto_manager_deinit_enterprise()
#define se_get_device_info(info)                    esp32_crypto_get_device_info_enterprise(info)
#define se_health_check()                           esp32_crypto_health_check_enterprise()
#define se_self_test()                              esp32_crypto_self_test_enterprise()

// Gestion des clés Enterprise
#define se_generate_key_pair(id, key)               esp32_crypto_generate_ecdsa_keypair_enterprise(id, key, NULL)
#define se_generate_key_pair_enterprise(id, key, meta) esp32_crypto_generate_ecdsa_keypair_enterprise(id, key, meta)
#define se_get_public_key(id, key)                  esp32_crypto_get_public_key(id, key)
#define se_rotate_key(id)                           esp32_crypto_rotate_key_enterprise(id)
#define se_backup_key(id, backup_loc)               esp32_crypto_backup_key_enterprise(id, backup_loc)

// Opérations cryptographiques Enterprise
#define se_sign_message(id, hash, sig)              esp32_crypto_ecdsa_sign_enterprise(id, hash, sig)
#define se_verify_signature(key, hash, sig)         esp32_crypto_ecdsa_verify_enterprise(key, hash, sig)
#define se_generate_random(buf, len)                esp32_crypto_generate_random_enterprise(buf, len)
#define se_sha256(data, len, hash)                  esp32_crypto_sha256_enterprise(data, len, hash)

// Fonctions TRNG Enterprise
#define se_trng_continuous_test()                   esp32_crypto_trng_continuous_test()
#define se_generate_entropy(buf, len)               esp32_crypto_generate_random_enterprise(buf, len)

// Attestation et vérification Enterprise
#define se_perform_attestation(ch, sz, att)         esp32_crypto_perform_attestation_enterprise(ch, sz, att)
#define se_continuous_attestation()                 esp32_crypto_continuous_attestation()
#define se_attestation_renewal()                    esp32_crypto_attestation_renewal()
#define se_verify_integrity()                       esp32_crypto_verify_integrity_enterprise()

// Monitoring et performance Enterprise
#define se_get_performance_metrics(metrics)         esp32_crypto_get_performance_metrics(metrics)
#define se_optimize_performance()                   esp32_crypto_optimize_performance()
#define se_tamper_detection()                       esp32_crypto_tamper_detection()
#define se_get_ops_per_second()                     esp32_crypto_get_ops_per_second()

// Gestion d'énergie Enterprise
#define se_adaptive_power_management(mode)          esp32_crypto_adaptive_power_management(mode)
#define se_temperature_monitoring(temp)             esp32_crypto_temperature_monitoring(temp)

// Conformité Enterprise
#define se_compliance_check(level)                  esp32_crypto_compliance_check(level)
#define se_security_audit()                         esp32_crypto_security_audit()

// Gestion d'état Enterprise
#define se_update_heartbeat(cnt)                    esp32_crypto_update_heartbeat_enterprise(cnt, 100)
#define se_update_heartbeat_enterprise(cnt, score)  esp32_crypto_update_heartbeat_enterprise(cnt, score)
#define se_store_emergency_state()                  esp32_crypto_store_emergency_state_enterprise()

// Utilitaires Enterprise
#define se_error_to_string(error)                   esp32_crypto_error_to_string(error)
#define se_print_device_info()                      esp32_crypto_print_device_info_enterprise()
#define se_get_statistics(ops, err, time)           esp32_crypto_get_statistics_enterprise(ops, err, time, NULL)
#define se_get_statistics_enterprise(ops, err, time, perf) esp32_crypto_get_statistics_enterprise(ops, err, time, perf)
#define se_get_device_id(id)                        esp32_crypto_get_device_id(id)

// ================================
// Fonctions spécifiques Enterprise
// ================================

/**
 * @brief Initialisation complète SE Enterprise avec configuration avancée
 * @param enable_hsm_max_performance Activer performance HSM maximale
 * @param enable_continuous_tests Activer tests continus TRNG
 * @param enable_tamper_detection Activer détection manipulation
 * @return se_result_t SE_SUCCESS en cas de succès
 */
static inline se_result_t se_init_enterprise_advanced(bool enable_hsm_max_performance,
                                                     bool enable_continuous_tests,
                                                     bool enable_tamper_detection) {
    esp32_crypto_config_t config = {
        .enable_secure_boot = true,
        .enable_flash_encryption = true,
        .enable_hardware_random = true,
        .enable_efuse_protection = true,
        .enable_hsm_max_performance = enable_hsm_max_performance,
        .enable_trng_continuous_test = enable_continuous_tests,
        .enable_key_rotation = true,
        .enable_tamper_detection = enable_tamper_detection,
        .enable_performance_monitoring = true,
        .enable_compliance_mode = true,
        .entropy_source = 1,
        .rsa_key_size = 2048,
        .hsm_operation_timeout_ms = 1000,
        .trng_entropy_threshold = 1024,
        .enable_debug_mode = false,
        .max_retries = 2
    };
    
    return esp32_crypto_manager_init_enterprise(&config);
}

/**
 * @brief Vérification santé complète Enterprise
 * @param performance_score Pointeur vers le score de performance
 * @param security_score Pointeur vers le score de sécurité
 * @return se_result_t SE_SUCCESS si tous les tests passent
 */
static inline se_result_t se_comprehensive_health_check(float* performance_score,
                                                       uint32_t* security_score) {
    se_result_t result = esp32_crypto_health_check_enterprise();
    if (result == SE_SUCCESS) {
        esp32_crypto_performance_t metrics;
        if (esp32_crypto_get_performance_metrics(&metrics) == ESP32_CRYPTO_SUCCESS) {
            if (performance_score) *performance_score = metrics.efficiency_score;
        }
        
        esp32_crypto_info_t info;
        if (esp32_crypto_get_device_info_enterprise(&info) == ESP32_CRYPTO_SUCCESS) {
            if (security_score) *security_score = info.security_score;
        }
    }
    return result;
}

/**
 * @brief Auto-diagnostic Enterprise complet
 * @return se_result_t SE_SUCCESS si tous les diagnostics passent
 */
static inline se_result_t se_enterprise_auto_diagnostic(void) {
    se_result_t result;
    
    // Test de base
    result = esp32_crypto_self_test_enterprise();
    if (result != SE_SUCCESS) return result;
    
    // Test TRNG continu
    result = esp32_crypto_trng_continuous_test();
    if (result != SE_SUCCESS) return result;
    
    // Test de détection de manipulation
    result = esp32_crypto_tamper_detection();
    if (result != SE_SUCCESS) return result;
    
    // Vérification conformité
    uint32_t compliance_level;
    result = esp32_crypto_compliance_check(&compliance_level);
    if (result != SE_SUCCESS || compliance_level < 3) return SE_ERROR_COMPLIANCE_VIOLATION;
    
    return SE_SUCCESS;
}

// ================================
// Macros utilitaires Enterprise
// ================================

/**
 * @brief Macro pour vérification rapide des résultats Enterprise
 */
#define SE_CHECK_RESULT_ENTERPRISE(result) do { \
    if ((result) != SE_SUCCESS) { \
        ESP_LOGE("SE_ENTERPRISE", "Échec opération SE: %s à %s:%d", \
                 se_error_to_string(result), __FILE__, __LINE__); \
        return (result); \
    } \
} while(0)

/**
 * @brief Macro pour logging performance Enterprise
 */
#define SE_LOG_PERFORMANCE_ENTERPRISE(operation, start_time) do { \
    uint64_t __end_time = esp_timer_get_time(); \
    ESP_LOGI("SE_PERF", "%s completed in %llu μs", \
             (operation), (__end_time - start_time)); \
} while(0)

/**
 * @brief Macro pour vérification sécurité Enterprise
 */
#define SE_SECURITY_CHECK_ENTERPRISE() do { \
    se_result_t __sec_result = esp32_crypto_tamper_detection(); \
    if (__sec_result != SE_SUCCESS) { \
        ESP_LOGE("SE_SECURITY", "Violation sécurité détectée: %s", \
                 se_error_to_string(__sec_result)); \
        esp32_crypto_store_emergency_state_enterprise(); \
        return SE_ERROR_TAMPER_DETECTED; \
    } \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* SE_MANAGER_H */