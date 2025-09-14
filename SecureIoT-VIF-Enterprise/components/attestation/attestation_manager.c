/**
 * @file attestation_manager.c
 * @brief Gestionnaire d'attestation continue Enterprise avec renouvellement autonome
 * 
 * Version Enterprise avec attestation continue, renouvellement autonome,
 * intégration HSM ESP32 complète et monitoring avancé.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "attestation_manager.h"
#include "remote_verifier.h"
#include "esp32_crypto_manager.h"
#include "integrity_checker.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <math.h>

static const char *TAG = "ATTESTATION_MGR_ENTERPRISE";

// Variables globales Enterprise
static bool g_attestation_initialized = false;
static uint32_t g_sequence_counter = 0;
static uint32_t g_continuous_attestations_performed = 0;
static uint32_t g_autonomous_renewals_count = 0;
static float g_attestation_success_rate = 1.0f;
static SemaphoreHandle_t g_attestation_mutex = NULL;

// Timer pour renouvellement autonome
static esp_timer_handle_t g_autonomous_renewal_timer = NULL;

// Historique des attestations pour analyse comportementale
#define ATTESTATION_HISTORY_SIZE 50
static attestation_result_t g_attestation_history[ATTESTATION_HISTORY_SIZE];
static uint8_t g_history_index = 0;
static bool g_history_full = false;

// Configuration Enterprise avancée
static attestation_config_enterprise_t g_config_enterprise = {
    .continuous_enabled = true,
    .autonomous_renewal_enabled = true,
    .behavioral_analysis_enabled = true,
    .high_frequency_mode = false,
    .performance_optimization = true,
    .compliance_logging = true
};

/**
 * @brief Callback pour le renouvellement autonome
 */
static void autonomous_renewal_timer_callback(void* arg) {
    ESP_LOGD(TAG, "🔄 Déclenché renouvellement autonome Enterprise");
    
    if (xSemaphoreTake(g_attestation_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        attestation_result_t result = attestation_autonomous_renewal();
        if (result.status == ATTESTATION_SUCCESS) {
            g_autonomous_renewals_count++;
            ESP_LOGI(TAG, "✅ Renouvellement autonome réussi #%lu", g_autonomous_renewals_count);
        } else {
            ESP_LOGW(TAG, "⚠️ Échec renouvellement autonome: %d", result.status);
        }
        xSemaphoreGive(g_attestation_mutex);
    }
}

/**
 * @brief Initialisation du gestionnaire d'attestation Enterprise
 */
esp_err_t attestation_manager_init_enterprise(void) {
    if (g_attestation_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🛡️ Initialisation gestionnaire attestation Enterprise");
    
    // Création du mutex pour thread-safety
    g_attestation_mutex = xSemaphoreCreateMutex();
    if (g_attestation_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex attestation");
        return ESP_FAIL;
    }
    
    // Initialisation du vérifieur distant Enterprise
    esp_err_t ret = remote_verifier_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation vérifieur distant Enterprise: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Configuration du timer de renouvellement autonome
    if (g_config_enterprise.autonomous_renewal_enabled) {
        esp_timer_create_args_t timer_args = {
            .callback = &autonomous_renewal_timer_callback,
            .arg = NULL,
            .name = "attestation_autonomous_renewal_enterprise"
        };
        
        ret = esp_timer_create(&timer_args, &g_autonomous_renewal_timer);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "❌ Échec création timer renouvellement autonome: %s", esp_err_to_name(ret));
            return ret;
        }
        
        // Démarrage du timer (toutes les 5 minutes par défaut)
        ret = esp_timer_start_periodic(g_autonomous_renewal_timer, 300000000); // 5 minutes en µs
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "❌ Échec démarrage timer renouvellement: %s", esp_err_to_name(ret));
            return ret;
        }
        
        ESP_LOGI(TAG, "✅ Renouvellement autonome activé (5 minutes)");
    }
    
    // Initialisation des compteurs
    g_attestation_initialized = true;
    g_sequence_counter = 0;
    g_continuous_attestations_performed = 0;
    g_autonomous_renewals_count = 0;
    g_attestation_success_rate = 1.0f;
    g_history_index = 0;
    g_history_full = false;
    
    // Réinitialisation de l'historique
    memset(g_attestation_history, 0, sizeof(g_attestation_history));
    
    ESP_LOGI(TAG, "🎉 Gestionnaire attestation Enterprise initialisé avec succès");
    ESP_LOGI(TAG, "   ✅ Attestation continue: %s", g_config_enterprise.continuous_enabled ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   ✅ Renouvellement autonome: %s", g_config_enterprise.autonomous_renewal_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   ✅ Analyse comportementale: %s", g_config_enterprise.behavioral_analysis_enabled ? "Activée" : "Désactivée");
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation du gestionnaire Enterprise
 */
esp_err_t attestation_manager_deinit_enterprise(void) {
    if (!g_attestation_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation gestionnaire attestation Enterprise");
    
    // Arrêt du timer de renouvellement
    if (g_autonomous_renewal_timer != NULL) {
        esp_timer_stop(g_autonomous_renewal_timer);
        esp_timer_delete(g_autonomous_renewal_timer);
        g_autonomous_renewal_timer = NULL;
    }
    
    // Dé-initialisation du vérifieur distant
    remote_verifier_deinit();
    
    // Suppression du mutex
    if (g_attestation_mutex != NULL) {
        vSemaphoreDelete(g_attestation_mutex);
        g_attestation_mutex = NULL;
    }
    
    g_attestation_initialized = false;
    
    ESP_LOGI(TAG, "✅ Gestionnaire attestation Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Ajout d'une attestation à l'historique pour analyse comportementale
 */
static void add_to_history(const attestation_result_t* result) {
    if (!g_config_enterprise.behavioral_analysis_enabled || !result) return;
    
    memcpy(&g_attestation_history[g_history_index], result, sizeof(attestation_result_t));
    g_history_index = (g_history_index + 1) % ATTESTATION_HISTORY_SIZE;
    
    if (g_history_index == 0) {
        g_history_full = true;
    }
}

/**
 * @brief Analyse comportementale des attestations
 */
static float analyze_attestation_behavior(void) {
    if (!g_config_enterprise.behavioral_analysis_enabled) return 1.0f;
    
    uint32_t total_entries = g_history_full ? ATTESTATION_HISTORY_SIZE : g_history_index;
    if (total_entries == 0) return 1.0f;
    
    uint32_t successful_attestations = 0;
    uint64_t total_response_time = 0;
    uint32_t anomaly_count = 0;
    
    for (uint32_t i = 0; i < total_entries; i++) {
        const attestation_result_t* entry = &g_attestation_history[i];
        
        if (entry->status == ATTESTATION_SUCCESS) {
            successful_attestations++;
        }
        
        total_response_time += entry->response_time_ms;
        
        // Détection d'anomalie si temps de réponse > 200ms
        if (entry->response_time_ms > 200) {
            anomaly_count++;
        }
    }
    
    float success_rate = (float)successful_attestations / total_entries;
    float avg_response_time = (float)total_response_time / total_entries;
    float anomaly_rate = (float)anomaly_count / total_entries;
    
    // Score comportemental composite
    float behavior_score = (success_rate * 0.6f) + 
                          ((avg_response_time < 100.0f ? 1.0f : 100.0f / avg_response_time) * 0.3f) +
                          ((1.0f - anomaly_rate) * 0.1f);
    
    ESP_LOGD(TAG, "📊 Analyse comportementale: succès=%.2f%%, temps=%.1fms, score=%.3f", 
             success_rate * 100, avg_response_time, behavior_score);
    
    return behavior_score;
}

/**
 * @brief Attestation continue Enterprise avec fonctionnalités avancées
 */
attestation_result_t attestation_perform_continuous_enterprise(void) {
    attestation_result_t result = {0};
    uint64_t start_time = esp_timer_get_time();
    
    if (!g_attestation_initialized) {
        result.status = ATTESTATION_ERROR_NOT_INITIALIZED;
        return result;
    }
    
    if (xSemaphoreTake(g_attestation_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex attestation");
        result.status = ATTESTATION_ERROR_TIMEOUT;
        return result;
    }
    
    ESP_LOGD(TAG, "🛡️ Exécution attestation continue Enterprise #%lu", g_sequence_counter);
    
    // Génération d'un challenge sécurisé avec HSM ESP32
    uint8_t challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE];
    esp32_crypto_result_t crypto_ret = esp32_crypto_generate_random(challenge, sizeof(challenge));
    if (crypto_ret != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Échec génération challenge crypto: %s", esp32_crypto_error_to_string(crypto_ret));
        result.status = ATTESTATION_ERROR_CRYPTO_FAILURE;
        xSemaphoreGive(g_attestation_mutex);
        return result;
    }
    
    // Ajout de métadonnées Enterprise au challenge
    uint32_t timestamp = (uint32_t)(esp_timer_get_time() / 1000);
    memcpy(&challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE - 8], &timestamp, 4);
    memcpy(&challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE - 4], &g_sequence_counter, 4);
    
    // Réponse au challenge avec vérification intégrité parallèle
    esp_err_t ret = attestation_respond_to_challenge_enterprise(challenge, sizeof(challenge), &result);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec réponse challenge attestation Enterprise");
        result.status = ATTESTATION_ERROR_SIGNATURE_FAILED;
        xSemaphoreGive(g_attestation_mutex);
        return result;
    }
    
    // Vérification d'intégrité en parallèle (Enterprise uniquement)
    integrity_status_t integrity_status = integrity_check_firmware_realtime();
    if (integrity_status != INTEGRITY_OK) {
        ESP_LOGW(TAG, "⚠️ Intégrité compromise pendant attestation Enterprise: %d", integrity_status);
        result.status = ATTESTATION_ERROR_INTEGRITY_FAILED;
        result.integrity_status = integrity_status;
        xSemaphoreGive(g_attestation_mutex);
        return result;
    }
    
    // Finalisation du résultat Enterprise
    result.sequence_number = ++g_sequence_counter;
    result.status = ATTESTATION_SUCCESS;
    result.is_valid = true;
    result.timestamp = timestamp;
    result.response_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    result.enterprise_features.continuous_mode = true;
    result.enterprise_features.hsm_accelerated = true;
    result.enterprise_features.integrity_verified = true;
    
    // Mise à jour des statistiques
    g_continuous_attestations_performed++;
    
    // Calcul du taux de succès
    if (g_continuous_attestations_performed > 0) {
        // Simplification: on assume que si on arrive ici, c'est un succès
        g_attestation_success_rate = ((g_attestation_success_rate * (g_continuous_attestations_performed - 1)) + 1.0f) / g_continuous_attestations_performed;
    }
    
    // Ajout à l'historique pour analyse comportementale
    add_to_history(&result);
    
    // Analyse comportementale
    if (g_config_enterprise.behavioral_analysis_enabled) {
        result.behavior_score = analyze_attestation_behavior();
    }
    
    xSemaphoreGive(g_attestation_mutex);
    
    ESP_LOGD(TAG, "✅ Attestation continue Enterprise réussie #%lu (temps: %lums, score: %.3f)", 
             g_sequence_counter, result.response_time_ms, result.behavior_score);
    
    return result;
}

/**
 * @brief Renouvellement autonome d'attestation (Innovation Enterprise)
 */
attestation_result_t attestation_autonomous_renewal(void) {
    ESP_LOGI(TAG, "🔄 Renouvellement autonome Enterprise initié");
    
    // Générer une nouvelle attestation
    attestation_result_t result = attestation_perform_continuous_enterprise();
    
    if (result.status == ATTESTATION_SUCCESS) {
        // Marquer comme renouvellement autonome
        result.enterprise_features.autonomous_renewal = true;
        
        // Envoyer au vérifieur distant si configuré
        if (g_config_enterprise.remote_verification_enabled) {
            esp_err_t send_ret = remote_verifier_send_attestation((uint8_t*)&result, sizeof(result));
            if (send_ret != ESP_OK) {
                ESP_LOGW(TAG, "⚠️ Échec envoi renouvellement distant: %s", esp_err_to_name(send_ret));
            }
        }
        
        ESP_LOGI(TAG, "✅ Renouvellement autonome Enterprise terminé avec succès");
    } else {
        ESP_LOGE(TAG, "❌ Échec renouvellement autonome Enterprise: %d", result.status);
    }
    
    return result;
}

/**
 * @brief Réponse au challenge avec fonctionnalités Enterprise
 */
esp_err_t attestation_respond_to_challenge_enterprise(const uint8_t* challenge, size_t challenge_size, attestation_result_t* result) {
    if (!challenge || !result || challenge_size != ATTESTATION_CHALLENGE_SIZE_ENTERPRISE) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGD(TAG, "🔐 Réponse au challenge attestation Enterprise");
    
    // Copie du challenge
    memcpy(result->challenge, challenge, ATTESTATION_CHALLENGE_SIZE_ENTERPRISE);
    
    // Génération de la réponse avec HSM ESP32 complet
    esp32_crypto_attestation_t crypto_attestation;
    esp32_crypto_result_t crypto_ret = esp32_crypto_perform_attestation_enterprise(challenge, challenge_size, &crypto_attestation);
    if (crypto_ret != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Échec attestation crypto ESP32 Enterprise: %s", esp32_crypto_error_to_string(crypto_ret));
        return ESP_FAIL;
    }
    
    // Construction de la réponse Enterprise avec données étendues
    size_t response_size = MIN(ATTESTATION_RESPONSE_SIZE_ENTERPRISE, sizeof(crypto_attestation.response));
    memcpy(result->response, crypto_attestation.response, response_size);
    
    size_t cert_size = MIN(ATTESTATION_CERT_SIZE_ENTERPRISE, sizeof(crypto_attestation.device_cert));
    memcpy(result->device_certificate, crypto_attestation.device_cert, cert_size);
    
    // Métadonnées Enterprise
    result->timestamp = crypto_attestation.timestamp;
    result->is_valid = crypto_attestation.is_valid;
    result->status = crypto_attestation.is_valid ? ATTESTATION_SUCCESS : ATTESTATION_ERROR_SIGNATURE_FAILED;
    result->enterprise_features.efuse_protected = crypto_attestation.efuse_protected;
    result->enterprise_features.trng_generated = crypto_attestation.trng_generated;
    result->enterprise_features.hardware_accelerated = crypto_attestation.hardware_accelerated;
    
    // Signature composite Enterprise (innovation)
    memcpy(result->composite_signature, crypto_attestation.composite_signature, 
           MIN(sizeof(result->composite_signature), sizeof(crypto_attestation.composite_signature)));
    
    ESP_LOGD(TAG, "✅ Réponse challenge Enterprise générée: %s (eFuse: %s, TRNG: %s, HW: %s)", 
             result->is_valid ? "Valide" : "Invalide",
             result->enterprise_features.efuse_protected ? "Oui" : "Non",
             result->enterprise_features.trng_generated ? "Oui" : "Non",
             result->enterprise_features.hardware_accelerated ? "Oui" : "Non");
    
    return ESP_OK;
}

/**
 * @brief Génération d'auto-attestation Enterprise avancée
 */
esp_err_t attestation_generate_self_attestation_enterprise(attestation_result_t* result) {
    if (!result) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGD(TAG, "🛡️ Génération auto-attestation Enterprise avancée");
    
    // Génération d'un challenge local sécurisé avec entropie ESP32
    uint8_t self_challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE];
    esp32_crypto_result_t crypto_ret = esp32_crypto_generate_random(self_challenge, sizeof(self_challenge));
    if (crypto_ret != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Échec génération challenge auto-attestation: %s", esp32_crypto_error_to_string(crypto_ret));
        return ESP_FAIL;
    }
    
    // Ajout de métadonnées système au challenge
    uint32_t timestamp = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t heap_free = esp_get_free_heap_size();
    uint32_t uptime = timestamp; // Simplification
    
    memcpy(&self_challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE - 12], &timestamp, 4);
    memcpy(&self_challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE - 8], &heap_free, 4);
    memcpy(&self_challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE - 4], &uptime, 4);
    
    // Traitement de l'auto-attestation
    esp_err_t ret = attestation_respond_to_challenge_enterprise(self_challenge, sizeof(self_challenge), result);
    if (ret == ESP_OK) {
        // Marquer comme auto-attestation
        result->enterprise_features.self_attestation = true;
        ESP_LOGI(TAG, "✅ Auto-attestation Enterprise générée avec succès");
    }
    
    return ret;
}

/**
 * @brief Obtention des statistiques d'attestation Enterprise
 */
attestation_stats_enterprise_t attestation_get_stats_enterprise(void) {
    attestation_stats_enterprise_t stats = {0};
    
    if (!g_attestation_initialized) {
        return stats;
    }
    
    if (xSemaphoreTake(g_attestation_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        stats.total_attestations = g_continuous_attestations_performed;
        stats.autonomous_renewals = g_autonomous_renewals_count;
        stats.success_rate = g_attestation_success_rate;
        stats.current_sequence = g_sequence_counter;
        stats.behavior_score = analyze_attestation_behavior();
        stats.uptime_seconds = (uint32_t)(esp_timer_get_time() / 1000000);
        
        // Statistiques avancées
        uint32_t total_entries = g_history_full ? ATTESTATION_HISTORY_SIZE : g_history_index;
        if (total_entries > 0) {
            uint64_t total_time = 0;
            uint32_t min_time = UINT32_MAX;
            uint32_t max_time = 0;
            
            for (uint32_t i = 0; i < total_entries; i++) {
                uint32_t time = g_attestation_history[i].response_time_ms;
                total_time += time;
                if (time < min_time) min_time = time;
                if (time > max_time) max_time = time;
            }
            
            stats.avg_response_time_ms = (uint32_t)(total_time / total_entries);
            stats.min_response_time_ms = min_time;
            stats.max_response_time_ms = max_time;
        }
        
        xSemaphoreGive(g_attestation_mutex);
    }
    
    return stats;
}

/**
 * @brief Configuration Enterprise du gestionnaire d'attestation
 */
esp_err_t attestation_configure_enterprise(const attestation_config_enterprise_t* config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "⚙️ Configuration attestation Enterprise mise à jour");
    
    if (xSemaphoreTake(g_attestation_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(&g_config_enterprise, config, sizeof(attestation_config_enterprise_t));
        
        // Reconfiguration du timer si nécessaire
        if (g_autonomous_renewal_timer != NULL && config->autonomous_renewal_enabled) {
            esp_timer_stop(g_autonomous_renewal_timer);
            
            uint64_t period_us = config->autonomous_renewal_interval_ms * 1000;
            esp_err_t ret = esp_timer_start_periodic(g_autonomous_renewal_timer, period_us);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "✅ Timer renouvellement reconfiguré: %lums", config->autonomous_renewal_interval_ms);
            }
        }
        
        xSemaphoreGive(g_attestation_mutex);
    }
    
    return ESP_OK;
}

/**
 * @brief Compatibilité avec version standard
 */
esp_err_t attestation_manager_init(void) {
    return attestation_manager_init_enterprise();
}

attestation_result_t attestation_perform_continuous(void) {
    return attestation_perform_continuous_enterprise();
}

esp_err_t attestation_respond_to_challenge(const uint8_t* challenge, size_t challenge_size, attestation_result_t* result) {
    // Adapter la taille du challenge si nécessaire
    if (challenge_size == ATTESTATION_CHALLENGE_SIZE) {
        // Étendre le challenge pour Enterprise
        uint8_t extended_challenge[ATTESTATION_CHALLENGE_SIZE_ENTERPRISE] = {0};
        memcpy(extended_challenge, challenge, ATTESTATION_CHALLENGE_SIZE);
        return attestation_respond_to_challenge_enterprise(extended_challenge, sizeof(extended_challenge), result);
    }
    return attestation_respond_to_challenge_enterprise(challenge, challenge_size, result);
}

esp_err_t attestation_generate_self_attestation(attestation_result_t* result) {
    return attestation_generate_self_attestation_enterprise(result);
}