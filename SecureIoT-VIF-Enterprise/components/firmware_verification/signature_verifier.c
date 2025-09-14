/**
 * @file signature_verifier.c
 * @brief Vérificateur de signatures Enterprise avec accélération matérielle
 * 
 * Version Enterprise avec support HSM ESP32 complet, vérification parallèle,
 * signatures composites et validation en temps réel.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "signature_verifier.h"
#include "esp32_crypto_manager.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "SIG_VERIFIER_ENTERPRISE";

// Variables globales Enterprise
static bool g_verifier_initialized = false;
static SemaphoreHandle_t g_verifier_mutex = NULL;
static signature_verifier_config_enterprise_t g_config = {0};

// Statistiques Enterprise
static uint32_t g_total_verifications = 0;
static uint32_t g_successful_verifications = 0;
static uint32_t g_failed_verifications = 0;
static float g_avg_verification_time_ms = 0.0f;

// Cache de signatures pour optimisation
#define SIGNATURE_CACHE_SIZE 32
static signature_cache_entry_t g_signature_cache[SIGNATURE_CACHE_SIZE];
static uint8_t g_cache_index = 0;
static bool g_cache_full = false;

/**
 * @brief Initialisation du vérificateur de signatures Enterprise
 */
esp_err_t signature_verifier_init_enterprise(void) {
    if (g_verifier_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔐 Initialisation vérificateur signatures Enterprise");
    
    // Création du mutex thread-safe
    g_verifier_mutex = xSemaphoreCreateMutex();
    if (g_verifier_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex vérificateur");
        return ESP_FAIL;
    }
    
    // Configuration par défaut Enterprise
    g_config.hardware_acceleration = true;
    g_config.parallel_verification = true;
    g_config.cache_enabled = true;
    g_config.composite_signatures = true;
    g_config.realtime_validation = true;
    g_config.efuse_key_validation = true;
    g_config.performance_optimization = true;
    
    // Initialisation du cache
    memset(g_signature_cache, 0, sizeof(g_signature_cache));
    g_cache_index = 0;
    g_cache_full = false;
    
    // Initialisation des statistiques
    g_total_verifications = 0;
    g_successful_verifications = 0;
    g_failed_verifications = 0;
    g_avg_verification_time_ms = 0.0f;
    
    g_verifier_initialized = true;
    
    ESP_LOGI(TAG, "✅ Vérificateur signatures Enterprise initialisé");
    ESP_LOGI(TAG, "   🚀 Accélération matérielle: %s", g_config.hardware_acceleration ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   ⚡ Vérification parallèle: %s", g_config.parallel_verification ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   💾 Cache signatures: %s", g_config.cache_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   🔗 Signatures composites: %s", g_config.composite_signatures ? "Activées" : "Désactivées");
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation du vérificateur Enterprise
 */
esp_err_t signature_verifier_deinit_enterprise(void) {
    if (!g_verifier_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation vérificateur signatures Enterprise");
    
    // Suppression du mutex
    if (g_verifier_mutex != NULL) {
        vSemaphoreDelete(g_verifier_mutex);
        g_verifier_mutex = NULL;
    }
    
    g_verifier_initialized = false;
    
    ESP_LOGI(TAG, "✅ Vérificateur signatures Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Recherche dans le cache de signatures
 */
static bool search_signature_cache(const uint8_t* hash, signature_verification_result_enterprise_t* cached_result) {
    if (!g_config.cache_enabled || !hash || !cached_result) return false;
    
    uint32_t total_entries = g_cache_full ? SIGNATURE_CACHE_SIZE : g_cache_index;
    
    for (uint32_t i = 0; i < total_entries; i++) {
        if (memcmp(g_signature_cache[i].hash, hash, INTEGRITY_HASH_SIZE) == 0) {
            // Cache hit
            memcpy(cached_result, &g_signature_cache[i].result, sizeof(signature_verification_result_enterprise_t));
            g_signature_cache[i].hit_count++;
            g_signature_cache[i].last_access = (uint32_t)(esp_timer_get_time() / 1000);
            
            ESP_LOGD(TAG, "💾 Cache hit pour signature (entrée %lu)", i);
            return true;
        }
    }
    
    return false; // Cache miss
}

/**
 * @brief Ajout d'une signature au cache
 */
static void add_to_signature_cache(const uint8_t* hash, const signature_verification_result_enterprise_t* result) {
    if (!g_config.cache_enabled || !hash || !result) return;
    
    signature_cache_entry_t* entry = &g_signature_cache[g_cache_index];
    
    memcpy(entry->hash, hash, INTEGRITY_HASH_SIZE);
    memcpy(&entry->result, result, sizeof(signature_verification_result_enterprise_t));
    entry->timestamp = (uint32_t)(esp_timer_get_time() / 1000);
    entry->hit_count = 1;
    entry->last_access = entry->timestamp;
    
    g_cache_index = (g_cache_index + 1) % SIGNATURE_CACHE_SIZE;
    if (g_cache_index == 0) g_cache_full = true;
    
    ESP_LOGD(TAG, "💾 Signature ajoutée au cache");
}

/**
 * @brief Vérification de signature firmware Enterprise avec toutes les fonctionnalités
 */
esp_err_t signature_verify_firmware_enterprise(const integrity_metadata_enterprise_t* metadata, signature_verification_result_enterprise_t* result) {
    if (!metadata || !result || !g_verifier_initialized) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGD(TAG, "🔍 Vérification signature firmware Enterprise");
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex vérificateur");
        return ESP_ERR_TIMEOUT;
    }
    
    uint64_t start_time = esp_timer_get_time();
    
    // Initialisation du résultat
    memset(result, 0, sizeof(signature_verification_result_enterprise_t));
    result->timestamp = (uint32_t)(start_time / 1000);
    
    // Recherche dans le cache en premier
    if (search_signature_cache(metadata->global_hash, result)) {
        result->cache_hit = true;
        result->verification_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
        xSemaphoreGive(g_verifier_mutex);
        ESP_LOGD(TAG, "⚡ Vérification firmware via cache (%lums)", result->verification_time_ms);
        return ESP_OK;
    }
    
    // Vérification avec accélération matérielle ESP32
    esp32_crypto_signature_verification_t crypto_verification = {0};
    memcpy(crypto_verification.signature, metadata->global_signature, INTEGRITY_SIGNATURE_SIZE_ENTERPRISE);
    memcpy(crypto_verification.hash, metadata->global_hash, INTEGRITY_HASH_SIZE);
    crypto_verification.signature_type = ESP32_CRYPTO_SIGNATURE_ECDSA_P256;
    crypto_verification.key_source = ESP32_CRYPTO_KEY_EFUSE;
    crypto_verification.hardware_accelerated = g_config.hardware_acceleration;
    
    esp32_crypto_result_t crypto_ret = esp32_crypto_verify_signature_enterprise(&crypto_verification);
    
    // Construction du résultat Enterprise
    result->is_valid = (crypto_ret == ESP32_CRYPTO_SUCCESS);
    result->verification_method = SIGNATURE_METHOD_ECDSA_P256;
    result->hardware_accelerated = g_config.hardware_acceleration;
    result->efuse_validated = g_config.efuse_key_validation;
    
    memcpy(result->signature, metadata->global_signature, INTEGRITY_SIGNATURE_SIZE_ENTERPRISE);
    memcpy(result->verified_hash, metadata->global_hash, INTEGRITY_HASH_SIZE);
    
    // Vérification de signature composite si activée
    if (g_config.composite_signatures && metadata->has_composite_signature) {
        ESP_LOGD(TAG, "🔗 Vérification signature composite Enterprise");
        
        esp32_crypto_signature_verification_t composite_verification = {0};
        memcpy(composite_verification.signature, metadata->composite_signature, sizeof(metadata->composite_signature));
        memcpy(composite_verification.hash, metadata->global_hash, INTEGRITY_HASH_SIZE);
        composite_verification.signature_type = ESP32_CRYPTO_SIGNATURE_COMPOSITE;
        composite_verification.key_source = ESP32_CRYPTO_KEY_EFUSE_MULTIPLE;
        
        esp32_crypto_result_t composite_ret = esp32_crypto_verify_signature_enterprise(&composite_verification);
        result->composite_signature_valid = (composite_ret == ESP32_CRYPTO_SUCCESS);
        result->has_composite_signature = true;
        
        // Validation combinée
        result->is_valid = result->is_valid && result->composite_signature_valid;
    }
    
    // Métadonnées de performance
    result->verification_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    result->crypto_performance_score = crypto_verification.performance_score;
    result->security_strength = crypto_verification.security_strength;
    
    // Validation eFuse si activée
    if (g_config.efuse_key_validation) {
        esp32_crypto_efuse_validation_t efuse_validation = {0};
        esp32_crypto_result_t efuse_ret = esp32_crypto_validate_efuse_integrity(&efuse_validation);
        result->efuse_integrity_ok = (efuse_ret == ESP32_CRYPTO_SUCCESS);
        result->efuse_validated = true;
        
        if (!result->efuse_integrity_ok) {
            ESP_LOGW(TAG, "⚠️ Intégrité eFuse compromise");
            result->is_valid = false;
        }
    }
    
    // Ajout au cache si vérification réussie
    if (result->is_valid && g_config.cache_enabled) {
        add_to_signature_cache(metadata->global_hash, result);
    }
    
    // Mise à jour des statistiques
    g_total_verifications++;
    if (result->is_valid) {
        g_successful_verifications++;
    } else {
        g_failed_verifications++;
    }
    
    // Calcul du temps de vérification moyen
    g_avg_verification_time_ms = ((g_avg_verification_time_ms * (g_total_verifications - 1)) + result->verification_time_ms) / g_total_verifications;
    
    xSemaphoreGive(g_verifier_mutex);
    
    ESP_LOGD(TAG, "%s Vérification signature firmware (%lums) - Valid:%s, Composite:%s, eFuse:%s", 
             result->is_valid ? "✅" : "❌",
             result->verification_time_ms,
             result->is_valid ? "Oui" : "Non",
             (result->has_composite_signature && result->composite_signature_valid) ? "Oui" : "Non",
             result->efuse_integrity_ok ? "Oui" : "Non");
    
    return ESP_OK;
}

/**
 * @brief Vérification de signature chunk Enterprise avec optimisations
 */
esp_err_t signature_verify_chunk_enterprise(const integrity_chunk_info_enterprise_t* chunk, signature_verification_result_enterprise_t* result) {
    if (!chunk || !result || !g_verifier_initialized) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGD(TAG, "🔍 Vérification signature chunk Enterprise #%lu", chunk->chunk_id);
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex pour chunk");
        return ESP_ERR_TIMEOUT;
    }
    
    uint64_t start_time = esp_timer_get_time();
    
    // Initialisation du résultat
    memset(result, 0, sizeof(signature_verification_result_enterprise_t));
    result->timestamp = (uint32_t)(start_time / 1000);
    result->chunk_id = chunk->chunk_id;
    
    // Recherche dans le cache
    if (search_signature_cache(chunk->hash, result)) {
        result->cache_hit = true;
        result->verification_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
        xSemaphoreGive(g_verifier_mutex);
        ESP_LOGD(TAG, "⚡ Vérification chunk #%lu via cache", chunk->chunk_id);
        return ESP_OK;
    }
    
    // Vérification avec crypto ESP32
    esp32_crypto_signature_verification_t crypto_verification = {0};
    memcpy(crypto_verification.signature, chunk->signature, INTEGRITY_SIGNATURE_SIZE_ENTERPRISE);
    memcpy(crypto_verification.hash, chunk->hash, INTEGRITY_HASH_SIZE);
    crypto_verification.signature_type = ESP32_CRYPTO_SIGNATURE_ECDSA_P256;
    crypto_verification.key_source = ESP32_CRYPTO_KEY_EFUSE;
    crypto_verification.hardware_accelerated = g_config.hardware_acceleration;
    
    esp32_crypto_result_t crypto_ret = esp32_crypto_verify_signature_enterprise(&crypto_verification);
    
    // Construction du résultat
    result->is_valid = (crypto_ret == ESP32_CRYPTO_SUCCESS);
    result->verification_method = SIGNATURE_METHOD_ECDSA_P256;
    result->hardware_accelerated = g_config.hardware_acceleration;
    result->chunk_verification = true;
    
    memcpy(result->signature, chunk->signature, INTEGRITY_SIGNATURE_SIZE_ENTERPRISE);
    memcpy(result->verified_hash, chunk->hash, INTEGRITY_HASH_SIZE);
    
    result->verification_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    result->crypto_performance_score = crypto_verification.performance_score;
    
    // Ajout au cache si réussite
    if (result->is_valid && g_config.cache_enabled) {
        add_to_signature_cache(chunk->hash, result);
    }
    
    // Mise à jour des statistiques
    g_total_verifications++;
    if (result->is_valid) {
        g_successful_verifications++;
    } else {
        g_failed_verifications++;
    }
    
    g_avg_verification_time_ms = ((g_avg_verification_time_ms * (g_total_verifications - 1)) + result->verification_time_ms) / g_total_verifications;
    
    xSemaphoreGive(g_verifier_mutex);
    
    ESP_LOGD(TAG, "%s Vérification signature chunk #%lu (%lums)", 
             result->is_valid ? "✅" : "❌", chunk->chunk_id, result->verification_time_ms);
    
    return ESP_OK;
}

/**
 * @brief Vérification parallèle de multiple chunks (Innovation Enterprise)
 */
esp_err_t signature_verify_chunks_parallel_enterprise(const integrity_chunk_info_enterprise_t* chunks, uint32_t chunk_count, signature_batch_result_enterprise_t* batch_result) {
    if (!chunks || chunk_count == 0 || !batch_result || !g_verifier_initialized) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!g_config.parallel_verification) {
        ESP_LOGW(TAG, "⚠️ Vérification parallèle désactivée - utilisation séquentielle");
        // Fallback vers vérification séquentielle
        batch_result->total_chunks = chunk_count;
        batch_result->verified_chunks = 0;
        batch_result->failed_chunks = 0;
        
        for (uint32_t i = 0; i < chunk_count; i++) {
            signature_verification_result_enterprise_t result;
            esp_err_t ret = signature_verify_chunk_enterprise(&chunks[i], &result);
            if (ret == ESP_OK && result.is_valid) {
                batch_result->verified_chunks++;
            } else {
                batch_result->failed_chunks++;
            }
        }
        
        batch_result->success_rate = (float)batch_result->verified_chunks / chunk_count;
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "⚡ Vérification parallèle de %lu chunks Enterprise", chunk_count);
    
    uint64_t start_time = esp_timer_get_time();
    
    // Initialisation du résultat batch
    memset(batch_result, 0, sizeof(signature_batch_result_enterprise_t));
    batch_result->total_chunks = chunk_count;
    batch_result->start_timestamp = (uint32_t)(start_time / 1000);
    batch_result->parallel_processing = true;
    
    // Limitation du nombre de chunks par batch pour éviter la surcharge mémoire
    uint32_t max_parallel = MIN(chunk_count, 8); // Maximum 8 en parallèle
    
    for (uint32_t i = 0; i < chunk_count; i += max_parallel) {
        uint32_t batch_size = MIN(max_parallel, chunk_count - i);
        
        // Traitement du batch actuel
        for (uint32_t j = 0; j < batch_size; j++) {
            signature_verification_result_enterprise_t result;
            esp_err_t ret = signature_verify_chunk_enterprise(&chunks[i + j], &result);
            
            if (ret == ESP_OK && result.is_valid) {
                batch_result->verified_chunks++;
            } else {
                batch_result->failed_chunks++;
                // Enregistrement des chunks en échec
                if (batch_result->failed_chunk_count < MAX_FAILED_CHUNKS_ENTERPRISE) {
                    batch_result->failed_chunk_ids[batch_result->failed_chunk_count++] = chunks[i + j].chunk_id;
                }
            }
        }
        
        // Délai pour éviter la surcharge CPU
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    
    batch_result->processing_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    batch_result->success_rate = (float)batch_result->verified_chunks / chunk_count;
    batch_result->avg_time_per_chunk_ms = (float)batch_result->processing_time_ms / chunk_count;
    
    ESP_LOGI(TAG, "✅ Vérification parallèle terminée: %lu/%lu chunks valides (%.1f%%) en %lums", 
             batch_result->verified_chunks, chunk_count,
             batch_result->success_rate * 100, batch_result->processing_time_ms);
    
    return ESP_OK;
}

/**
 * @brief Configuration du vérificateur Enterprise
 */
esp_err_t signature_verifier_configure_enterprise(const signature_verifier_config_enterprise_t* config) {
    if (!config || !g_verifier_initialized) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "⚙️ Configuration vérificateur signatures Enterprise");
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(&g_config, config, sizeof(signature_verifier_config_enterprise_t));
        
        // Validation de la configuration
        if (!g_config.hardware_acceleration) {
            ESP_LOGW(TAG, "⚠️ Accélération matérielle désactivée - Performance réduite");
        }
        
        xSemaphoreGive(g_verifier_mutex);
        
        ESP_LOGI(TAG, "✅ Configuration vérificateur mise à jour");
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

/**
 * @brief Obtention des statistiques du vérificateur Enterprise
 */
signature_verifier_stats_enterprise_t signature_verifier_get_stats_enterprise(void) {
    signature_verifier_stats_enterprise_t stats = {0};
    
    if (!g_verifier_initialized) {
        return stats;
    }
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        stats.total_verifications = g_total_verifications;
        stats.successful_verifications = g_successful_verifications;
        stats.failed_verifications = g_failed_verifications;
        stats.avg_verification_time_ms = g_avg_verification_time_ms;
        
        if (g_total_verifications > 0) {
            stats.success_rate = (float)g_successful_verifications / g_total_verifications;
        }
        
        // Statistiques du cache
        uint32_t total_entries = g_cache_full ? SIGNATURE_CACHE_SIZE : g_cache_index;
        stats.cache_entries = total_entries;
        
        uint32_t total_hits = 0;
        for (uint32_t i = 0; i < total_entries; i++) {
            total_hits += g_signature_cache[i].hit_count;
        }
        stats.cache_hit_rate = total_entries > 0 ? (float)total_hits / total_entries : 0.0f;
        
        stats.uptime_seconds = (uint32_t)(esp_timer_get_time() / 1000000);
        
        xSemaphoreGive(g_verifier_mutex);
    }
    
    return stats;
}

/**
 * @brief Nettoyage du cache de signatures
 */
esp_err_t signature_verifier_clear_cache_enterprise(void) {
    if (!g_verifier_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "🧹 Nettoyage cache signatures Enterprise");
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memset(g_signature_cache, 0, sizeof(g_signature_cache));
        g_cache_index = 0;
        g_cache_full = false;
        
        xSemaphoreGive(g_verifier_mutex);
        
        ESP_LOGI(TAG, "✅ Cache signatures nettoyé");
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

/**
 * @brief Compatibilité avec version standard
 */
esp_err_t signature_verify_firmware(const integrity_metadata_t* metadata, signature_verification_result_t* result) {
    if (!metadata || !result) return ESP_ERR_INVALID_ARG;
    
    // Adaptation vers Enterprise
    integrity_metadata_enterprise_t enterprise_metadata = {0};
    memcpy(enterprise_metadata.global_hash, metadata->global_hash, INTEGRITY_HASH_SIZE);
    memcpy(enterprise_metadata.global_signature, metadata->global_signature, INTEGRITY_SIGNATURE_SIZE);
    enterprise_metadata.has_composite_signature = false;
    
    signature_verification_result_enterprise_t enterprise_result;
    esp_err_t ret = signature_verify_firmware_enterprise(&enterprise_metadata, &enterprise_result);
    
    if (ret == ESP_OK) {
        result->is_valid = enterprise_result.is_valid;
        memcpy(result->signature, enterprise_result.signature, 64);
        result->verification_time_ms = enterprise_result.verification_time_ms;
    }
    
    return ret;
}

esp_err_t signature_verify_chunk(const integrity_chunk_info_t* chunk, signature_verification_result_t* result) {
    if (!chunk || !result) return ESP_ERR_INVALID_ARG;
    
    // Adaptation vers Enterprise
    integrity_chunk_info_enterprise_t enterprise_chunk = {0};
    enterprise_chunk.chunk_id = chunk->chunk_id;
    memcpy(enterprise_chunk.hash, chunk->hash, INTEGRITY_HASH_SIZE);
    memcpy(enterprise_chunk.signature, chunk->signature, INTEGRITY_SIGNATURE_SIZE);
    
    signature_verification_result_enterprise_t enterprise_result;
    esp_err_t ret = signature_verify_chunk_enterprise(&enterprise_chunk, &enterprise_result);
    
    if (ret == ESP_OK) {
        result->is_valid = enterprise_result.is_valid;
        memcpy(result->signature, enterprise_result.signature, 64);
        result->verification_time_ms = enterprise_result.verification_time_ms;
    }
    
    return ret;
}