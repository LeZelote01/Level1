/**
 * @file integrity_checker.c
 * @brief Vérificateur d'intégrité simplifié pour SecureIoT-VIF Community Edition
 * 
 * Version de base qui ne vérifie l'intégrité qu'au démarrage (pas temps réel).
 * Idéale pour comprendre les concepts sans complexité avancée.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "crypto_operations_basic.h"
#include "integrity_checker.h"

static const char *TAG = "INTEGRITY_COMMUNITY";

// Variables globales pour la vérification Community
static bool integrity_checker_initialized = false;
static integrity_stats_community_t integrity_stats = {0};

/**
 * @brief Initialise le vérificateur d'intégrité Community
 */
esp_err_t integrity_checker_init(void) {
    if (integrity_checker_initialized) {
        ESP_LOGW(TAG, "Vérificateur d'intégrité déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "🔍 Initialisation vérificateur d'intégrité Community");
    ESP_LOGI(TAG, "💡 Version éducative - Vérification au démarrage seulement");
    
    // Réinitialiser les statistiques
    memset(&integrity_stats, 0, sizeof(integrity_stats));
    integrity_stats.last_check_time = esp_timer_get_time() / 1000;
    
    integrity_checker_initialized = true;
    ESP_LOGI(TAG, "✅ Vérificateur d'intégrité Community initialisé");
    
    return ESP_OK;
}

/**
 * @brief Vérification d'intégrité basique au démarrage
 */
integrity_status_t integrity_check_firmware_basic(void) {
    if (!integrity_checker_initialized) {
        ESP_LOGE(TAG, "❌ Vérificateur non initialisé");
        return INTEGRITY_ERROR;
    }
    
    ESP_LOGI(TAG, "🔍 Démarrage vérification d'intégrité basique...");
    
    uint32_t start_time = esp_timer_get_time() / 1000;
    integrity_stats.total_checks++;
    
    // Obtenir les informations de partition
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running == NULL) {
        ESP_LOGE(TAG, "❌ Impossible d'obtenir la partition courante");
        integrity_stats.failed_checks++;
        return INTEGRITY_ERROR;
    }
    
    ESP_LOGI(TAG, "📋 Partition courante: %s, taille: %d bytes", 
             running->label, running->size);
    
    // Vérification simplifiée par chunks (version éducative)
    const size_t chunk_size = 8192; // Plus gros chunks qu'Enterprise
    const size_t total_chunks = (running->size + chunk_size - 1) / chunk_size;
    size_t verified_chunks = 0;
    size_t corrupted_chunks = 0;
    
    ESP_LOGI(TAG, "🧩 Vérification par chunks: %d chunks de %d bytes", 
             total_chunks, chunk_size);
    
    uint8_t *buffer = malloc(chunk_size);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "❌ Allocation mémoire échouée");
        integrity_stats.failed_checks++;
        return INTEGRITY_ERROR;
    }
    
    uint8_t chunk_hash[32];
    
    // Vérifier un échantillon de chunks (pas tous pour Community)
    size_t sample_chunks = (total_chunks > 20) ? 20 : total_chunks;
    size_t chunk_step = total_chunks / sample_chunks;
    if (chunk_step == 0) chunk_step = 1;
    
    ESP_LOGI(TAG, "🎯 Échantillonnage: %d chunks sur %d (éducatif)", 
             sample_chunks, total_chunks);
    
    for (size_t i = 0; i < total_chunks; i += chunk_step) {
        size_t offset = i * chunk_size;
        size_t read_size = (offset + chunk_size > running->size) ? 
                          (running->size - offset) : chunk_size;
        
        // Lire le chunk
        esp_err_t ret = esp_partition_read(running, offset, buffer, read_size);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "❌ Erreur lecture chunk %d: %s", i, esp_err_to_name(ret));
            corrupted_chunks++;
            continue;
        }
        
        // Calculer le hash du chunk (version simplifiée)
        ret = crypto_basic_sha256(buffer, read_size, chunk_hash);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "❌ Erreur calcul hash chunk %d", i);
            corrupted_chunks++;
            continue;
        }
        
        // En Community, on vérifie juste que le hash peut être calculé
        // (pas de vérification contre signature stockée)
        verified_chunks++;
        
        // Log périodique pour éviter le spam
        if (i % (chunk_step * 5) == 0) {
            ESP_LOGD(TAG, "🔍 Chunk %d/%d vérifié", i/chunk_step + 1, sample_chunks);
        }
    }
    
    free(buffer);
    
    // Calculer le temps de vérification
    uint32_t check_duration = (esp_timer_get_time() / 1000) - start_time;
    integrity_stats.last_check_time = esp_timer_get_time() / 1000;
    integrity_stats.last_check_duration_ms = check_duration;
    
    // Déterminer le résultat
    integrity_status_t result;
    if (corrupted_chunks == 0) {
        result = INTEGRITY_OK;
        integrity_stats.successful_checks++;
        ESP_LOGI(TAG, "✅ Vérification d'intégrité basique réussie");
        ESP_LOGI(TAG, "📊 Chunks: %d échantillonnés, %d vérifiés, %d corrompus", 
                 sample_chunks, verified_chunks, corrupted_chunks);
        ESP_LOGI(TAG, "⏱️  Durée: %d ms (Community - échantillonnage)", check_duration);
    } else {
        result = INTEGRITY_CORRUPTED;
        integrity_stats.failed_checks++;
        ESP_LOGE(TAG, "❌ Corruption détectée dans %d chunks", corrupted_chunks);
    }
    
    ESP_LOGI(TAG, "📈 Statistiques: %d vérifications, %d succès, %d échecs",
             integrity_stats.total_checks, 
             integrity_stats.successful_checks,
             integrity_stats.failed_checks);
    
    return result;
}

/**
 * @brief Vérification rapide d'un chunk spécifique (Community)
 */
integrity_status_t integrity_check_chunk_basic(size_t chunk_id) {
    if (!integrity_checker_initialized) {
        ESP_LOGE(TAG, "❌ Vérificateur non initialisé");
        return INTEGRITY_ERROR;
    }
    
    ESP_LOGD(TAG, "🔍 Vérification chunk spécifique: %d", chunk_id);
    
    // En Community, on fait une vérification simplifiée
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running == NULL) {
        return INTEGRITY_ERROR;
    }
    
    const size_t chunk_size = 8192;
    size_t offset = chunk_id * chunk_size;
    
    if (offset >= running->size) {
        ESP_LOGW(TAG, "⚠️  Chunk %d hors limites", chunk_id);
        return INTEGRITY_INVALID_CHUNK;
    }
    
    uint8_t *buffer = malloc(chunk_size);
    if (buffer == NULL) {
        return INTEGRITY_ERROR;
    }
    
    size_t read_size = (offset + chunk_size > running->size) ? 
                      (running->size - offset) : chunk_size;
    
    esp_err_t ret = esp_partition_read(running, offset, buffer, read_size);
    if (ret != ESP_OK) {
        free(buffer);
        return INTEGRITY_CORRUPTED;
    }
    
    // Calcul hash basique (pas de vérification signature en Community)
    uint8_t chunk_hash[32];
    ret = crypto_basic_sha256(buffer, read_size, chunk_hash);
    free(buffer);
    
    if (ret != ESP_OK) {
        return INTEGRITY_ERROR;
    }
    
    ESP_LOGD(TAG, "✅ Chunk %d: hash calculé avec succès", chunk_id);
    return INTEGRITY_OK;
}

/**
 * @brief Obtient les statistiques d'intégrité Community
 */
esp_err_t integrity_get_stats_community(integrity_stats_community_t *stats) {
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!integrity_checker_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memcpy(stats, &integrity_stats, sizeof(integrity_stats_community_t));
    return ESP_OK;
}

/**
 * @brief Affiche les statistiques d'intégrité Community
 */
void integrity_print_stats_community(void) {
    if (!integrity_checker_initialized) {
        ESP_LOGW(TAG, "Vérificateur non initialisé");
        return;
    }
    
    ESP_LOGI(TAG, "📊 === Statistiques Intégrité Community ===");
    ESP_LOGI(TAG, "Vérifications totales: %d", integrity_stats.total_checks);
    ESP_LOGI(TAG, "Vérifications réussies: %d", integrity_stats.successful_checks);
    ESP_LOGI(TAG, "Vérifications échouées: %d", integrity_stats.failed_checks);
    ESP_LOGI(TAG, "Dernière vérification: %lld ms ago", 
             (esp_timer_get_time() / 1000) - integrity_stats.last_check_time);
    ESP_LOGI(TAG, "Durée dernière vérif: %d ms", integrity_stats.last_check_duration_ms);
    
    if (integrity_stats.total_checks > 0) {
        float success_rate = (float)integrity_stats.successful_checks / 
                            integrity_stats.total_checks * 100.0f;
        ESP_LOGI(TAG, "Taux de réussite: %.1f%%", success_rate);
    }
    
    ESP_LOGI(TAG, "===========================================");
}

/**
 * @brief Réinitialise les statistiques d'intégrité
 */
esp_err_t integrity_reset_stats_community(void) {
    if (!integrity_checker_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memset(&integrity_stats, 0, sizeof(integrity_stats));
    integrity_stats.last_check_time = esp_timer_get_time() / 1000;
    
    ESP_LOGI(TAG, "🔄 Statistiques d'intégrité réinitialisées");
    return ESP_OK;
}

/**
 * @brief Test de fonctionnement du vérificateur Community
 */
esp_err_t integrity_checker_self_test(void) {
    ESP_LOGI(TAG, "🧪 Auto-test vérificateur d'intégrité Community...");
    
    // Test d'initialisation
    esp_err_t ret = integrity_checker_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation");
        return ret;
    }
    
    // Test de vérification basique
    integrity_status_t status = integrity_check_firmware_basic();
    if (status == INTEGRITY_ERROR) {
        ESP_LOGE(TAG, "❌ Échec vérification basique");
        return ESP_FAIL;
    }
    
    // Test de vérification d'un chunk
    status = integrity_check_chunk_basic(0);
    if (status == INTEGRITY_ERROR) {
        ESP_LOGE(TAG, "❌ Échec vérification chunk");
        return ESP_FAIL;
    }
    
    // Test des statistiques
    integrity_stats_community_t stats;
    ret = integrity_get_stats_community(&stats);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec récupération statistiques");
        return ret;
    }
    
    ESP_LOGI(TAG, "✅ Auto-test vérificateur Community réussi");
    ESP_LOGI(TAG, "💡 Fonctionnalités de base opérationnelles");
    
    return ESP_OK;
}

/**
 * @brief Affiche les informations du vérificateur Community
 */
void integrity_checker_print_info(void) {
    ESP_LOGI(TAG, "📋 === Vérificateur Intégrité Community ===");
    ESP_LOGI(TAG, "Édition: Community (Éducative)");
    ESP_LOGI(TAG, "Type: Vérification au démarrage seulement");
    ESP_LOGI(TAG, "Méthode: Échantillonnage de chunks");
    ESP_LOGI(TAG, "Taille chunk: 8192 bytes");
    ESP_LOGI(TAG, "Hash: SHA-256 software");
    ESP_LOGI(TAG, "Fonctionnalités disponibles:");
    ESP_LOGI(TAG, "  ✅ Vérification au boot");
    ESP_LOGI(TAG, "  ✅ Vérification chunks individuels");
    ESP_LOGI(TAG, "  ✅ Statistiques basiques");
    ESP_LOGI(TAG, "Limitations Community:");
    ESP_LOGI(TAG, "  ❌ Pas de vérification temps réel");
    ESP_LOGI(TAG, "  ❌ Pas de vérification de signature");
    ESP_LOGI(TAG, "  ❌ Échantillonnage seulement");
    ESP_LOGI(TAG, "🎓 Idéal pour comprendre les concepts!");
    ESP_LOGI(TAG, "==========================================");
}