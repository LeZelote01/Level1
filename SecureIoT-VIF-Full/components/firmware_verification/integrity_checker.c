/**
 * @file integrity_checker.c
 * @brief Implémentation du vérificateur d'intégrité du firmware
 * 
 * Ce module implémente la vérification d'intégrité continue du firmware,
 * une fonctionnalité unique permettant la détection en temps réel des
 * modifications non autorisées du firmware.
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#include "integrity_checker.h"
#include "signature_verifier.h"
#include "se_manager.h"
#include "crypto_operations.h"

#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_flash.h"
#include "esp_app_format.h"
#include "esp_ota_ops.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "INTEGRITY_CHECKER";

// ================================
// Variables globales et état
// ================================

static bool g_integrity_initialized = false;
static integrity_config_t g_config;
static integrity_metadata_t g_metadata;
static integrity_chunk_info_t g_chunks[INTEGRITY_MAX_CHUNKS];
static integrity_stats_t g_stats;
static SemaphoreHandle_t g_integrity_mutex = NULL;
static TaskHandle_t g_runtime_check_task = NULL;
static TimerHandle_t g_incremental_timer = NULL;
static integrity_event_callback_t g_event_callback = NULL;
static void* g_callback_user_data = NULL;

// Constantes pour les métadonnées
#define INTEGRITY_MAGIC             (0x53454349) // "SECI" - Secure Integrity
#define INTEGRITY_METADATA_VERSION  (1)
#define INTEGRITY_NVS_NAMESPACE     "integrity"
#define INTEGRITY_NVS_KEY_METADATA  "metadata"
#define INTEGRITY_NVS_KEY_CHUNKS    "chunks"

// ================================
// Fonctions utilitaires internes
// ================================

/**
 * @brief Calcule le checksum d'une structure de métadonnées
 */
static uint32_t calculate_metadata_checksum(const integrity_metadata_t* metadata) {
    uint32_t checksum = 0;
    const uint8_t* data = (const uint8_t*)metadata;
    size_t size = sizeof(integrity_metadata_t) - sizeof(uint32_t); // Exclure le checksum lui-même
    
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) ^ data[i];
    }
    
    return checksum;
}

/**
 * @brief Trigger d'événement d'intégrité
 */
static void trigger_integrity_event(integrity_status_t status, uint32_t chunk_id) {
    if (g_event_callback != NULL) {
        g_event_callback(status, chunk_id, g_callback_user_data);
    }
    
    // Log de l'événement
    switch (status) {
        case INTEGRITY_OK:
            ESP_LOGD(TAG, "Intégrité OK pour chunk %lu", chunk_id);
            break;
        case INTEGRITY_ERROR_CORRUPTED:
            ESP_LOGE(TAG, "CORRUPTION détectée chunk %lu", chunk_id);
            break;
        case INTEGRITY_ERROR_SIGNATURE:
            ESP_LOGE(TAG, "Signature invalide chunk %lu", chunk_id);
            break;
        default:
            ESP_LOGW(TAG, "Événement intégrité: %s chunk %lu", 
                     integrity_status_to_string(status), chunk_id);
            break;
    }
}

/**
 * @brief Lit des données depuis la flash de manière sécurisée
 */
static esp_err_t secure_flash_read(uint32_t address, void* buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    esp_err_t ret = esp_flash_read(esp_flash_default_chip, buffer, address, size);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Erreur lecture flash addr=0x%08lx size=%zu: %s", 
                 address, size, esp_err_to_name(ret));
    }
    
    return ret;
}

/**
 * @brief Calcule le hash d'un chunk de firmware
 */
static integrity_status_t calculate_chunk_hash(const integrity_chunk_info_t* chunk, uint8_t* hash) {
    if (chunk == NULL || hash == NULL) {
        return INTEGRITY_ERROR_MEMORY;
    }
    
    uint8_t* chunk_data = malloc(chunk->size);
    if (chunk_data == NULL) {
        ESP_LOGE(TAG, "Échec allocation mémoire pour chunk %lu", chunk->chunk_id);
        return INTEGRITY_ERROR_MEMORY;
    }
    
    esp_err_t ret = secure_flash_read(chunk->start_address, chunk_data, chunk->size);
    if (ret != ESP_OK) {
        free(chunk_data);
        return INTEGRITY_ERROR_FLASH_READ;
    }
    
    size_t hash_len = INTEGRITY_HASH_SIZE;
    crypto_result_t crypto_ret = crypto_hash_compute(CRYPTO_HASH_SHA256, 
                                                     chunk_data, chunk->size, 
                                                     hash, &hash_len);
    
    free(chunk_data);
    
    if (crypto_ret != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec calcul hash chunk %lu: %s", 
                 chunk->chunk_id, crypto_result_to_string(crypto_ret));
        return INTEGRITY_ERROR_MEMORY;
    }
    
    return INTEGRITY_OK;
}

/**
 * @brief Tâche de vérification d'intégrité en temps réel
 */
static void runtime_check_task(void* pvParameters) {
    ESP_LOGI(TAG, "Démarrage tâche vérification intégrité en temps réel");
    
    TickType_t xLastWakeTime = xTaskGetTickCount();
    uint32_t check_cycle = 0;
    
    while (1) {
        if (xSemaphoreTake(g_integrity_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            uint64_t start_time = esp_timer_get_time();
            
            // Vérification incrémentale
            integrity_status_t status = integrity_incremental_check();
            
            uint64_t check_time = esp_timer_get_time() - start_time;
            uint32_t check_time_ms = (uint32_t)(check_time / 1000);
            
            // Mise à jour des statistiques
            g_stats.total_checks++;
            g_stats.total_check_time_us += check_time;
            g_stats.avg_check_time_ms = (uint32_t)(g_stats.total_check_time_us / 1000 / g_stats.total_checks);
            
            if (check_time_ms > g_stats.max_check_time_ms) {
                g_stats.max_check_time_ms = check_time_ms;
            }
            
            if (g_stats.min_check_time_ms == 0 || check_time_ms < g_stats.min_check_time_ms) {
                g_stats.min_check_time_ms = check_time_ms;
            }
            
            if (status == INTEGRITY_OK) {
                g_stats.successful_checks++;
            } else {
                g_stats.failed_checks++;
                trigger_integrity_event(status, 0);
            }
            
            xSemaphoreGive(g_integrity_mutex);
        }
        
        check_cycle++;
        
        // Vérification complète périodique (toutes les 100 cycles)
        if (check_cycle % 100 == 0) {
            ESP_LOGI(TAG, "Vérification complète périodique (cycle %lu)", check_cycle);
            integrity_status_t full_status = integrity_check_firmware();
            if (full_status == INTEGRITY_OK) {
                g_stats.last_full_check_time = esp_timer_get_time();
            }
        }
        
        vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(g_config.check_interval_ms));
    }
}

/**
 * @brief Callback du timer de vérification incrémentale
 */
static void incremental_timer_callback(TimerHandle_t xTimer) {
    // Cette fonction est appelée depuis un contexte d'interruption,
    // donc on utilise les versions FromISR des fonctions FreeRTOS
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    
    if (g_runtime_check_task != NULL) {
        vTaskNotifyGiveFromISR(g_runtime_check_task, &xHigherPriorityTaskWoken);
    }
    
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

// ================================
// Fonctions publiques - Initialisation
// ================================

esp_err_t integrity_checker_init(const integrity_config_t* config) {
    if (g_integrity_initialized) {
        ESP_LOGW(TAG, "Vérificateur d'intégrité déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Initialisation du vérificateur d'intégrité");
    
    // Configuration par défaut si non fournie
    if (config == NULL) {
        g_config = (integrity_config_t) {
            .enable_runtime_check = true,
            .enable_incremental_check = true,
            .enable_critical_only = false,
            .check_interval_ms = 5000,
            .chunk_size = INTEGRITY_CHUNK_SIZE,
            .max_concurrent_checks = 2,
            .preferred_method = INTEGRITY_METHOD_HYBRID,
            .signature_key_slot = SE_SLOT_ATTESTATION_KEY,
            .mac_key_slot = SE_SLOT_ENCRYPTION_KEY
        };
    } else {
        memcpy(&g_config, config, sizeof(integrity_config_t));
    }
    
    // Création du mutex
    g_integrity_mutex = xSemaphoreCreateMutex();
    if (g_integrity_mutex == NULL) {
        ESP_LOGE(TAG, "Échec création mutex intégrité");
        return ESP_ERR_NO_MEM;
    }
    
    // Initialisation des statistiques
    memset(&g_stats, 0, sizeof(integrity_stats_t));
    g_stats.min_check_time_ms = UINT32_MAX;
    
    // Lecture ou initialisation des métadonnées
    esp_err_t ret = integrity_read_metadata(&g_metadata);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Métadonnées non trouvées, initialisation...");
        
        // Obtenir les informations de l'application courante
        const esp_app_desc_t* app_desc = esp_app_get_description();
        const esp_partition_t* running_partition = esp_ota_get_running_partition();
        
        if (running_partition == NULL) {
            ESP_LOGE(TAG, "Impossible d'obtenir la partition courante");
            return ESP_FAIL;
        }
        
        ret = integrity_init_metadata(running_partition->address, running_partition->size);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Échec initialisation métadonnées");
            return ret;
        }
    }
    
    // Validation des métadonnées
    if (!integrity_validate_metadata(&g_metadata)) {
        ESP_LOGE(TAG, "Métadonnées d'intégrité invalides");
        return ESP_FAIL;
    }
    
    // Génération des chunks si nécessaire
    if (g_metadata.chunk_count == 0) {
        ret = integrity_generate_chunks(g_metadata.firmware_size, g_metadata.firmware_size, g_config.chunk_size);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Échec génération chunks");
            return ret;
        }
    }
    
    g_integrity_initialized = true;
    
    ESP_LOGI(TAG, "Vérificateur d'intégrité initialisé");
    ESP_LOGI(TAG, "Firmware: %lu bytes, %lu chunks, méthode: %d", 
             g_metadata.firmware_size, g_metadata.chunk_count, g_config.preferred_method);
    
    return ESP_OK;
}

esp_err_t integrity_checker_deinit(void) {
    if (!g_integrity_initialized) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Dé-initialisation du vérificateur d'intégrité");
    
    // Arrêt de la vérification en temps réel
    integrity_stop_runtime_check();
    
    // Suppression du mutex
    if (g_integrity_mutex != NULL) {
        vSemaphoreDelete(g_integrity_mutex);
        g_integrity_mutex = NULL;
    }
    
    g_integrity_initialized = false;
    
    ESP_LOGI(TAG, "Vérificateur d'intégrité dé-initialisé");
    return ESP_OK;
}

// ================================
// Fonctions publiques - Vérification
// ================================

integrity_status_t integrity_check_firmware(void) {
    if (!g_integrity_initialized) {
        return INTEGRITY_ERROR_NOT_INITIALIZED;
    }
    
    ESP_LOGI(TAG, "Démarrage vérification complète du firmware");
    
    integrity_result_t result;
    return integrity_check_firmware_detailed(&result);
}

integrity_status_t integrity_check_firmware_detailed(integrity_result_t* result) {
    if (!g_integrity_initialized || result == NULL) {
        return INTEGRITY_ERROR_NOT_INITIALIZED;
    }
    
    if (xSemaphoreTake(g_integrity_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        return INTEGRITY_ERROR_TIMEOUT;
    }
    
    memset(result, 0, sizeof(integrity_result_t));
    uint64_t start_time = esp_timer_get_time();
    
    result->total_chunks = g_metadata.chunk_count;
    result->status = INTEGRITY_OK;
    
    // Vérification chunk par chunk
    for (uint32_t i = 0; i < g_metadata.chunk_count && i < INTEGRITY_MAX_CHUNKS; i++) {
        integrity_status_t chunk_status = integrity_check_chunk(i);
        
        switch (chunk_status) {
            case INTEGRITY_OK:
                result->verified_chunks++;
                break;
            case INTEGRITY_ERROR_CORRUPTED:
                result->corrupted_chunks++;
                result->has_corruption = true;
                if (result->failed_count < 16) {
                    result->failed_chunk_ids[result->failed_count++] = i;
                }
                result->status = INTEGRITY_ERROR_CORRUPTED;
                break;
            default:
                result->failed_chunks++;
                if (result->failed_count < 16) {
                    result->failed_chunk_ids[result->failed_count++] = i;
                }
                if (result->status == INTEGRITY_OK) {
                    result->status = chunk_status;
                }
                break;
        }
    }
    
    // Vérification de la signature globale
    if (g_config.preferred_method == INTEGRITY_METHOD_SIGNATURE || 
        g_config.preferred_method == INTEGRITY_METHOD_HYBRID) {
        
        signature_verification_result_t sig_result;
        esp_err_t sig_ret = signature_verify_firmware(&g_metadata, &sig_result);
        
        if (sig_ret == ESP_OK && sig_result.is_valid) {
            result->signature_valid = true;
        } else {
            result->signature_valid = false;
            if (result->status == INTEGRITY_OK) {
                result->status = INTEGRITY_ERROR_SIGNATURE;
            }
        }
    } else {
        result->signature_valid = true; // Non applicable
    }
    
    uint64_t end_time = esp_timer_get_time();
    result->verification_time_ms = (uint32_t)((end_time - start_time) / 1000);
    
    xSemaphoreGive(g_integrity_mutex);
    
    ESP_LOGI(TAG, "Vérification complète terminée: %s (%lu ms)", 
             integrity_status_to_string(result->status), result->verification_time_ms);
    ESP_LOGI(TAG, "Chunks: %lu total, %lu vérifiés, %lu corrompus, %lu échecs",
             result->total_chunks, result->verified_chunks, 
             result->corrupted_chunks, result->failed_chunks);
    
    return result->status;
}

integrity_status_t integrity_check_chunk(uint32_t chunk_id) {
    if (!g_integrity_initialized || chunk_id >= g_metadata.chunk_count || chunk_id >= INTEGRITY_MAX_CHUNKS) {
        return INTEGRITY_ERROR_NOT_INITIALIZED;
    }
    
    integrity_chunk_info_t* chunk = &g_chunks[chunk_id];
    
    // Calcul du hash actuel
    uint8_t current_hash[INTEGRITY_HASH_SIZE];
    integrity_status_t status = calculate_chunk_hash(chunk, current_hash);
    if (status != INTEGRITY_OK) {
        return status;
    }
    
    // Comparaison avec le hash de référence
    if (memcmp(current_hash, chunk->hash, INTEGRITY_HASH_SIZE) != 0) {
        ESP_LOGE(TAG, "Hash mismatch chunk %lu", chunk_id);
        chunk->is_verified = false;
        trigger_integrity_event(INTEGRITY_ERROR_CORRUPTED, chunk_id);
        return INTEGRITY_ERROR_CORRUPTED;
    }
    
    // Vérification de signature si requise
    if (g_config.preferred_method == INTEGRITY_METHOD_SIGNATURE || 
        g_config.preferred_method == INTEGRITY_METHOD_HYBRID) {
        
        signature_verification_result_t sig_result;
        esp_err_t ret = signature_verify_chunk(chunk, &sig_result);
        
        if (ret != ESP_OK || !sig_result.is_valid) {
            ESP_LOGE(TAG, "Signature invalide chunk %lu", chunk_id);
            chunk->is_verified = false;
            trigger_integrity_event(INTEGRITY_ERROR_SIGNATURE, chunk_id);
            return INTEGRITY_ERROR_SIGNATURE;
        }
    }
    
    // Mise à jour des informations du chunk
    chunk->is_verified = true;
    chunk->last_check_time = (uint32_t)(esp_timer_get_time() / 1000000);
    chunk->check_count++;
    
    ESP_LOGD(TAG, "Chunk %lu vérifié avec succès", chunk_id);
    return INTEGRITY_OK;
}

integrity_status_t integrity_check_critical_sections(integrity_result_t* result) {
    if (!g_integrity_initialized || result == NULL) {
        return INTEGRITY_ERROR_NOT_INITIALIZED;
    }
    
    ESP_LOGI(TAG, "Vérification des sections critiques");
    
    memset(result, 0, sizeof(integrity_result_t));
    uint64_t start_time = esp_timer_get_time();
    
    uint32_t critical_chunks = 0;
    result->status = INTEGRITY_OK;
    
    // Vérification uniquement des chunks critiques
    for (uint32_t i = 0; i < g_metadata.chunk_count && i < INTEGRITY_MAX_CHUNKS; i++) {
        if (g_chunks[i].is_critical) {
            critical_chunks++;
            result->total_chunks++;
            
            integrity_status_t chunk_status = integrity_check_chunk(i);
            
            switch (chunk_status) {
                case INTEGRITY_OK:
                    result->verified_chunks++;
                    break;
                case INTEGRITY_ERROR_CORRUPTED:
                    result->corrupted_chunks++;
                    result->has_corruption = true;
                    if (result->failed_count < 16) {
                        result->failed_chunk_ids[result->failed_count++] = i;
                    }
                    result->status = INTEGRITY_ERROR_CORRUPTED;
                    break;
                default:
                    result->failed_chunks++;
                    if (result->failed_count < 16) {
                        result->failed_chunk_ids[result->failed_count++] = i;
                    }
                    if (result->status == INTEGRITY_OK) {
                        result->status = chunk_status;
                    }
                    break;
            }
        }
    }
    
    uint64_t end_time = esp_timer_get_time();
    result->verification_time_ms = (uint32_t)((end_time - start_time) / 1000);
    
    ESP_LOGI(TAG, "Vérification sections critiques terminée: %s (%lu chunks critiques)",
             integrity_status_to_string(result->status), critical_chunks);
    
    return result->status;
}

// ================================
// Fonctions publiques - Vérification en temps réel
// ================================

esp_err_t integrity_start_runtime_check(void) {
    if (!g_integrity_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (!g_config.enable_runtime_check) {
        ESP_LOGW(TAG, "Vérification en temps réel désactivée dans la configuration");
        return ESP_ERR_NOT_SUPPORTED;
    }
    
    if (g_runtime_check_task != NULL) {
        ESP_LOGW(TAG, "Vérification en temps réel déjà active");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Démarrage vérification en temps réel");
    
    // Création de la tâche de vérification
    BaseType_t task_ret = xTaskCreate(
        runtime_check_task,
        "integrity_runtime",
        4096,
        NULL,
        5, // Priorité moyenne
        &g_runtime_check_task
    );
    
    if (task_ret != pdPASS) {
        ESP_LOGE(TAG, "Échec création tâche vérification en temps réel");
        return ESP_ERR_NO_MEM;
    }
    
    // Création du timer pour la vérification incrémentale
    if (g_config.enable_incremental_check) {
        g_incremental_timer = xTimerCreate(
            "integrity_timer",
            pdMS_TO_TICKS(g_config.check_interval_ms),
            pdTRUE, // Timer périodique
            NULL,
            incremental_timer_callback
        );
        
        if (g_incremental_timer != NULL) {
            xTimerStart(g_incremental_timer, 0);
        }
    }
    
    ESP_LOGI(TAG, "Vérification en temps réel démarrée");
    return ESP_OK;
}

esp_err_t integrity_stop_runtime_check(void) {
    if (g_runtime_check_task == NULL) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Arrêt vérification en temps réel");
    
    // Arrêt du timer
    if (g_incremental_timer != NULL) {
        xTimerStop(g_incremental_timer, portMAX_DELAY);
        xTimerDelete(g_incremental_timer, portMAX_DELAY);
        g_incremental_timer = NULL;
    }
    
    // Suppression de la tâche
    vTaskDelete(g_runtime_check_task);
    g_runtime_check_task = NULL;
    
    ESP_LOGI(TAG, "Vérification en temps réel arrêtée");
    return ESP_OK;
}

bool integrity_is_runtime_check_active(void) {
    return (g_runtime_check_task != NULL);
}

integrity_status_t integrity_incremental_check(void) {
    if (!g_integrity_initialized) {
        return INTEGRITY_ERROR_NOT_INITIALIZED;
    }
    
    static uint32_t next_chunk_to_check = 0;
    
    // Vérification d'un nombre limité de chunks par cycle
    uint32_t chunks_to_check = MIN(g_config.max_concurrent_checks, g_metadata.chunk_count);
    
    for (uint32_t i = 0; i < chunks_to_check; i++) {
        uint32_t chunk_id = (next_chunk_to_check + i) % g_metadata.chunk_count;
        
        integrity_status_t status = integrity_check_chunk(chunk_id);
        if (status != INTEGRITY_OK) {
            ESP_LOGW(TAG, "Échec vérification incrémentale chunk %lu: %s", 
                     chunk_id, integrity_status_to_string(status));
            return status;
        }
    }
    
    next_chunk_to_check = (next_chunk_to_check + chunks_to_check) % g_metadata.chunk_count;
    
    ESP_LOGD(TAG, "Vérification incrémentale OK (%lu chunks)", chunks_to_check);
    return INTEGRITY_OK;
}

// ================================
// Fonctions publiques - Utilitaires
// ================================

const char* integrity_status_to_string(integrity_status_t status) {
    switch (status) {
        case INTEGRITY_OK: return "OK";
        case INTEGRITY_ERROR_CORRUPTED: return "Corrompu";
        case INTEGRITY_ERROR_SIGNATURE: return "Signature invalide";
        case INTEGRITY_ERROR_HASH_MISMATCH: return "Hash ne correspond pas";
        case INTEGRITY_ERROR_METADATA: return "Métadonnées corrompues";
        case INTEGRITY_ERROR_NOT_INITIALIZED: return "Non initialisé";
        case INTEGRITY_ERROR_MEMORY: return "Erreur mémoire";
        case INTEGRITY_ERROR_FLASH_READ: return "Erreur lecture flash";
        case INTEGRITY_ERROR_TIMEOUT: return "Timeout";
        case INTEGRITY_ERROR_UNKNOWN: return "Erreur inconnue";
        default: return "Statut invalide";
    }
}

integrity_status_t integrity_self_test(void) {
    ESP_LOGI(TAG, "Démarrage auto-test du vérificateur d'intégrité");
    
    if (!g_integrity_initialized) {
        ESP_LOGE(TAG, "Vérificateur non initialisé");
        return INTEGRITY_ERROR_NOT_INITIALIZED;
    }
    
    // Test de vérification d'un chunk
    if (g_metadata.chunk_count > 0) {
        integrity_status_t status = integrity_check_chunk(0);
        if (status != INTEGRITY_OK) {
            ESP_LOGE(TAG, "Échec test vérification chunk");
            return status;
        }
    }
    
    // Test de calcul de hash
    uint8_t test_data[] = "Test data for integrity check";
    uint8_t hash[INTEGRITY_HASH_SIZE];
    size_t hash_len = sizeof(hash);
    
    crypto_result_t crypto_ret = crypto_hash_compute(CRYPTO_HASH_SHA256, 
                                                     test_data, sizeof(test_data), 
                                                     hash, &hash_len);
    
    if (crypto_ret != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test calcul hash");
        return INTEGRITY_ERROR_MEMORY;
    }
    
    ESP_LOGI(TAG, "Auto-test réussi");
    return INTEGRITY_OK;
}

esp_err_t integrity_get_statistics(integrity_stats_t* stats) {
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (xSemaphoreTake(g_integrity_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(stats, &g_stats, sizeof(integrity_stats_t));
        xSemaphoreGive(g_integrity_mutex);
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

void integrity_reset_statistics(void) {
    if (xSemaphoreTake(g_integrity_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memset(&g_stats, 0, sizeof(integrity_stats_t));
        g_stats.min_check_time_ms = UINT32_MAX;
        xSemaphoreGive(g_integrity_mutex);
    }
}

// ================================
// Stubs pour fonctions non critiques
// ================================

esp_err_t integrity_init_metadata(uint32_t firmware_start, uint32_t firmware_size) {
    memset(&g_metadata, 0, sizeof(integrity_metadata_t));
    g_metadata.magic = INTEGRITY_MAGIC;
    g_metadata.version = INTEGRITY_METADATA_VERSION;
    g_metadata.firmware_size = firmware_size;
    g_metadata.chunk_size = g_config.chunk_size;
    g_metadata.verification_method = g_config.preferred_method;
    g_metadata.timestamp = (uint32_t)(esp_timer_get_time() / 1000000);
    g_metadata.checksum = calculate_metadata_checksum(&g_metadata);
    
    ESP_LOGI(TAG, "Métadonnées initialisées: firmware=%lu bytes, chunks=%lu", 
             firmware_size, g_metadata.chunk_count);
    
    return ESP_OK;
}

esp_err_t integrity_read_metadata(integrity_metadata_t* metadata) {
    // Stub - Dans une vraie implémentation, lirait depuis NVS
    memcpy(metadata, &g_metadata, sizeof(integrity_metadata_t));
    return ESP_OK;
}

bool integrity_validate_metadata(const integrity_metadata_t* metadata) {
    if (metadata->magic != INTEGRITY_MAGIC) return false;
    if (metadata->version != INTEGRITY_METADATA_VERSION) return false;
    
    uint32_t calculated_checksum = calculate_metadata_checksum(metadata);
    return (calculated_checksum == metadata->checksum);
}

esp_err_t integrity_generate_chunks(uint32_t firmware_start, uint32_t firmware_size, uint32_t chunk_size) {
    uint32_t chunk_count = (firmware_size + chunk_size - 1) / chunk_size;
    if (chunk_count > INTEGRITY_MAX_CHUNKS) {
        chunk_count = INTEGRITY_MAX_CHUNKS;
    }
    
    g_metadata.chunk_count = chunk_count;
    
    for (uint32_t i = 0; i < chunk_count; i++) {
        g_chunks[i].chunk_id = i;
        g_chunks[i].start_address = firmware_start + (i * chunk_size);
        g_chunks[i].size = MIN(chunk_size, firmware_size - (i * chunk_size));
        g_chunks[i].section_type = FIRMWARE_SECTION_APP;
        g_chunks[i].priority = INTEGRITY_PRIORITY_MEDIUM;
        g_chunks[i].is_critical = (i < 4); // Les premiers chunks sont critiques
        g_chunks[i].is_verified = false;
        
        // Calcul du hash initial
        calculate_chunk_hash(&g_chunks[i], g_chunks[i].hash);
    }
    
    ESP_LOGI(TAG, "Généré %lu chunks de %lu bytes", chunk_count, chunk_size);
    return ESP_OK;
}

// Autres stubs simplifiés
esp_err_t integrity_write_metadata(const integrity_metadata_t* metadata) { return ESP_OK; }
esp_err_t integrity_get_chunk_info(uint32_t chunk_id, integrity_chunk_info_t* chunk_info) { 
    if (chunk_id < INTEGRITY_MAX_CHUNKS) {
        memcpy(chunk_info, &g_chunks[chunk_id], sizeof(integrity_chunk_info_t));
        return ESP_OK;
    }
    return ESP_ERR_INVALID_ARG;
}
esp_err_t integrity_update_chunk_status(uint32_t chunk_id, bool is_verified) { 
    if (chunk_id < INTEGRITY_MAX_CHUNKS) {
        g_chunks[chunk_id].is_verified = is_verified;
        return ESP_OK;
    }
    return ESP_ERR_INVALID_ARG;
}
uint32_t integrity_get_chunk_count(void) { return g_metadata.chunk_count; }
bool integrity_detect_memory_corruption(uint32_t address, size_t size) { return false; }
esp_err_t integrity_analyze_corruption(uint32_t chunk_id, uint8_t* corruption_type) { return ESP_OK; }
esp_err_t integrity_recover_from_corruption(uint32_t chunk_id) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t integrity_configure(const integrity_config_t* config) { 
    if (config) memcpy(&g_config, config, sizeof(integrity_config_t));
    return ESP_OK; 
}
esp_err_t integrity_get_config(integrity_config_t* config) { 
    if (config) memcpy(config, &g_config, sizeof(integrity_config_t));
    return ESP_OK; 
}
esp_err_t integrity_register_callback(integrity_event_callback_t callback, void* user_data) {
    g_event_callback = callback;
    g_callback_user_data = user_data;
    return ESP_OK;
}
void integrity_unregister_callback(void) {
    g_event_callback = NULL;
    g_callback_user_data = NULL;
}
void integrity_print_info(void) {
    ESP_LOGI(TAG, "=== Informations Vérificateur d'Intégrité ===");
    ESP_LOGI(TAG, "Initialisé: %s", g_integrity_initialized ? "Oui" : "Non");
    ESP_LOGI(TAG, "Firmware: %lu bytes, %lu chunks", g_metadata.firmware_size, g_metadata.chunk_count);
    ESP_LOGI(TAG, "Vérification temps réel: %s", integrity_is_runtime_check_active() ? "Active" : "Inactive");
    ESP_LOGI(TAG, "==========================================");
}
void integrity_print_statistics(void) {
    ESP_LOGI(TAG, "=== Statistiques Intégrité ===");
    ESP_LOGI(TAG, "Vérifications totales: %lu", g_stats.total_checks);
    ESP_LOGI(TAG, "Réussies: %lu, Échouées: %lu", g_stats.successful_checks, g_stats.failed_checks);
    ESP_LOGI(TAG, "Corruptions détectées: %lu", g_stats.corruption_detections);
    ESP_LOGI(TAG, "Temps moyen: %lu ms", g_stats.avg_check_time_ms);
    ESP_LOGI(TAG, "===============================");
}
esp_err_t integrity_benchmark(uint32_t iterations) { return ESP_OK; }
integrity_status_t integrity_emergency_check(void) {
    return integrity_check_firmware();
}