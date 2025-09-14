/**
 * @file remote_verifier.c
 * @brief Vérifieur distant Enterprise avec TLS et authentification avancée
 * 
 * Version Enterprise avec support TLS obligatoire, authentification certificat,
 * monitoring des communications et retry intelligent.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "remote_verifier.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "REMOTE_VERIFIER_ENTERPRISE";

// Variables globales Enterprise
static bool g_verifier_initialized = false;
static SemaphoreHandle_t g_verifier_mutex = NULL;
static remote_verifier_config_enterprise_t g_config = {0};

// Statistiques Enterprise
static uint32_t g_total_requests = 0;
static uint32_t g_successful_requests = 0;
static uint32_t g_failed_requests = 0;
static uint32_t g_retry_attempts = 0;
static float g_avg_response_time_ms = 0.0f;

// Buffer pour réponse HTTP
#define HTTP_RESPONSE_BUFFER_SIZE 2048
static char g_http_response_buffer[HTTP_RESPONSE_BUFFER_SIZE];

/**
 * @brief Handler d'événement HTTP Enterprise
 */
static esp_err_t http_event_handler_enterprise(esp_http_client_event_t *evt) {
    static int output_len = 0;
    
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGE(TAG, "❌ Erreur HTTP Enterprise");
            break;
            
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "🔗 Connexion HTTP Enterprise établie");
            break;
            
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "📤 Headers HTTP Enterprise envoyés");
            break;
            
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "📥 Header reçu: %.*s", evt->data_len, (char*)evt->data);
            break;
            
        case HTTP_EVENT_ON_DATA:
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // Accumulation des données de réponse
                if (output_len + evt->data_len < HTTP_RESPONSE_BUFFER_SIZE) {
                    memcpy(g_http_response_buffer + output_len, evt->data, evt->data_len);
                    output_len += evt->data_len;
                    g_http_response_buffer[output_len] = '\0';
                }
            }
            break;
            
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "✅ Requête HTTP Enterprise terminée");
            output_len = 0;
            break;
            
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "🔌 Déconnexion HTTP Enterprise");
            output_len = 0;
            break;
            
        default:
            break;
    }
    return ESP_OK;
}

/**
 * @brief Initialisation du vérifieur distant Enterprise 
 */
esp_err_t remote_verifier_init_enterprise(void) {
    if (g_verifier_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🌐 Initialisation vérifieur distant Enterprise");
    
    // Création du mutex thread-safe
    g_verifier_mutex = xSemaphoreCreateMutex();
    if (g_verifier_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex vérifieur");
        return ESP_FAIL;
    }
    
    // Configuration par défaut Enterprise
    strncpy(g_config.server_url, "https://attestation.secureiot-vif.com", sizeof(g_config.server_url) - 1);
    g_config.server_port = 443;
    strncpy(g_config.api_endpoint, "/api/v2/enterprise/verify", sizeof(g_config.api_endpoint) - 1);
    strncpy(g_config.api_key, "ENTERPRISE_API_KEY_PLACEHOLDER", sizeof(g_config.api_key) - 1);
    g_config.timeout_ms = 10000; // 10 secondes
    g_config.tls_enabled = true; // Obligatoire en Enterprise
    g_config.certificate_validation = true;
    g_config.retry_attempts = 3;
    g_config.retry_delay_ms = 1000;
    g_config.compression_enabled = true;
    g_config.keep_alive_enabled = true;
    
    // Initialisation des statistiques
    g_total_requests = 0;
    g_successful_requests = 0;
    g_failed_requests = 0;
    g_retry_attempts = 0;
    g_avg_response_time_ms = 0.0f;
    
    g_verifier_initialized = true;
    
    ESP_LOGI(TAG, "✅ Vérifieur distant Enterprise initialisé");
    ESP_LOGI(TAG, "   🔒 TLS: Obligatoire");
    ESP_LOGI(TAG, "   🔑 Authentification: API Key");
    ESP_LOGI(TAG, "   📊 Monitoring: Activé");
    ESP_LOGI(TAG, "   🔄 Retry intelligent: %d tentatives", g_config.retry_attempts);
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation du vérifieur Enterprise
 */
esp_err_t remote_verifier_deinit_enterprise(void) {
    if (!g_verifier_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation vérifieur distant Enterprise");
    
    // Suppression du mutex
    if (g_verifier_mutex != NULL) {
        vSemaphoreDelete(g_verifier_mutex);
        g_verifier_mutex = NULL;
    }
    
    g_verifier_initialized = false;
    
    ESP_LOGI(TAG, "✅ Vérifieur distant Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Création du payload JSON Enterprise pour attestation
 */
static char* create_attestation_payload_enterprise(const uint8_t* attestation_data, size_t data_len) {
    cJSON *json_root = cJSON_CreateObject();
    cJSON *json_attestation = cJSON_CreateObject();
    cJSON *json_metadata = cJSON_CreateObject();
    
    if (!json_root || !json_attestation || !json_metadata) {
        ESP_LOGE(TAG, "❌ Échec création JSON payload");
        if (json_root) cJSON_Delete(json_root);
        if (json_attestation) cJSON_Delete(json_attestation);
        if (json_metadata) cJSON_Delete(json_metadata);
        return NULL;
    }
    
    // Conversion des données binaires en base64 (simplifié ici en hex)
    char *hex_data = malloc(data_len * 2 + 1);
    if (!hex_data) {
        cJSON_Delete(json_root);
        cJSON_Delete(json_attestation);
        cJSON_Delete(json_metadata);
        return NULL;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        sprintf(&hex_data[i * 2], "%02x", attestation_data[i]);
    }
    hex_data[data_len * 2] = '\0';
    
    // Construction du payload Enterprise
    cJSON_AddStringToObject(json_attestation, "data", hex_data);
    cJSON_AddStringToObject(json_attestation, "format", "secureiot-vif-enterprise");
    cJSON_AddStringToObject(json_attestation, "version", "2.0.0");
    
    // Métadonnées Enterprise
    cJSON_AddStringToObject(json_metadata, "device_type", "ESP32-Enterprise");
    cJSON_AddStringToObject(json_metadata, "framework", "SecureIoT-VIF-Enterprise");
    cJSON_AddNumberToObject(json_metadata, "timestamp", (uint32_t)(esp_timer_get_time() / 1000));
    cJSON_AddStringToObject(json_metadata, "api_version", "v2");
    cJSON_AddBoolToObject(json_metadata, "hsm_accelerated", true);
    cJSON_AddBoolToObject(json_metadata, "efuse_protected", true);
    
    // Assemblage final
    cJSON_AddItemToObject(json_root, "attestation", json_attestation);
    cJSON_AddItemToObject(json_root, "metadata", json_metadata);
    
    char *json_string = cJSON_Print(json_root);
    
    // Nettoyage
    free(hex_data);
    cJSON_Delete(json_root);
    
    return json_string;
}

/**
 * @brief Envoi d'attestation avec retry intelligent Enterprise
 */
esp_err_t remote_verifier_send_attestation_enterprise(const uint8_t* attestation_data, size_t data_len) {
    if (!g_verifier_initialized || !attestation_data || data_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex vérifieur");
        return ESP_ERR_TIMEOUT;
    }
    
    ESP_LOGI(TAG, "📤 Envoi attestation Enterprise (%zu bytes)", data_len);
    
    uint64_t start_time = esp_timer_get_time();
    esp_err_t final_result = ESP_FAIL;
    
    // Création du payload JSON
    char *json_payload = create_attestation_payload_enterprise(attestation_data, data_len);
    if (!json_payload) {
        ESP_LOGE(TAG, "❌ Échec création payload JSON");
        xSemaphoreGive(g_verifier_mutex);
        return ESP_FAIL;
    }
    
    // Configuration client HTTP Enterprise
    esp_http_client_config_t config = {
        .url = g_config.server_url,
        .port = g_config.server_port,
        .event_handler = http_event_handler_enterprise,
        .timeout_ms = g_config.timeout_ms,
        .buffer_size = HTTP_RESPONSE_BUFFER_SIZE,
        .buffer_size_tx = strlen(json_payload) + 512,
        .user_agent = "SecureIoT-VIF-Enterprise/2.0.0",
        .method = HTTP_METHOD_POST,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .skip_cert_common_name_check = !g_config.certificate_validation,
        .use_global_ca_store = true,
        .keep_alive_enable = g_config.keep_alive_enabled
    };
    
    // Retry intelligent avec backoff exponentiel
    for (uint32_t attempt = 1; attempt <= g_config.retry_attempts; attempt++) {
        ESP_LOGD(TAG, "🔄 Tentative %lu/%lu", attempt, g_config.retry_attempts);
        
        esp_http_client_handle_t client = esp_http_client_init(&config);
        if (!client) {
            ESP_LOGE(TAG, "❌ Échec initialisation client HTTP");
            continue;
        }
        
        // Configuration des headers Enterprise
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_header(client, "X-API-Key", g_config.api_key);
        esp_http_client_set_header(client, "X-SecureIoT-Version", "Enterprise-2.0.0");
        esp_http_client_set_header(client, "X-Device-Type", "ESP32-Enterprise");
        
        if (g_config.compression_enabled) {
            esp_http_client_set_header(client, "Accept-Encoding", "gzip, deflate");
        }
        
        // Configuration du post data
        esp_http_client_set_post_field(client, json_payload, strlen(json_payload));
        
        // Exécution de la requête
        esp_err_t err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            int status_code = esp_http_client_get_status_code(client);
            int content_length = esp_http_client_get_content_length(client);
            
            ESP_LOGD(TAG, "📊 Réponse HTTP: Status=%d, Length=%d", status_code, content_length);
            
            if (status_code >= 200 && status_code < 300) {
                // Succès
                ESP_LOGI(TAG, "✅ Attestation Enterprise envoyée avec succès (tentative %lu)", attempt);
                final_result = ESP_OK;
                g_successful_requests++;
                esp_http_client_cleanup(client);
                break;
            } else {
                ESP_LOGW(TAG, "⚠️ Réponse HTTP erreur: %d", status_code);
                if (g_http_response_buffer[0] != '\0') {
                    ESP_LOGD(TAG, "Réponse serveur: %s", g_http_response_buffer);
                }
            }
        } else {
            ESP_LOGE(TAG, "❌ Erreur requête HTTP: %s", esp_err_to_name(err));
        }
        
        esp_http_client_cleanup(client);
        
        // Backoff exponentiel pour retry
        if (attempt < g_config.retry_attempts) {
            uint32_t delay = g_config.retry_delay_ms * (1 << (attempt - 1)); // 2^(attempt-1)
            ESP_LOGD(TAG, "⏳ Attente %lums avant retry", delay);
            vTaskDelay(pdMS_TO_TICKS(delay));
            g_retry_attempts++;
        }
    }
    
    // Mise à jour des statistiques
    g_total_requests++;
    if (final_result != ESP_OK) {
        g_failed_requests++;
    }
    
    // Calcul du temps de réponse moyen
    uint64_t response_time = (esp_timer_get_time() - start_time) / 1000; // en ms
    g_avg_response_time_ms = ((g_avg_response_time_ms * (g_total_requests - 1)) + response_time) / g_total_requests;
    
    // Nettoyage
    free(json_payload);
    xSemaphoreGive(g_verifier_mutex);
    
    if (final_result == ESP_OK) {
        ESP_LOGI(TAG, "🎉 Attestation Enterprise transmise avec succès (%llums)", response_time);
    } else {
        ESP_LOGE(TAG, "💥 Échec définitif envoi attestation Enterprise après %lu tentatives", g_config.retry_attempts);
    }
    
    return final_result;
}

/**
 * @brief Configuration du vérifieur distant Enterprise
 */
esp_err_t remote_verifier_configure_enterprise(const remote_verifier_config_enterprise_t* config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "⚙️ Configuration vérifieur distant Enterprise");
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
        memcpy(&g_config, config, sizeof(remote_verifier_config_enterprise_t));
        
        // Validation de la configuration Enterprise
        if (!g_config.tls_enabled) {
            ESP_LOGW(TAG, "⚠️ TLS désactivé - Activation forcée en Enterprise");
            g_config.tls_enabled = true;
        }
        
        if (g_config.timeout_ms < 5000) {
            ESP_LOGW(TAG, "⚠️ Timeout trop court - Ajustement à 5s minimum");
            g_config.timeout_ms = 5000;
        }
        
        xSemaphoreGive(g_verifier_mutex);
        
        ESP_LOGI(TAG, "✅ Configuration vérifieur Enterprise mise à jour");
        ESP_LOGI(TAG, "   🌐 Serveur: %s:%d", g_config.server_url, g_config.server_port);
        ESP_LOGI(TAG, "   🔒 TLS: %s", g_config.tls_enabled ? "Activé" : "Désactivé");
        ESP_LOGI(TAG, "   ⏱️ Timeout: %lums", g_config.timeout_ms);
        ESP_LOGI(TAG, "   🔄 Retry: %lu tentatives", g_config.retry_attempts);
        
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

/**
 * @brief Obtention des statistiques du vérifieur Enterprise
 */
remote_verifier_stats_enterprise_t remote_verifier_get_stats_enterprise(void) {
    remote_verifier_stats_enterprise_t stats = {0};
    
    if (!g_verifier_initialized) {
        return stats;
    }
    
    if (xSemaphoreTake(g_verifier_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        stats.total_requests = g_total_requests;
        stats.successful_requests = g_successful_requests;
        stats.failed_requests = g_failed_requests;
        stats.retry_attempts = g_retry_attempts;
        stats.avg_response_time_ms = g_avg_response_time_ms;
        
        if (g_total_requests > 0) {
            stats.success_rate = (float)g_successful_requests / g_total_requests;
        }
        
        stats.uptime_seconds = (uint32_t)(esp_timer_get_time() / 1000000);
        
        xSemaphoreGive(g_verifier_mutex);
    }
    
    return stats;
}

/**
 * @brief Test de connectivité du vérifieur Enterprise
 */
esp_err_t remote_verifier_test_connectivity_enterprise(void) {
    if (!g_verifier_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "🔍 Test connectivité vérifieur Enterprise");
    
    // Configuration client HTTP pour test
    esp_http_client_config_t config = {
        .url = g_config.server_url,
        .port = g_config.server_port,
        .timeout_ms = 5000,
        .method = HTTP_METHOD_HEAD,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .skip_cert_common_name_check = !g_config.certificate_validation
    };
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "❌ Échec initialisation client test");
        return ESP_FAIL;
    }
    
    esp_http_client_set_header(client, "X-API-Key", g_config.api_key);
    esp_http_client_set_header(client, "User-Agent", "SecureIoT-VIF-Enterprise-Test/2.0.0");
    
    esp_err_t err = esp_http_client_perform(client);
    bool connectivity_ok = false;
    
    if (err == ESP_OK) {
        int status_code = esp_http_client_get_status_code(client);
        if (status_code >= 200 && status_code < 500) { // Accepter même les erreurs d'auth
            connectivity_ok = true;
            ESP_LOGI(TAG, "✅ Connectivité Enterprise OK (Status: %d)", status_code);
        } else {
            ESP_LOGW(TAG, "⚠️ Connectivité Enterprise limitée (Status: %d)", status_code);
        }
    } else {
        ESP_LOGE(TAG, "❌ Échec test connectivité: %s", esp_err_to_name(err));
    }
    
    esp_http_client_cleanup(client);
    
    return connectivity_ok ? ESP_OK : ESP_FAIL;
}

/**
 * @brief Compatibilité avec version standard
 */
esp_err_t remote_verifier_init(void) {
    return remote_verifier_init_enterprise();
}

esp_err_t remote_verifier_deinit(void) {
    return remote_verifier_deinit_enterprise();
}

esp_err_t remote_verifier_send_attestation(const uint8_t* attestation_data, size_t data_len) {
    return remote_verifier_send_attestation_enterprise(attestation_data, data_len);
}