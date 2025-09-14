/**
 * @file incident_manager.c
 * @brief Implémentation du gestionnaire d'incidents de sécurité
 */

#include "incident_manager.h"
#include "se_manager.h"
#include "esp_log.h"
#include "esp_system.h"
#include <string.h>

static const char *TAG = "INCIDENT_MANAGER";
static bool g_incident_initialized = false;
static incident_stats_t g_stats;

esp_err_t incident_manager_init(void) {
    if (g_incident_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Initialisation gestionnaire d'incidents");
    memset(&g_stats, 0, sizeof(incident_stats_t));
    g_incident_initialized = true;
    
    ESP_LOGI(TAG, "Gestionnaire d'incidents initialisé");
    return ESP_OK;
}

esp_err_t incident_manager_deinit(void) {
    if (!g_incident_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Dé-initialisation gestionnaire d'incidents");
    g_incident_initialized = false;
    return ESP_OK;
}

esp_err_t incident_handle_integrity_failure(const security_event_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "INCIDENT CRITIQUE: Échec intégrité - %s", event->description);
    
    g_stats.total_incidents++;
    g_stats.critical_incidents++;
    g_stats.integrity_failures++;
    g_stats.active_incidents++;
    g_stats.last_incident_time = esp_timer_get_time();
    
    // Actions d'urgence
    if (event->severity >= SECURITY_SEVERITY_CRITICAL) {
        ESP_LOGE(TAG, "Déclenchement procédure d'urgence");
        se_store_emergency_state();
        
        // En production, pourrait déclencher un redémarrage sécurisé
        // esp_restart();
    }
    
    return ESP_OK;
}

esp_err_t incident_handle_anomaly(const security_event_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGW(TAG, "INCIDENT: Anomalie détectée - %s", event->description);
    
    g_stats.total_incidents++;
    g_stats.anomaly_detections++;
    g_stats.active_incidents++;
    g_stats.last_incident_time = esp_timer_get_time();
    
    // Actions selon la sévérité
    switch (event->severity) {
        case SECURITY_SEVERITY_HIGH:
        case SECURITY_SEVERITY_CRITICAL:
            ESP_LOGW(TAG, "Anomalie de haute sévérité - monitoring renforcé");
            break;
        default:
            ESP_LOGD(TAG, "Anomalie de sévérité normale - surveillance continue");
            break;
    }
    
    return ESP_OK;
}

esp_err_t incident_handle_attestation_failure(const security_event_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "INCIDENT: Échec attestation - %s", event->description);
    
    g_stats.total_incidents++;
    g_stats.attestation_failures++;
    g_stats.active_incidents++;
    g_stats.last_incident_time = esp_timer_get_time();
    
    // Tentative de récupération
    ESP_LOGI(TAG, "Tentative de récupération attestation");
    
    return ESP_OK;
}

esp_err_t incident_handle_unauthorized_access(const security_event_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "INCIDENT SÉCURITÉ: Accès non autorisé - %s", event->description);
    
    g_stats.total_incidents++;
    g_stats.critical_incidents++;
    g_stats.active_incidents++;
    g_stats.last_incident_time = esp_timer_get_time();
    
    // Mesures de sécurité immédiates
    ESP_LOGE(TAG, "Activation mesures de sécurité d'urgence");
    se_enable_secure_mode();
    
    return ESP_OK;
}

esp_err_t incident_get_statistics(incident_stats_t* stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;
    
    memcpy(stats, &g_stats, sizeof(incident_stats_t));
    return ESP_OK;
}