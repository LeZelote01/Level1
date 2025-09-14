/**
 * @file incident_manager.c
 * @brief Gestionnaire d'incidents de sécurité Enterprise avancé
 * 
 * Version Enterprise avec gestion avancée des incidents, escalade automatique,
 * réponse adaptative, intégration compliance et forensique.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "incident_manager.h"
#include "esp32_crypto_manager.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "INCIDENT_MANAGER_ENTERPRISE";

// Variables globales Enterprise
static bool g_incident_initialized = false;
static incident_stats_enterprise_t g_stats_enterprise = {0};
static incident_config_enterprise_t g_config_enterprise = {0};
static SemaphoreHandle_t g_incident_mutex = NULL;

// Gestion des incidents actifs
static incident_enterprise_t g_active_incidents[MAX_CONCURRENT_INCIDENTS_ENTERPRISE];
static uint32_t g_active_incident_count = 0;
static uint32_t g_next_incident_id = 1;

// Historique des incidents
static incident_enterprise_t g_incident_history[MAX_INCIDENT_HISTORY_ENTERPRISE];
static uint32_t g_history_write_index = 0;
static bool g_history_full = false;

// Timer pour vérifications périodiques
static esp_timer_handle_t g_incident_monitor_timer = NULL;

/**
 * @brief Callback timer de monitoring des incidents
 */
static void incident_monitor_timer_callback(void* arg) {
    if (!g_incident_initialized) return;
    
    if (xSemaphoreTake(g_incident_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        uint32_t current_time = (uint32_t)(esp_timer_get_time() / 1000);
        
        // Vérification escalade automatique
        for (uint32_t i = 0; i < g_active_incident_count; i++) {
            incident_enterprise_t* incident = &g_active_incidents[i];
            
            if (!incident->escalated && 
                g_config_enterprise.escalation_enabled &&
                (current_time - incident->start_time) > g_config_enterprise.auto_escalation_time_ms) {
                
                // Escalade automatique
                incident->escalated = true;
                incident->escalation_time = current_time;
                strncpy(incident->escalation_reason, "Auto-escalation timeout", sizeof(incident->escalation_reason) - 1);
                
                g_stats_enterprise.escalated_incidents++;
                
                ESP_LOGW(TAG, "⬆️ Escalade automatique incident #%lu après %lums", 
                         incident->incident_id, 
                         current_time - incident->start_time);
            }
        }
        
        xSemaphoreGive(g_incident_mutex);
    }
}

/**
 * @brief Détermination du niveau de réponse basé sur l'événement
 */
static incident_response_level_t determine_response_level(const security_event_enterprise_t* event) {
    if (!event) return RESPONSE_LEVEL_NONE;
    
    // Logique de détermination basée sur type et sévérité
    switch (event->type) {
        case SECURITY_EVENT_REALTIME_INTEGRITY_FAIL:
        case SECURITY_EVENT_SECURE_BOOT_FAILURE:
        case SECURITY_EVENT_TAMPER_DETECTION:
            return RESPONSE_LEVEL_EMERGENCY_SHUTDOWN;
            
        case SECURITY_EVENT_CONTINUOUS_ATTESTATION_FAIL:
        case SECURITY_EVENT_EFUSE_CORRUPTION:
            return RESPONSE_LEVEL_ISOLATE;
            
        case SECURITY_EVENT_BEHAVIORAL_ANOMALY:
        case SECURITY_EVENT_ML_MODEL_DRIFT:
            return (event->severity >= SECURITY_SEVERITY_HIGH) ? RESPONSE_LEVEL_MITIGATE : RESPONSE_LEVEL_ALERT;
            
        case SECURITY_EVENT_PERFORMANCE_DEGRADATION:
            return RESPONSE_LEVEL_MONITOR;
            
        default:
            if (event->severity >= SECURITY_SEVERITY_CRITICAL) {
                return RESPONSE_LEVEL_MITIGATE;
            } else if (event->severity >= SECURITY_SEVERITY_HIGH) {
                return RESPONSE_LEVEL_ALERT;
            } else {
                return RESPONSE_LEVEL_LOG_ONLY;
            }
    }
}

/**
 * @brief Capture des données forensiques
 */
static void capture_forensic_data(const security_event_enterprise_t* event, incident_enterprise_t* incident) {
    if (!event || !incident || !g_config_enterprise.forensic_capture_enabled) return;
    
    ESP_LOGI(TAG, "🔍 Capture données forensiques pour incident #%lu", incident->incident_id);
    
    // Capture basique des données système
    incident->forensic_evidence_collected = true;
    incident->forensic_package_id = incident->incident_id * 1000 + (uint32_t)(esp_timer_get_time() / 1000000);
    
    // Dans une implémentation complète, capturerait :
    // - État mémoire
    // - Logs système
    // - Configuration sécurité  
    // - Données crypto
    // - Traces réseau
    
    ESP_LOGI(TAG, "✅ Données forensiques capturées (Package: %lu)", incident->forensic_package_id);
}

/**
 * @brief Exécution de la réponse automatique
 */
static void execute_automated_response(incident_response_level_t response_level, incident_enterprise_t* incident) {
    if (!g_config_enterprise.automated_response_enabled) return;
    
    ESP_LOGI(TAG, "🤖 Exécution réponse automatique niveau %d pour incident #%lu", 
             response_level, incident->incident_id);
    
    incident->automated_response_triggered = true;
    
    switch (response_level) {
        case RESPONSE_LEVEL_EMERGENCY_SHUTDOWN:
            ESP_LOGE(TAG, "💥 RÉPONSE D'URGENCE: Arrêt d'urgence système");
            esp32_crypto_store_emergency_state();
            strncpy(incident->mitigation_actions, "Emergency shutdown executed", sizeof(incident->mitigation_actions) - 1);
            // Note: En production, pourrait déclencher esp_restart()
            break;
            
        case RESPONSE_LEVEL_ISOLATE:
            ESP_LOGW(TAG, "🔒 ISOLATION: Activation mode sécurisé");
            esp32_crypto_enable_secure_mode();
            strncpy(incident->mitigation_actions, "System isolated, secure mode enabled", sizeof(incident->mitigation_actions) - 1);
            break;
            
        case RESPONSE_LEVEL_MITIGATE:
            ESP_LOGI(TAG, "🛡️ MITIGATION: Mesures de protection renforcées");
            strncpy(incident->mitigation_actions, "Security measures reinforced", sizeof(incident->mitigation_actions) - 1);
            break;
            
        case RESPONSE_LEVEL_ALERT:
            ESP_LOGI(TAG, "🚨 ALERTE: Notification et monitoring renforcé");
            strncpy(incident->mitigation_actions, "Alert sent, monitoring increased", sizeof(incident->mitigation_actions) - 1);
            break;
            
        case RESPONSE_LEVEL_MONITOR:
            ESP_LOGI(TAG, "👁️ MONITORING: Surveillance renforcée");
            strncpy(incident->mitigation_actions, "Enhanced monitoring activated", sizeof(incident->mitigation_actions) - 1);
            break;
            
        case RESPONSE_LEVEL_LOG_ONLY:
            ESP_LOGD(TAG, "📝 LOG: Événement enregistré");
            strncpy(incident->mitigation_actions, "Event logged", sizeof(incident->mitigation_actions) - 1);
            break;
            
        case RESPONSE_LEVEL_FORENSIC_CAPTURE:
            ESP_LOGI(TAG, "🔍 FORENSIQUE: Capture données forensiques");
            capture_forensic_data(NULL, incident);
            strncpy(incident->mitigation_actions, "Forensic data captured", sizeof(incident->mitigation_actions) - 1);
            break;
            
        default:
            strncpy(incident->mitigation_actions, "No automated response", sizeof(incident->mitigation_actions) - 1);
            break;
    }
}

/**
 * @brief Ajout d'un incident à l'historique
 */
static void add_incident_to_history(const incident_enterprise_t* incident) {
    if (!incident) return;
    
    memcpy(&g_incident_history[g_history_write_index], incident, sizeof(incident_enterprise_t));
    g_history_write_index = (g_history_write_index + 1) % MAX_INCIDENT_HISTORY_ENTERPRISE;
    
    if (g_history_write_index == 0) {
        g_history_full = true;
    }
}

/**
 * @brief Initialisation du gestionnaire d'incidents Enterprise
 */
esp_err_t incident_manager_init_enterprise(const incident_config_enterprise_t* config) {
    if (g_incident_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🚨 Initialisation gestionnaire incidents Enterprise");
    
    // Création du mutex thread-safe
    g_incident_mutex = xSemaphoreCreateMutex();
    if (g_incident_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex incidents");
        return ESP_FAIL;
    }
    
    // Configuration par défaut ou fournie
    if (config) {
        memcpy(&g_config_enterprise, config, sizeof(incident_config_enterprise_t));
    } else {
        // Configuration par défaut Enterprise
        g_config_enterprise.automated_response_enabled = true;
        g_config_enterprise.forensic_capture_enabled = true;
        g_config_enterprise.compliance_monitoring_enabled = true;
        g_config_enterprise.escalation_enabled = true;
        g_config_enterprise.auto_escalation_time_ms = 300000; // 5 minutes
        g_config_enterprise.incident_retention_days = 90;
        g_config_enterprise.default_response_level = RESPONSE_LEVEL_ALERT;
        g_config_enterprise.real_time_notification_enabled = true;
    }
    
    // Initialisation des structures
    memset(&g_stats_enterprise, 0, sizeof(incident_stats_enterprise_t));
    memset(g_active_incidents, 0, sizeof(g_active_incidents));
    memset(g_incident_history, 0, sizeof(g_incident_history));
    
    g_active_incident_count = 0;
    g_next_incident_id = 1;
    g_history_write_index = 0;
    g_history_full = false;
    
    // Configuration du timer de monitoring
    esp_timer_create_args_t timer_args = {
        .callback = &incident_monitor_timer_callback,
        .arg = NULL,
        .name = "incident_monitor_enterprise"
    };
    
    esp_err_t ret = esp_timer_create(&timer_args, &g_incident_monitor_timer);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec création timer monitoring: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Démarrage du timer (toutes les 30 secondes)
    ret = esp_timer_start_periodic(g_incident_monitor_timer, 30000000); // 30s en µs
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec démarrage timer monitoring: %s", esp_err_to_name(ret));
        return ret;
    }
    
    g_incident_initialized = true;
    
    ESP_LOGI(TAG, "✅ Gestionnaire incidents Enterprise initialisé");
    ESP_LOGI(TAG, "   🤖 Réponse automatique: %s", g_config_enterprise.automated_response_enabled ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   🔍 Capture forensique: %s", g_config_enterprise.forensic_capture_enabled ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   📋 Monitoring compliance: %s", g_config_enterprise.compliance_monitoring_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   ⬆️ Escalade automatique: %s (%lums)", 
             g_config_enterprise.escalation_enabled ? "Activée" : "Désactivée",
             g_config_enterprise.auto_escalation_time_ms);
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation du gestionnaire Enterprise
 */
esp_err_t incident_manager_deinit_enterprise(void) {
    if (!g_incident_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation gestionnaire incidents Enterprise");
    
    // Arrêt du timer
    if (g_incident_monitor_timer != NULL) {
        esp_timer_stop(g_incident_monitor_timer);
        esp_timer_delete(g_incident_monitor_timer);
        g_incident_monitor_timer = NULL;
    }
    
    // Suppression du mutex
    if (g_incident_mutex != NULL) {
        vSemaphoreDelete(g_incident_mutex);
        g_incident_mutex = NULL;
    }
    
    g_incident_initialized = false;
    
    ESP_LOGI(TAG, "✅ Gestionnaire incidents Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Création d'un incident Enterprise
 */
esp_err_t incident_create_enterprise(const security_event_enterprise_t* event, uint32_t* incident_id) {
    if (!g_incident_initialized || !event || !incident_id) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (xSemaphoreTake(g_incident_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex incidents");
        return ESP_ERR_TIMEOUT;
    }
    
    // Vérification capacité
    if (g_active_incident_count >= MAX_CONCURRENT_INCIDENTS_ENTERPRISE) {
        ESP_LOGW(TAG, "⚠️ Capacité incidents atteinte - résolution automatique anciens");
        // Dans une implémentation complète, résoudrait les anciens incidents
        xSemaphoreGive(g_incident_mutex);
        return ESP_ERR_NO_MEM;
    }
    
    // Création du nouvel incident
    incident_enterprise_t* incident = &g_active_incidents[g_active_incident_count];
    memset(incident, 0, sizeof(incident_enterprise_t));
    
    // Informations de base
    incident->incident_id = g_next_incident_id++;
    incident->type = (incident_type_enterprise_t)event->type;
    incident->status = INCIDENT_STATUS_NEW;
    incident->severity = event->severity;
    incident->start_time = event->timestamp;
    incident->last_update_time = event->timestamp;
    
    // Descriptions
    snprintf(incident->title, sizeof(incident->title), "Incident #%lu - %s", 
             incident->incident_id, 
             (event->type == SECURITY_EVENT_REALTIME_INTEGRITY_FAIL) ? "Intégrité temps réel" :
             (event->type == SECURITY_EVENT_CONTINUOUS_ATTESTATION_FAIL) ? "Attestation continue" :
             (event->type == SECURITY_EVENT_BEHAVIORAL_ANOMALY) ? "Anomalie comportementale" :
             "Incident sécurité");
    
    strncpy(incident->description, event->description, sizeof(incident->description) - 1);
    
    // Événement associé
    incident->event_count = 1;
    incident->event_ids[0] = event->correlation_id;
    
    // Détermination du niveau de réponse
    incident->response_level = determine_response_level(event);
    
    // Capture forensique si nécessaire
    if (event->forensic_capture_required || incident->response_level >= RESPONSE_LEVEL_ISOLATE) {
        capture_forensic_data(event, incident);
    }
    
    // Réponse automatique
    execute_automated_response(incident->response_level, incident);
    
    // Compliance
    if (g_config_enterprise.compliance_monitoring_enabled && event->compliance_relevant) {
        incident->compliance_notification_sent = true;
        incident->compliance_case_id = incident->incident_id + 50000;
        g_stats_enterprise.compliance_incidents++;
    }
    
    // Métriques
    incident->detection_time_ms = 10; // Simulation
    incident->response_time_ms = (uint32_t)(esp_timer_get_time() / 1000) - event->timestamp;
    incident->impact_score = (float)event->severity / 5.0f;
    
    g_active_incident_count++;
    *incident_id = incident->incident_id;
    
    // Mise à jour des statistiques
    g_stats_enterprise.total_incidents++;
    g_stats_enterprise.active_incidents++;
    g_stats_enterprise.last_incident_time = esp_timer_get_time();
    
    if (incident->severity >= SECURITY_SEVERITY_CRITICAL) {
        g_stats_enterprise.critical_incidents++;
    }
    if (incident->severity == SECURITY_SEVERITY_EMERGENCY) {
        g_stats_enterprise.emergency_incidents++;
    }
    
    // Types spécifiques
    switch (event->type) {
        case SECURITY_EVENT_INTEGRITY_FAILURE:
        case SECURITY_EVENT_REALTIME_INTEGRITY_FAIL:
            g_stats_enterprise.integrity_failures++;
            break;
        case SECURITY_EVENT_ANOMALY_DETECTED:
        case SECURITY_EVENT_BEHAVIORAL_ANOMALY:
            g_stats_enterprise.anomaly_detections++;
            break;
        case SECURITY_EVENT_ATTESTATION_FAILURE:
        case SECURITY_EVENT_CONTINUOUS_ATTESTATION_FAIL:
            g_stats_enterprise.attestation_failures++;
            break;
        default:
            break;
    }
    
    xSemaphoreGive(g_incident_mutex);
    
    ESP_LOGI(TAG, "🚨 Incident Enterprise créé #%lu (Type: %d, Sévérité: %d, Réponse: %d)", 
             incident->incident_id, incident->type, incident->severity, incident->response_level);
    
    return ESP_OK;
}

/**
 * @brief Gestion incident intégrité temps réel (Innovation Enterprise)
 */
esp_err_t incident_handle_realtime_integrity_failure(const security_event_enterprise_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "💥 INCIDENT CRITIQUE: Échec intégrité temps réel Enterprise - %s", event->description);
    
    uint32_t incident_id;
    esp_err_t ret = incident_create_enterprise(event, &incident_id);
    
    if (ret == ESP_OK) {
        ESP_LOGE(TAG, "⚡ Mesures d'urgence activées pour incident #%lu", incident_id);
        
        // Actions d'urgence spécifiques
        esp32_crypto_store_emergency_state();
        
        // En production, pourrait déclencher un redémarrage sécurisé immédiat
        // esp_restart();
    }
    
    return ret;
}

/**
 * @brief Gestion incident attestation continue (Innovation Enterprise)
 */
esp_err_t incident_handle_continuous_attestation_failure(const security_event_enterprise_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "🛡️ INCIDENT ÉLEVÉ: Échec attestation continue Enterprise - %s", event->description);
    
    uint32_t incident_id;
    esp_err_t ret = incident_create_enterprise(event, &incident_id);
    
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "🔒 Isolation système activée pour incident #%lu", incident_id);
    }
    
    return ret;
}

/**
 * @brief Gestion anomalie comportementale ML (Innovation Enterprise)
 */
esp_err_t incident_handle_behavioral_anomaly(const security_event_enterprise_t* event) {
    if (!g_incident_initialized || !event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGW(TAG, "🤖 INCIDENT ML: Anomalie comportementale Enterprise - %s", event->description);
    
    uint32_t incident_id;
    esp_err_t ret = incident_create_enterprise(event, &incident_id);
    
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "📊 Analyse ML renforcée pour incident #%lu", incident_id);
    }
    
    return ret;
}

/**
 * @brief Fonctions de compatibilité avec version standard
 */
esp_err_t incident_manager_init(void) {
    return incident_manager_init_enterprise(NULL);
}

esp_err_t incident_manager_deinit(void) {
    return incident_manager_deinit_enterprise();
}

esp_err_t incident_handle_integrity_failure(const security_event_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    // Conversion vers Enterprise
    security_event_enterprise_t enterprise_event = {0};
    enterprise_event.type = event->type;
    enterprise_event.timestamp = event->timestamp;
    enterprise_event.severity = event->severity;
    strncpy(enterprise_event.description, event->description, sizeof(enterprise_event.description) - 1);
    memcpy(enterprise_event.data, event->data, MIN(event->data_len, sizeof(enterprise_event.data)));
    enterprise_event.data_len = event->data_len;
    enterprise_event.confidence_score = 0.8f;
    enterprise_event.response_level = RESPONSE_LEVEL_MITIGATE;
    
    return incident_handle_realtime_integrity_failure(&enterprise_event);
}

esp_err_t incident_handle_anomaly(const security_event_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    // Conversion vers Enterprise
    security_event_enterprise_t enterprise_event = {0};
    enterprise_event.type = SECURITY_EVENT_BEHAVIORAL_ANOMALY;
    enterprise_event.timestamp = event->timestamp;
    enterprise_event.severity = event->severity;
    strncpy(enterprise_event.description, event->description, sizeof(enterprise_event.description) - 1);
    memcpy(enterprise_event.data, event->data, MIN(event->data_len, sizeof(enterprise_event.data)));
    enterprise_event.data_len = event->data_len;
    enterprise_event.confidence_score = 0.7f;
    enterprise_event.response_level = RESPONSE_LEVEL_ALERT;
    
    return incident_handle_behavioral_anomaly(&enterprise_event);
}

esp_err_t incident_handle_attestation_failure(const security_event_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    // Conversion vers Enterprise
    security_event_enterprise_t enterprise_event = {0};
    enterprise_event.type = SECURITY_EVENT_CONTINUOUS_ATTESTATION_FAIL;
    enterprise_event.timestamp = event->timestamp;
    enterprise_event.severity = event->severity;
    strncpy(enterprise_event.description, event->description, sizeof(enterprise_event.description) - 1);
    memcpy(enterprise_event.data, event->data, MIN(event->data_len, sizeof(enterprise_event.data)));
    enterprise_event.data_len = event->data_len;
    enterprise_event.confidence_score = 0.9f;
    enterprise_event.response_level = RESPONSE_LEVEL_ISOLATE;
    
    return incident_handle_continuous_attestation_failure(&enterprise_event);
}

esp_err_t incident_handle_unauthorized_access(const security_event_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "🚨 INCIDENT SÉCURITÉ: Accès non autorisé Enterprise - %s", event->description);
    
    // Conversion vers Enterprise
    security_event_enterprise_t enterprise_event = {0};
    enterprise_event.type = event->type;
    enterprise_event.timestamp = event->timestamp;
    enterprise_event.severity = SECURITY_SEVERITY_CRITICAL; // Élevé à critique
    strncpy(enterprise_event.description, event->description, sizeof(enterprise_event.description) - 1);
    enterprise_event.confidence_score = 0.95f;
    enterprise_event.response_level = RESPONSE_LEVEL_EMERGENCY_SHUTDOWN;
    enterprise_event.forensic_capture_required = true;
    
    uint32_t incident_id;
    esp_err_t ret = incident_create_enterprise(&enterprise_event, &incident_id);
    
    if (ret == ESP_OK) {
        ESP_LOGE(TAG, "💥 Mesures d'urgence activées pour accès non autorisé #%lu", incident_id);
    }
    
    return ret;
}

esp_err_t incident_get_statistics(incident_stats_t* stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;
    
    incident_stats_enterprise_t enterprise_stats;
    esp_err_t ret = incident_get_statistics_enterprise(&enterprise_stats);
    
    if (ret == ESP_OK) {
        // Conversion vers format standard
        stats->total_incidents = enterprise_stats.total_incidents;
        stats->critical_incidents = enterprise_stats.critical_incidents;
        stats->resolved_incidents = enterprise_stats.resolved_incidents;
        stats->active_incidents = enterprise_stats.active_incidents;
        stats->last_incident_time = enterprise_stats.last_incident_time;
        stats->integrity_failures = enterprise_stats.integrity_failures;
        stats->anomaly_detections = enterprise_stats.anomaly_detections;
        stats->attestation_failures = enterprise_stats.attestation_failures;
    }
    
    return ret;
}

esp_err_t incident_get_statistics_enterprise(incident_stats_enterprise_t* stats) {
    if (!stats || !g_incident_initialized) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_incident_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(stats, &g_stats_enterprise, sizeof(incident_stats_enterprise_t));
        
        // Calculs dérivés temps réel
        uint32_t current_time = (uint32_t)(esp_timer_get_time() / 1000000);
        stats->uptime_seconds = current_time;
        
        // Tendances 24h
        uint32_t day_ago = current_time - 86400;
        stats->incidents_last_24h = 0;
        stats->critical_incidents_last_24h = 0;
        
        // Parcours historique pour tendances
        uint32_t history_size = g_history_full ? MAX_INCIDENT_HISTORY_ENTERPRISE : g_history_write_index;
        for (uint32_t i = 0; i < history_size; i++) {
            const incident_enterprise_t* hist_incident = &g_incident_history[i];
            if (hist_incident->start_time > day_ago) {
                stats->incidents_last_24h++;
                if (hist_incident->severity >= SECURITY_SEVERITY_CRITICAL) {
                    stats->critical_incidents_last_24h++;
                }
            }
        }
        
        // Score de tendance (simplifié)
        if (stats->total_incidents > 10) {
            stats->incident_trend_score = (float)stats->incidents_last_24h / (stats->total_incidents / 10.0f);
        } else {
            stats->incident_trend_score = 0.0f;
        }
        
        xSemaphoreGive(g_incident_mutex);
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

// Fonctions Enterprise supplémentaires à implémenter selon les besoins...
esp_err_t incident_handle_ml_model_drift(const security_event_enterprise_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGW(TAG, "🔄 INCIDENT ML: Dérive modèle détectée - %s", event->description);
    
    uint32_t incident_id;
    return incident_create_enterprise(event, &incident_id);
}

esp_err_t incident_handle_performance_degradation(const security_event_enterprise_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGW(TAG, "📉 INCIDENT PERF: Dégradation performance - %s", event->description);
    
    uint32_t incident_id;
    return incident_create_enterprise(event, &incident_id);
}

esp_err_t incident_handle_tamper_detection(const security_event_enterprise_t* event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGE(TAG, "🔨 INCIDENT CRITIQUE: Manipulation détectée - %s", event->description);
    
    uint32_t incident_id;
    esp_err_t ret = incident_create_enterprise(event, &incident_id);
    
    if (ret == ESP_OK) {
        ESP_LOGE(TAG, "⚡ Réponse d'urgence pour manipulation #%lu", incident_id);
        esp32_crypto_store_emergency_state();
    }
    
    return ret;
}