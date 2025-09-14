/**
 * @file incident_manager.c
 * @brief Gestionnaire d'incidents pour SecureIoT-VIF Community Edition
 * 
 * Version simplifiée pour la gestion des incidents de sécurité.
 * Basé sur le fichier original avec adaptations Community.
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
#include "incident_manager.h"

static const char *TAG = "INCIDENT_COMMUNITY";

// Variables globales du gestionnaire d'incidents Community
static bool incident_manager_initialized = false;
static incident_stats_t incident_stats = {0};

/**
 * @brief Initialise le gestionnaire d'incidents Community
 */
esp_err_t incident_manager_init(void) {
    if (incident_manager_initialized) {
        ESP_LOGW(TAG, "Gestionnaire d'incidents déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "🚨 Initialisation gestionnaire d'incidents Community");
    ESP_LOGI(TAG, "💡 Version éducative - Gestion basique des incidents");
    
    // Réinitialiser les statistiques
    memset(&incident_stats, 0, sizeof(incident_stats));
    incident_stats.init_time = esp_timer_get_time() / 1000;
    
    incident_manager_initialized = true;
    ESP_LOGI(TAG, "✅ Gestionnaire d'incidents Community initialisé");
    
    return ESP_OK;
}

/**
 * @brief Gestion d'un échec de vérification d'intégrité
 */
esp_err_t incident_handle_integrity_failure(const void *event_data) {
    if (!incident_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGE(TAG, "🔴 INCIDENT: Échec vérification d'intégrité");
    
    incident_stats.integrity_failures++;
    incident_stats.total_incidents++;
    incident_stats.last_incident_time = esp_timer_get_time() / 1000;
    
    // Actions Community (simplifiées)
    ESP_LOGI(TAG, "📋 Actions Community:");
    ESP_LOGI(TAG, "  1. 📝 Logging de l'incident");
    ESP_LOGI(TAG, "  2. 📊 Mise à jour des statistiques");
    ESP_LOGI(TAG, "  3. ⚠️  Notification console");
    ESP_LOGI(TAG, "  4. 🎓 Fin - Version éducative");
    
    // Pas d'actions critiques en Community (redémarrage, etc.)
    ESP_LOGI(TAG, "💡 En Enterprise: redémarrage automatique disponible");
    
    return ESP_OK;
}

/**
 * @brief Gestion d'une anomalie détectée
 */
esp_err_t incident_handle_anomaly(const void *event_data) {
    if (!incident_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGW(TAG, "🟡 INCIDENT: Anomalie détectée");
    
    incident_stats.anomalies_handled++;
    incident_stats.total_incidents++;
    incident_stats.last_incident_time = esp_timer_get_time() / 1000;
    
    // Actions Community pour anomalies
    ESP_LOGI(TAG, "📋 Actions anomalie Community:");
    ESP_LOGI(TAG, "  1. 📝 Log de l'anomalie");
    ESP_LOGI(TAG, "  2. 📊 Mise à jour compteurs");
    ESP_LOGI(TAG, "  3. 🔍 Analyse basique (seuils)");
    ESP_LOGI(TAG, "  4. 🎓 Fin - Version éducative");
    
    ESP_LOGI(TAG, "💡 En Enterprise: ML adaptatif et actions automatiques");
    
    return ESP_OK;
}

/**
 * @brief Gestion d'un échec d'attestation (pas disponible en Community)
 */
esp_err_t incident_handle_attestation_failure(const void *event_data) {
    if (!incident_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGW(TAG, "🟠 INCIDENT: Échec attestation (non supporté en Community)");
    ESP_LOGI(TAG, "💡 L'attestation continue est disponible en Enterprise Edition");
    ESP_LOGI(TAG, "🎓 Community Edition: apprentissage des concepts de base");
    
    return ESP_OK;
}

/**
 * @brief Gestion d'un accès non autorisé
 */
esp_err_t incident_handle_unauthorized_access(const void *event_data) {
    if (!incident_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGE(TAG, "🔴 INCIDENT: Accès non autorisé détecté");
    
    incident_stats.security_violations++;
    incident_stats.total_incidents++;
    incident_stats.last_incident_time = esp_timer_get_time() / 1000;
    
    // Actions Community (éducatives)
    ESP_LOGI(TAG, "📋 Actions sécurité Community:");
    ESP_LOGI(TAG, "  1. 📝 Log sécurité détaillé");
    ESP_LOGI(TAG, "  2. 🚨 Alerte console");
    ESP_LOGI(TAG, "  3. 📊 Statistiques sécurité");
    ESP_LOGI(TAG, "  4. 🎓 Démonstration éducative");
    
    ESP_LOGI(TAG, "💡 En Enterprise: blocage automatique et audit");
    
    return ESP_OK;
}

/**
 * @brief Obtient les statistiques des incidents
 */
esp_err_t incident_get_stats(incident_stats_t *stats) {
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!incident_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memcpy(stats, &incident_stats, sizeof(incident_stats_t));
    return ESP_OK;
}

/**
 * @brief Affiche les statistiques des incidents
 */
void incident_print_stats(void) {
    if (!incident_manager_initialized) {
        ESP_LOGW(TAG, "Gestionnaire non initialisé");
        return;
    }
    
    ESP_LOGI(TAG, "📊 === Statistiques Incidents Community ===");
    ESP_LOGI(TAG, "Incidents totaux: %d", incident_stats.total_incidents);
    ESP_LOGI(TAG, "Échecs intégrité: %d", incident_stats.integrity_failures);
    ESP_LOGI(TAG, "Anomalies gérées: %d", incident_stats.anomalies_handled);
    ESP_LOGI(TAG, "Violations sécurité: %d", incident_stats.security_violations);
    ESP_LOGI(TAG, "Autres incidents: %d", incident_stats.other_incidents);
    
    if (incident_stats.total_incidents > 0) {
        uint64_t last_incident_ago = (esp_timer_get_time() / 1000) - incident_stats.last_incident_time;
        ESP_LOGI(TAG, "Dernier incident: il y a %lld ms", last_incident_ago);
    } else {
        ESP_LOGI(TAG, "✅ Aucun incident détecté");
    }
    
    uint64_t uptime = (esp_timer_get_time() / 1000) - incident_stats.init_time;
    ESP_LOGI(TAG, "Temps de surveillance: %lld ms", uptime);
    
    ESP_LOGI(TAG, "========================================");
}

/**
 * @brief Réinitialise les statistiques des incidents
 */
esp_err_t incident_reset_stats(void) {
    if (!incident_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memset(&incident_stats, 0, sizeof(incident_stats));
    incident_stats.init_time = esp_timer_get_time() / 1000;
    
    ESP_LOGI(TAG, "🔄 Statistiques incidents réinitialisées");
    return ESP_OK;
}

/**
 * @brief Test de fonctionnement du gestionnaire Community
 */
esp_err_t incident_manager_self_test(void) {
    ESP_LOGI(TAG, "🧪 Auto-test gestionnaire d'incidents Community...");
    
    // Test d'initialisation
    esp_err_t ret = incident_manager_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation");
        return ret;
    }
    
    // Test simulation incident intégrité
    ESP_LOGI(TAG, "🧪 Test simulation échec intégrité...");
    ret = incident_handle_integrity_failure(NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec gestion incident intégrité");
        return ret;
    }
    
    // Test simulation anomalie
    ESP_LOGI(TAG, "🧪 Test simulation anomalie...");
    ret = incident_handle_anomaly(NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec gestion anomalie");
        return ret;
    }
    
    // Test des statistiques
    incident_stats_t stats;
    ret = incident_get_stats(&stats);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec récupération statistiques");
        return ret;
    }
    
    // Vérifier que les incidents de test ont été comptés
    if (stats.total_incidents < 2) {
        ESP_LOGE(TAG, "❌ Statistiques incorrectes après simulation");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "✅ Auto-test gestionnaire incidents réussi");
    ESP_LOGI(TAG, "💡 Gestion basique des incidents opérationnelle");
    
    return ESP_OK;
}

/**
 * @brief Affiche les informations du gestionnaire Community
 */
void incident_manager_print_info(void) {
    ESP_LOGI(TAG, "📋 === Gestionnaire Incidents Community ===");
    ESP_LOGI(TAG, "Édition: Community (Éducative)");
    ESP_LOGI(TAG, "Type: Gestion basique des incidents");
    ESP_LOGI(TAG, "Fonctionnalités disponibles:");
    ESP_LOGI(TAG, "  ✅ Gestion échecs intégrité");
    ESP_LOGI(TAG, "  ✅ Gestion anomalies capteurs");
    ESP_LOGI(TAG, "  ✅ Logging et statistiques");
    ESP_LOGI(TAG, "  ✅ Notifications console");
    ESP_LOGI(TAG, "Limitations Community:");
    ESP_LOGI(TAG, "  ❌ Pas d'actions automatiques");
    ESP_LOGI(TAG, "  ❌ Pas de redémarrage auto");
    ESP_LOGI(TAG, "  ❌ Pas d'escalade d'incidents");
    ESP_LOGI(TAG, "  ❌ Pas de notifications externes");
    ESP_LOGI(TAG, "🎓 Version éducative pour comprendre la gestion!");
    ESP_LOGI(TAG, "============================================");
}