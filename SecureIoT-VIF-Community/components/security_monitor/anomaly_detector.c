/**
 * @file anomaly_detector.c
 * @brief Détecteur d'anomalies simplifié pour SecureIoT-VIF Community Edition
 * 
 * Version de base utilisant uniquement des seuils fixes (pas de ML adaptatif).
 * Idéale pour comprendre les concepts de détection d'anomalies.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "anomaly_detector.h"

static const char *TAG = "ANOMALY_COMMUNITY";

// Variables globales du détecteur Community
static bool anomaly_detector_initialized = false;
static anomaly_stats_community_t anomaly_stats = {0};
static sensor_data_t history_buffer[ANOMALY_HISTORY_SIZE_COMMUNITY];
static size_t history_index = 0;
static size_t history_count = 0;

// Seuils par défaut Community (plus tolérants)
static anomaly_thresholds_t current_thresholds = {
    .temp_min = 5.0f,           // Plus large que Enterprise
    .temp_max = 45.0f,          // Plus large que Enterprise
    .humidity_min = 10.0f,      // Plus large que Enterprise
    .humidity_max = 90.0f,      // Plus large que Enterprise
    .temp_change_max = 10.0f,   // Plus tolérant
    .humidity_change_max = 20.0f // Plus tolérant
};

/**
 * @brief Initialise le détecteur d'anomalies Community
 */
esp_err_t anomaly_detector_basic_init(void) {
    if (anomaly_detector_initialized) {
        ESP_LOGW(TAG, "Détecteur d'anomalies déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "🤖 Initialisation détecteur d'anomalies Community");
    ESP_LOGI(TAG, "💡 Version éducative - Seuils fixes seulement");
    
    // Réinitialiser les statistiques et l'historique
    memset(&anomaly_stats, 0, sizeof(anomaly_stats));
    memset(history_buffer, 0, sizeof(history_buffer));
    history_index = 0;
    history_count = 0;
    
    anomaly_stats.init_time = esp_timer_get_time() / 1000;
    
    anomaly_detector_initialized = true;
    ESP_LOGI(TAG, "✅ Détecteur d'anomalies Community initialisé");
    ESP_LOGI(TAG, "🎓 Méthode: Seuils fixes pour apprentissage");
    
    return ESP_OK;
}

/**
 * @brief Deinitialise le détecteur d'anomalies
 */
esp_err_t anomaly_detector_basic_deinit(void) {
    if (!anomaly_detector_initialized) {
        return ESP_OK;
    }
    
    anomaly_detector_initialized = false;
    ESP_LOGI(TAG, "🔓 Détecteur d'anomalies Community déinitialisé");
    
    return ESP_OK;
}

/**
 * @brief Détection d'anomalies par seuils fixes (Community)
 */
anomaly_result_t anomaly_detect_threshold_based(const sensor_data_t *data) {
    anomaly_result_t result = {0};
    
    if (!anomaly_detector_initialized) {
        ESP_LOGE(TAG, "❌ Détecteur non initialisé");
        result.is_anomaly = false;
        result.anomaly_score = 0.0f;
        result.error_code = ANOMALY_ERROR_NOT_INITIALIZED;
        return result;
    }
    
    if (data == NULL) {
        ESP_LOGE(TAG, "❌ Données invalides");
        result.is_anomaly = false;
        result.anomaly_score = 0.0f;
        result.error_code = ANOMALY_ERROR_INVALID_DATA;
        return result;
    }
    
    ESP_LOGD(TAG, "🔍 Analyse anomalies par seuils: T=%.1f°C, H=%.1f%%",
             data->temperature, data->humidity);
    
    anomaly_stats.total_analyses++;
    
    bool temp_anomaly = false;
    bool humidity_anomaly = false;
    bool change_anomaly = false;
    float anomaly_score = 0.0f;
    
    // 1. Vérification seuils absolus
    if (data->temperature < current_thresholds.temp_min || 
        data->temperature > current_thresholds.temp_max) {
        temp_anomaly = true;
        anomaly_score += 0.4f; // 40% du score
        ESP_LOGD(TAG, "🌡️ Anomalie température: %.1f°C hors [%.1f, %.1f]",
                 data->temperature, current_thresholds.temp_min, current_thresholds.temp_max);
    }
    
    if (data->humidity < current_thresholds.humidity_min || 
        data->humidity > current_thresholds.humidity_max) {
        humidity_anomaly = true;
        anomaly_score += 0.4f; // 40% du score
        ESP_LOGD(TAG, "💧 Anomalie humidité: %.1f%% hors [%.1f, %.1f]",
                 data->humidity, current_thresholds.humidity_min, current_thresholds.humidity_max);
    }
    
    // 2. Vérification changements rapides (si historique disponible)
    if (history_count > 0) {
        sensor_data_t *last_data = &history_buffer[(history_index - 1 + ANOMALY_HISTORY_SIZE_COMMUNITY) % ANOMALY_HISTORY_SIZE_COMMUNITY];
        
        float temp_change = fabsf(data->temperature - last_data->temperature);
        float humidity_change = fabsf(data->humidity - last_data->humidity);
        
        if (temp_change > current_thresholds.temp_change_max) {
            change_anomaly = true;
            anomaly_score += 0.1f; // 10% du score
            ESP_LOGD(TAG, "📈 Changement rapide température: %.1f°C (seuil=%.1f°C)",
                     temp_change, current_thresholds.temp_change_max);
        }
        
        if (humidity_change > current_thresholds.humidity_change_max) {
            change_anomaly = true;
            anomaly_score += 0.1f; // 10% du score
            ESP_LOGD(TAG, "📈 Changement rapide humidité: %.1f%% (seuil=%.1f%%)",
                     humidity_change, current_thresholds.humidity_change_max);
        }
    }
    
    // 3. Déterminer si c'est une anomalie
    bool is_anomaly = temp_anomaly || humidity_anomaly || change_anomaly;
    
    // Remplir le résultat
    result.is_anomaly = is_anomaly;
    result.anomaly_score = anomaly_score;
    result.timestamp = data->timestamp;
    result.temperature = data->temperature;
    result.humidity = data->humidity;
    result.error_code = ANOMALY_SUCCESS;
    
    // Détails des anomalies détectées
    result.temp_anomaly = temp_anomaly;
    result.humidity_anomaly = humidity_anomaly;
    result.change_anomaly = change_anomaly;
    
    // Mettre à jour les statistiques
    if (is_anomaly) {
        anomaly_stats.anomalies_detected++;
        anomaly_stats.last_anomaly_time = data->timestamp;
        ESP_LOGW(TAG, "🚨 Anomalie détectée: score=%.3f, T=%s, H=%s, Δ=%s",
                 anomaly_score,
                 temp_anomaly ? "OUI" : "non",
                 humidity_anomaly ? "OUI" : "non", 
                 change_anomaly ? "OUI" : "non");
    } else {
        anomaly_stats.normal_analyses++;
        ESP_LOGD(TAG, "✅ Données normales: score=%.3f", anomaly_score);
    }
    
    // Ajouter à l'historique
    history_buffer[history_index] = *data;
    history_index = (history_index + 1) % ANOMALY_HISTORY_SIZE_COMMUNITY;
    if (history_count < ANOMALY_HISTORY_SIZE_COMMUNITY) {
        history_count++;
    }
    
    return result;
}

/**
 * @brief Configure les seuils de détection Community
 */
esp_err_t anomaly_set_thresholds_community(const anomaly_thresholds_t *thresholds) {
    if (!anomaly_detector_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (thresholds == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Validation des seuils
    if (thresholds->temp_min >= thresholds->temp_max ||
        thresholds->humidity_min >= thresholds->humidity_max) {
        ESP_LOGE(TAG, "❌ Seuils invalides: min >= max");
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(&current_thresholds, thresholds, sizeof(anomaly_thresholds_t));
    
    ESP_LOGI(TAG, "⚙️ Seuils Community mis à jour:");
    ESP_LOGI(TAG, "  🌡️ Température: [%.1f, %.1f]°C, Δmax=%.1f°C",
             current_thresholds.temp_min, current_thresholds.temp_max,
             current_thresholds.temp_change_max);
    ESP_LOGI(TAG, "  💧 Humidité: [%.1f, %.1f]%%, Δmax=%.1f%%",
             current_thresholds.humidity_min, current_thresholds.humidity_max,
             current_thresholds.humidity_change_max);
    
    return ESP_OK;
}

/**
 * @brief Obtient les seuils actuels
 */
esp_err_t anomaly_get_thresholds_community(anomaly_thresholds_t *thresholds) {
    if (!anomaly_detector_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (thresholds == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(thresholds, &current_thresholds, sizeof(anomaly_thresholds_t));
    return ESP_OK;
}

/**
 * @brief Obtient les statistiques du détecteur Community
 */
esp_err_t anomaly_get_stats_community(anomaly_stats_community_t *stats) {
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!anomaly_detector_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memcpy(stats, &anomaly_stats, sizeof(anomaly_stats_community_t));
    return ESP_OK;
}

/**
 * @brief Affiche les statistiques du détecteur Community
 */
void anomaly_print_stats_community(void) {
    if (!anomaly_detector_initialized) {
        ESP_LOGW(TAG, "Détecteur non initialisé");
        return;
    }
    
    ESP_LOGI(TAG, "📊 === Statistiques Anomalies Community ===");
    ESP_LOGI(TAG, "Analyses totales: %d", anomaly_stats.total_analyses);
    ESP_LOGI(TAG, "Analyses normales: %d", anomaly_stats.normal_analyses);
    ESP_LOGI(TAG, "Anomalies détectées: %d", anomaly_stats.anomalies_detected);
    
    if (anomaly_stats.total_analyses > 0) {
        float anomaly_rate = (float)anomaly_stats.anomalies_detected / 
                            anomaly_stats.total_analyses * 100.0f;
        ESP_LOGI(TAG, "Taux d'anomalies: %.2f%%", anomaly_rate);
    }
    
    if (anomaly_stats.anomalies_detected > 0) {
        uint64_t last_anomaly_ago = (esp_timer_get_time() / 1000) - anomaly_stats.last_anomaly_time;
        ESP_LOGI(TAG, "Dernière anomalie: il y a %lld ms", last_anomaly_ago);
    }
    
    uint64_t uptime = (esp_timer_get_time() / 1000) - anomaly_stats.init_time;
    ESP_LOGI(TAG, "Temps de fonctionnement: %lld ms", uptime);
    ESP_LOGI(TAG, "Taille historique: %d/%d", history_count, ANOMALY_HISTORY_SIZE_COMMUNITY);
    
    ESP_LOGI(TAG, "Seuils actuels:");
    ESP_LOGI(TAG, "  🌡️ T: [%.1f, %.1f]°C, Δ%.1f°C",
             current_thresholds.temp_min, current_thresholds.temp_max,
             current_thresholds.temp_change_max);
    ESP_LOGI(TAG, "  💧 H: [%.1f, %.1f]%%, Δ%.1f%%",
             current_thresholds.humidity_min, current_thresholds.humidity_max,
             current_thresholds.humidity_change_max);
    
    ESP_LOGI(TAG, "======================================");
}

/**
 * @brief Réinitialise les statistiques du détecteur
 */
esp_err_t anomaly_reset_stats_community(void) {
    if (!anomaly_detector_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memset(&anomaly_stats, 0, sizeof(anomaly_stats));
    memset(history_buffer, 0, sizeof(history_buffer));
    history_index = 0;
    history_count = 0;
    anomaly_stats.init_time = esp_timer_get_time() / 1000;
    
    ESP_LOGI(TAG, "🔄 Statistiques détecteur anomalies réinitialisées");
    return ESP_OK;
}

/**
 * @brief Test de fonctionnement du détecteur Community
 */
esp_err_t anomaly_detector_self_test(void) {
    ESP_LOGI(TAG, "🧪 Auto-test détecteur d'anomalies Community...");
    
    // Test d'initialisation
    esp_err_t ret = anomaly_detector_basic_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation");
        return ret;
    }
    
    // Test avec données normales
    sensor_data_t normal_data = {
        .temperature = 22.5f,
        .humidity = 55.0f,
        .timestamp = esp_timer_get_time() / 1000,
        .read_duration_ms = 100,
        .quality_score = 95
    };
    
    anomaly_result_t result = anomaly_detect_threshold_based(&normal_data);
    if (result.error_code != ANOMALY_SUCCESS) {
        ESP_LOGE(TAG, "❌ Erreur détection données normales");
        return ESP_FAIL;
    }
    
    if (result.is_anomaly) {
        ESP_LOGW(TAG, "⚠️ Données normales détectées comme anomalie (vérifier seuils)");
    } else {
        ESP_LOGI(TAG, "✅ Données normales correctement identifiées");
    }
    
    // Test avec données anormales
    sensor_data_t anomaly_data = {
        .temperature = 60.0f,  // Hors seuils
        .humidity = 95.0f,     // Hors seuils
        .timestamp = esp_timer_get_time() / 1000,
        .read_duration_ms = 100,
        .quality_score = 50
    };
    
    result = anomaly_detect_threshold_based(&anomaly_data);
    if (result.error_code != ANOMALY_SUCCESS) {
        ESP_LOGE(TAG, "❌ Erreur détection données anormales");
        return ESP_FAIL;
    }
    
    if (!result.is_anomaly) {
        ESP_LOGW(TAG, "⚠️ Anomalie non détectée (vérifier seuils)");
    } else {
        ESP_LOGI(TAG, "✅ Anomalie correctement détectée: score=%.3f", result.anomaly_score);
    }
    
    // Test des statistiques
    anomaly_stats_community_t stats;
    ret = anomaly_get_stats_community(&stats);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec récupération statistiques");
        return ret;
    }
    
    ESP_LOGI(TAG, "✅ Auto-test détecteur Community réussi");
    ESP_LOGI(TAG, "💡 Détection par seuils fixes opérationnelle");
    
    return ESP_OK;
}

/**
 * @brief Affiche les informations du détecteur Community
 */
void anomaly_detector_print_info(void) {
    ESP_LOGI(TAG, "📋 === Détecteur Anomalies Community ===");
    ESP_LOGI(TAG, "Édition: Community (Éducative)");
    ESP_LOGI(TAG, "Méthode: Seuils fixes seulement");
    ESP_LOGI(TAG, "Historique: %d échantillons", ANOMALY_HISTORY_SIZE_COMMUNITY);
    ESP_LOGI(TAG, "Fonctionnalités disponibles:");
    ESP_LOGI(TAG, "  ✅ Détection par seuils absolus");
    ESP_LOGI(TAG, "  ✅ Détection changements rapides");
    ESP_LOGI(TAG, "  ✅ Configuration seuils personnalisés");
    ESP_LOGI(TAG, "  ✅ Statistiques détaillées");
    ESP_LOGI(TAG, "  ✅ Historique simple");
    ESP_LOGI(TAG, "Limitations Community:");
    ESP_LOGI(TAG, "  ❌ Pas d'apprentissage automatique");
    ESP_LOGI(TAG, "  ❌ Pas d'adaptation comportementale");
    ESP_LOGI(TAG, "  ❌ Seuils fixes uniquement");
    ESP_LOGI(TAG, "  ❌ Historique limité");
    ESP_LOGI(TAG, "🎓 Idéal pour comprendre la détection!");
    ESP_LOGI(TAG, "======================================");
}