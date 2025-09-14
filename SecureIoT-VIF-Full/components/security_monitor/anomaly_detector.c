/**
 * @file anomaly_detector.c
 * @brief Implémentation du détecteur d'anomalies comportementales
 */

#include "anomaly_detector.h"
#include "app_config.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <math.h>

static const char *TAG = "ANOMALY_DETECTOR";
static bool g_detector_initialized = false;
static anomaly_context_t g_context;

esp_err_t anomaly_detector_init(void) {
    if (g_detector_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Initialisation détecteur d'anomalies");
    
    memset(&g_context, 0, sizeof(anomaly_context_t));
    g_context.is_learning = true;
    g_context.learning_start_time = esp_timer_get_time();
    
    g_detector_initialized = true;
    
    ESP_LOGI(TAG, "Détecteur d'anomalies initialisé (mode apprentissage)");
    return ESP_OK;
}

esp_err_t anomaly_detector_deinit(void) {
    if (!g_detector_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Dé-initialisation détecteur d'anomalies");
    g_detector_initialized = false;
    
    return ESP_OK;
}

static float calculate_zscore(float value, float mean, float std_dev) {
    if (std_dev == 0.0f) return 0.0f;
    return fabsf((value - mean) / std_dev);
}

static void calculate_statistics(float* data, uint32_t count, float* mean, float* std_dev) {
    if (count == 0) {
        *mean = 0.0f;
        *std_dev = 0.0f;
        return;
    }
    
    // Calcul de la moyenne
    float sum = 0.0f;
    for (uint32_t i = 0; i < count; i++) {
        sum += data[i];
    }
    *mean = sum / count;
    
    // Calcul de l'écart-type
    if (count > 1) {
        float variance = 0.0f;
        for (uint32_t i = 0; i < count; i++) {
            float diff = data[i] - *mean;
            variance += diff * diff;
        }
        variance /= (count - 1);
        *std_dev = sqrtf(variance);
    } else {
        *std_dev = 0.0f;
    }
}

anomaly_result_t anomaly_detect_sensor_data(const sensor_data_t* data) {
    anomaly_result_t result = {0};
    
    if (!g_detector_initialized || !data || !data->is_valid) {
        result.type = ANOMALY_TYPE_NONE;
        return result;
    }
    
    uint64_t start_time = esp_timer_get_time();
    
    // Ajouter les nouvelles données à l'historique
    anomaly_update_baseline(data);
    
    // Si en mode apprentissage, pas de détection d'anomalie
    if (g_context.is_learning) {
        uint64_t learning_time = esp_timer_get_time() - g_context.learning_start_time;
        if (learning_time < ANOMALY_LEARNING_PERIOD_MS * 1000) {
            result.type = ANOMALY_TYPE_NONE;
            result.is_anomaly = false;
            return result;
        } else {
            // Fin de la période d'apprentissage
            g_context.is_learning = false;
            ESP_LOGI(TAG, "Fin période d'apprentissage - détection active");
        }
    }
    
    // Besoin d'au moins 10 échantillons pour la détection
    if (g_context.sample_count < ANOMALY_WINDOW_SIZE) {
        result.type = ANOMALY_TYPE_NONE;
        return result;
    }
    
    // Extraction des données historiques pour analyse
    uint32_t analysis_count = MIN(g_context.sample_count, ANOMALY_HISTORY_SIZE);
    float temp_data[ANOMALY_HISTORY_SIZE];
    float humidity_data[ANOMALY_HISTORY_SIZE];
    
    for (uint32_t i = 0; i < analysis_count; i++) {
        temp_data[i] = g_context.sensor_data[i][0];
        humidity_data[i] = g_context.sensor_data[i][1];
    }
    
    // Calcul des statistiques
    float temp_mean, temp_std, humidity_mean, humidity_std;
    calculate_statistics(temp_data, analysis_count, &temp_mean, &temp_std);
    calculate_statistics(humidity_data, analysis_count, &humidity_mean, &humidity_std);
    
    // Calcul des Z-scores pour la détection d'anomalie
    float temp_zscore = calculate_zscore(data->temperature, temp_mean, temp_std);
    float humidity_zscore = calculate_zscore(data->humidity, humidity_mean, humidity_std);
    
    // Score d'anomalie combiné (max des deux Z-scores normalisé)
    float max_zscore = fmaxf(temp_zscore, humidity_zscore);
    result.anomaly_score = fminf(max_zscore / 3.0f, 1.0f); // Normalisation avec seuil à 3 sigma
    
    // Détection d'anomalie basée sur le seuil
    result.is_anomaly = (result.anomaly_score > ANOMALY_SCORE_THRESHOLD);
    result.type = result.is_anomaly ? ANOMALY_TYPE_SENSOR_DATA : ANOMALY_TYPE_NONE;
    result.timestamp = data->timestamp;
    
    // Détermination de la sévérité
    if (result.is_anomaly) {
        if (result.anomaly_score > 0.9f) {
            result.severity = 4; // Critical
        } else if (result.anomaly_score > 0.7f) {
            result.severity = 3; // High
        } else if (result.anomaly_score > 0.5f) {
            result.severity = 2; // Medium
        } else {
            result.severity = 1; // Low
        }
        
        snprintf(result.description, sizeof(result.description),
                 "Anomalie capteur: T=%.1f°C (Z=%.2f), H=%.1f%% (Z=%.2f)",
                 data->temperature, temp_zscore, data->humidity, humidity_zscore);
        
        ESP_LOGW(TAG, "%s", result.description);
    }
    
    result.detection_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    
    return result;
}

anomaly_result_t anomaly_detect_system_behavior(void) {
    anomaly_result_t result = {0};
    
    if (!g_detector_initialized) {
        result.type = ANOMALY_TYPE_NONE;
        return result;
    }
    
    uint64_t start_time = esp_timer_get_time();
    
    // Analyse du comportement système (exemple simplifié)
    // Dans une implémentation complète, analyserait :
    // - Utilisation CPU/mémoire
    // - Patterns de communication
    // - Fréquence des opérations cryptographiques
    // - Temps de réponse
    
    // Pour cette démo, simulation d'une détection basique
    static uint32_t last_check_time = 0;
    uint32_t current_time = (uint32_t)(esp_timer_get_time() / 1000000);
    
    if (last_check_time > 0) {
        uint32_t time_diff = current_time - last_check_time;
        
        // Détection d'un intervalle anormalement long
        if (time_diff > 60) { // Plus d'une minute
            result.is_anomaly = true;
            result.type = ANOMALY_TYPE_SYSTEM_BEHAVIOR;
            result.anomaly_score = 0.6f;
            result.severity = 2; // Medium
            result.timestamp = current_time;
            
            snprintf(result.description, sizeof(result.description),
                     "Comportement système anormal: intervalle %lu s", time_diff);
            
            ESP_LOGW(TAG, "%s", result.description);
        }
    }
    
    last_check_time = current_time;
    result.detection_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    
    return result;
}

esp_err_t anomaly_update_baseline(const sensor_data_t* data) {
    if (!g_detector_initialized || !data || !data->is_valid) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Ajout des données à l'historique circulaire
    uint32_t index = g_context.write_index;
    g_context.sensor_data[index][0] = data->temperature;
    g_context.sensor_data[index][1] = data->humidity;
    g_context.timestamps[index] = data->timestamp;
    
    g_context.write_index = (g_context.write_index + 1) % ANOMALY_HISTORY_SIZE;
    if (g_context.sample_count < ANOMALY_HISTORY_SIZE) {
        g_context.sample_count++;
    }
    
    ESP_LOGD(TAG, "Baseline mis à jour: %lu échantillons", g_context.sample_count);
    return ESP_OK;
}

esp_err_t anomaly_set_learning_mode(bool enable) {
    if (!g_detector_initialized) return ESP_ERR_INVALID_STATE;
    
    g_context.is_learning = enable;
    if (enable) {
        g_context.learning_start_time = esp_timer_get_time();
        ESP_LOGI(TAG, "Mode apprentissage activé");
    } else {
        ESP_LOGI(TAG, "Mode apprentissage désactivé");
    }
    
    return ESP_OK;
}

bool anomaly_is_learning_mode(void) {
    return g_context.is_learning;
}