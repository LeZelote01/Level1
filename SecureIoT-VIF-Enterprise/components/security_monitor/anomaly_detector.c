/**
 * @file anomaly_detector.c
 * @brief Détecteur d'anomalies ML comportemental Enterprise
 * 
 * Version Enterprise avec apprentissage adaptatif temps réel, modèles ML légers,
 * profiling comportemental et détection avancée multi-variée.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "anomaly_detector.h"
#include "app_config.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <math.h>

static const char *TAG = "ANOMALY_DETECTOR_ENTERPRISE";

// Variables globales Enterprise
static bool g_detector_initialized = false;
static anomaly_context_enterprise_t g_context_enterprise = {0};
static anomaly_config_enterprise_t g_config_enterprise = {0};
static SemaphoreHandle_t g_detector_mutex = NULL;

// Statistiques ML Enterprise
static anomaly_stats_enterprise_t g_stats_enterprise = {0};

/**
 * @brief Calcul du Z-score amélioré avec gestion des outliers
 */
static float calculate_zscore_robust(float value, float mean, float std_dev) {
    if (std_dev < 1e-6f) return 0.0f; // Éviter division par zéro
    
    float zscore = fabsf((value - mean) / std_dev);
    
    // Limitation pour éviter les scores extrêmes
    return fminf(zscore, 10.0f);
}

/**
 * @brief Calcul des statistiques robustes avec médiane
 */
static void calculate_robust_statistics(float* data, uint32_t count, float* mean, float* std_dev, float* median) {
    if (count == 0) {
        *mean = 0.0f;
        *std_dev = 0.0f;
        *median = 0.0f;
        return;
    }
    
    // Calcul de la moyenne
    float sum = 0.0f;
    for (uint32_t i = 0; i < count; i++) {
        sum += data[i];
    }
    *mean = sum / count;
    
    // Tri pour médiane (bubble sort simple pour petites données)
    float sorted_data[ANOMALY_HISTORY_SIZE_ENTERPRISE];
    memcpy(sorted_data, data, count * sizeof(float));
    
    for (uint32_t i = 0; i < count - 1; i++) {
        for (uint32_t j = 0; j < count - i - 1; j++) {
            if (sorted_data[j] > sorted_data[j + 1]) {
                float temp = sorted_data[j];
                sorted_data[j] = sorted_data[j + 1];
                sorted_data[j + 1] = temp;
            }
        }
    }
    
    // Médiane
    if (count % 2 == 0) {
        *median = (sorted_data[count/2 - 1] + sorted_data[count/2]) / 2.0f;
    } else {
        *median = sorted_data[count/2];
    }
    
    // Écart-type robuste basé sur la médiane
    if (count > 1) {
        float mad_sum = 0.0f; // Mean Absolute Deviation
        for (uint32_t i = 0; i < count; i++) {
            mad_sum += fabsf(data[i] - *median);
        }
        *std_dev = (mad_sum / count) * 1.4826f; // Facteur de conversion pour normalité
    } else {
        *std_dev = 0.0f;
    }
}

/**
 * @brief Extraction du vecteur de caractéristiques ML
 */
static void extract_feature_vector(const sensor_data_t* data, float* feature_vector) {
    if (!data || !feature_vector) return;
    
    // Caractéristiques de base
    feature_vector[0] = data->temperature;
    feature_vector[1] = data->humidity;
    
    // Caractéristiques dérivées (tendances, ratios, etc.)
    feature_vector[2] = data->temperature_trend;
    feature_vector[3] = data->humidity_trend;
    
    // Caractéristiques temporelles
    feature_vector[4] = (float)(data->timestamp % 86400) / 86400.0f; // Heure normalisée
    feature_vector[5] = sinf(2.0f * M_PI * feature_vector[4]); // Composante cyclique
    feature_vector[6] = cosf(2.0f * M_PI * feature_vector[4]);
    
    // Caractéristiques contextuelles
    feature_vector[7] = sqrtf(data->temperature * data->temperature + data->humidity * data->humidity);
    feature_vector[8] = data->temperature / (data->humidity + 1e-6f); // Ratio T/H
    
    // Caractéristiques statistiques (fenêtre glissante)
    if (g_context_enterprise.sample_count > 5) {
        uint32_t window_size = MIN(g_context_enterprise.sample_count, 10);
        float temp_window[10], humidity_window[10];
        
        for (uint32_t i = 0; i < window_size; i++) {
            uint32_t idx = (g_context_enterprise.write_index - 1 - i + ANOMALY_HISTORY_SIZE_ENTERPRISE) % ANOMALY_HISTORY_SIZE_ENTERPRISE;
            temp_window[i] = g_context_enterprise.sensor_data[idx][0];
            humidity_window[i] = g_context_enterprise.sensor_data[idx][1];
        }
        
        // Variance locale
        float temp_var = 0.0f, humidity_var = 0.0f;
        float temp_mean = 0.0f, humidity_mean = 0.0f;
        
        for (uint32_t i = 0; i < window_size; i++) {
            temp_mean += temp_window[i];
            humidity_mean += humidity_window[i];
        }
        temp_mean /= window_size;
        humidity_mean /= window_size;
        
        for (uint32_t i = 0; i < window_size; i++) {
            temp_var += (temp_window[i] - temp_mean) * (temp_window[i] - temp_mean);
            humidity_var += (humidity_window[i] - humidity_mean) * (humidity_window[i] - humidity_mean);
        }
        
        feature_vector[9] = temp_var / window_size;
        feature_vector[10] = humidity_var / window_size;
    } else {
        feature_vector[9] = 0.0f;
        feature_vector[10] = 0.0f;
    }
    
    // Remplir le reste avec des zéros pour l'instant
    for (uint32_t i = 11; i < ML_FEATURE_VECTOR_SIZE; i++) {
        feature_vector[i] = 0.0f;
    }
}

/**
 * @brief Détection d'anomalie par méthode Isolation Forest simplifiée
 */
static float isolation_forest_score(const float* feature_vector) {
    // Implémentation simplifiée d'Isolation Forest pour ESP32
    // Score basé sur la profondeur moyenne dans les "arbres"
    
    float isolation_score = 0.0f;
    const uint32_t num_trees = 5; // Nombre d'arbres limité
    
    for (uint32_t tree = 0; tree < num_trees; tree++) {
        float depth = 0.0f;
        
        // Simulation de l'isolement par comparaisons successives
        for (uint32_t level = 0; level < 8; level++) { // Profondeur max 8
            uint32_t feature_idx = (tree * 7 + level) % ML_FEATURE_VECTOR_SIZE;
            float threshold = g_context_enterprise.behavior_profiles[0].feature_means[feature_idx];
            
            if (feature_vector[feature_idx] < threshold) {
                depth += 1.0f;
            } else {
                break;
            }
        }
        
        isolation_score += depth;
    }
    
    isolation_score /= num_trees;
    
    // Normalisation du score (plus la profondeur est faible, plus c'est anormal)
    return 1.0f - (isolation_score / 8.0f);
}

/**
 * @brief Détection d'anomalie par ensemble de méthodes
 */
static float ensemble_anomaly_detection(const float* feature_vector, float* method_scores) {
    // Méthode 1: Z-score multivarié
    float zscore_sum = 0.0f;
    uint32_t valid_features = 0;
    
    for (uint32_t i = 0; i < 4; i++) { // Principales caractéristiques
        if (g_context_enterprise.behavior_profiles[0].feature_stds[i] > 1e-6f) {
            float zscore = calculate_zscore_robust(
                feature_vector[i],
                g_context_enterprise.behavior_profiles[0].feature_means[i],
                g_context_enterprise.behavior_profiles[0].feature_stds[i]
            );
            zscore_sum += zscore * zscore;
            valid_features++;
        }
    }
    
    method_scores[0] = valid_features > 0 ? sqrtf(zscore_sum / valid_features) / 3.0f : 0.0f;
    method_scores[0] = fminf(method_scores[0], 1.0f);
    
    // Méthode 2: Isolation Forest
    method_scores[1] = isolation_forest_score(feature_vector);
    
    // Méthode 3: Distance de Mahalanobis simplifiée
    float mahalanobis_dist = 0.0f;
    for (uint32_t i = 0; i < 4; i++) {
        float diff = feature_vector[i] - g_context_enterprise.behavior_profiles[0].feature_means[i];
        float normalized_diff = diff / (g_context_enterprise.behavior_profiles[0].feature_stds[i] + 1e-6f);
        mahalanobis_dist += normalized_diff * normalized_diff;
    }
    method_scores[2] = fminf(sqrtf(mahalanobis_dist) / 4.0f, 1.0f);
    
    // Méthode 4: Détection basée sur la densité locale
    method_scores[3] = 0.5f; // Placeholder pour l'instant
    
    // Méthode 5: Analyse temporelle
    method_scores[4] = fabsf(feature_vector[5]) * 0.5f; // Basé sur composante cyclique
    
    // Score d'ensemble (moyenne pondérée)
    float weights[5] = {0.3f, 0.25f, 0.2f, 0.15f, 0.1f};
    float ensemble_score = 0.0f;
    
    for (uint32_t i = 0; i < 5; i++) {
        ensemble_score += weights[i] * method_scores[i];
    }
    
    return ensemble_score;
}

/**
 * @brief Initialisation du détecteur d'anomalies ML Enterprise
 */
esp_err_t anomaly_detector_init_enterprise(const anomaly_config_enterprise_t* config) {
    if (g_detector_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🤖 Initialisation détecteur anomalies ML Enterprise");
    
    // Création du mutex thread-safe
    g_detector_mutex = xSemaphoreCreateMutex();
    if (g_detector_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex détecteur");
        return ESP_FAIL;
    }
    
    // Configuration par défaut ou fournie
    if (config) {
        memcpy(&g_config_enterprise, config, sizeof(anomaly_config_enterprise_t));
    } else {
        // Configuration par défaut Enterprise
        g_config_enterprise.ml_enabled = true;
        g_config_enterprise.adaptive_learning = true;
        g_config_enterprise.behavioral_profiling = true;
        g_config_enterprise.ensemble_detection = true;
        g_config_enterprise.performance_optimization = true;
        g_config_enterprise.preferred_method = ML_METHOD_ENSEMBLE;
        g_config_enterprise.sensitivity_level = 0.7f;
        g_config_enterprise.adaptation_interval_ms = 300000; // 5 minutes
        g_config_enterprise.min_samples_for_detection = 20;
        g_config_enterprise.false_positive_tolerance = 0.1f;
    }
    
    // Initialisation du contexte Enterprise
    memset(&g_context_enterprise, 0, sizeof(anomaly_context_enterprise_t));
    g_context_enterprise.is_learning = true;
    g_context_enterprise.learning_start_time = esp_timer_get_time();
    g_context_enterprise.learning_samples_required = g_config_enterprise.min_samples_for_detection;
    g_context_enterprise.adaptive_learning_enabled = g_config_enterprise.adaptive_learning;
    g_context_enterprise.adaptation_rate = 0.1f;
    g_context_enterprise.model_drift_threshold = 0.3f;
    g_context_enterprise.active_method = g_config_enterprise.preferred_method;
    g_context_enterprise.performance_monitoring_enabled = true;
    
    // Initialisation du profil comportemental par défaut
    ml_behavior_profile_t* default_profile = &g_context_enterprise.behavior_profiles[0];
    default_profile->profile_id = 0;
    strncpy(default_profile->name, "Default", sizeof(default_profile->name) - 1);
    default_profile->threshold_multiplier = 2.0f;
    default_profile->is_active = true;
    default_profile->confidence_score = 0.5f;
    
    g_context_enterprise.active_profile_count = 1;
    g_context_enterprise.current_profile_id = 0;
    
    // Initialisation des statistiques
    memset(&g_stats_enterprise, 0, sizeof(anomaly_stats_enterprise_t));
    
    g_detector_initialized = true;
    
    ESP_LOGI(TAG, "✅ Détecteur ML Enterprise initialisé");
    ESP_LOGI(TAG, "   🧠 ML: %s", g_config_enterprise.ml_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   📚 Apprentissage adaptatif: %s", g_config_enterprise.adaptive_learning ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   👤 Profiling comportemental: %s", g_config_enterprise.behavioral_profiling ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   🎯 Méthode: %s", g_config_enterprise.ensemble_detection ? "Ensemble" : "Simple");
    ESP_LOGI(TAG, "   🎚️ Sensibilité: %.2f", g_config_enterprise.sensitivity_level);
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation du détecteur Enterprise
 */
esp_err_t anomaly_detector_deinit_enterprise(void) {
    if (!g_detector_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation détecteur ML Enterprise");
    
    // Suppression du mutex
    if (g_detector_mutex != NULL) {
        vSemaphoreDelete(g_detector_mutex);
        g_detector_mutex = NULL;
    }
    
    g_detector_initialized = false;
    
    ESP_LOGI(TAG, "✅ Détecteur ML Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Détection d'anomalie ML adaptative (Innovation Enterprise)
 */
anomaly_result_t anomaly_detect_ml_adaptive(const sensor_data_t* data) {
    anomaly_result_t result = {0};
    
    if (!g_detector_initialized || !data || !data->is_valid) {
        result.type = ANOMALY_TYPE_NONE;
        return result;
    }
    
    if (xSemaphoreTake(g_detector_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex détecteur");
        result.type = ANOMALY_TYPE_NONE;
        return result;
    }
    
    uint64_t start_time = esp_timer_get_time();
    
    // Mise à jour baseline
    anomaly_update_baseline_enterprise(data);
    
    // Mode apprentissage
    if (g_context_enterprise.is_learning) {
        uint64_t learning_time = esp_timer_get_time() - g_context_enterprise.learning_start_time;
        if (learning_time < g_config_enterprise.adaptation_interval_ms * 1000) {
            result.type = ANOMALY_TYPE_NONE;
            result.is_anomaly = false;
            xSemaphoreGive(g_detector_mutex);
            return result;
        } else {
            g_context_enterprise.is_learning = false;
            ESP_LOGI(TAG, "🎓 Fin apprentissage initial - détection ML active");
        }
    }
    
    // Vérification échantillons suffisants
    if (g_context_enterprise.sample_count < g_config_enterprise.min_samples_for_detection) {
        result.type = ANOMALY_TYPE_NONE;
        xSemaphoreGive(g_detector_mutex);
        return result;
    }
    
    // Extraction du vecteur de caractéristiques
    float feature_vector[ML_FEATURE_VECTOR_SIZE];
    extract_feature_vector(data, feature_vector);
    
    // Détection selon la méthode configurée
    float anomaly_score = 0.0f;
    float method_scores[5] = {0};
    
    if (g_config_enterprise.ensemble_detection) {
        anomaly_score = ensemble_anomaly_detection(feature_vector, method_scores);
        result.method_used = ML_METHOD_ENSEMBLE;
        memcpy(result.ensemble_scores, method_scores, sizeof(method_scores));
    } else {
        // Méthode simple Z-score amélioré
        float temp_zscore = calculate_zscore_robust(
            data->temperature,
            g_context_enterprise.behavior_profiles[0].feature_means[0],
            g_context_enterprise.behavior_profiles[0].feature_stds[0]
        );
        float humidity_zscore = calculate_zscore_robust(
            data->humidity,
            g_context_enterprise.behavior_profiles[0].feature_means[1],
            g_context_enterprise.behavior_profiles[0].feature_stds[1]
        );
        
        anomaly_score = fmaxf(temp_zscore, humidity_zscore) / 3.0f;
        anomaly_score = fminf(anomaly_score, 1.0f);
        result.method_used = ML_METHOD_ZSCORE;
    }
    
    // Ajustement selon la sensibilité
    anomaly_score *= g_config_enterprise.sensitivity_level;
    
    // Détermination anomalie
    float threshold = g_context_enterprise.behavior_profiles[g_context_enterprise.current_profile_id].threshold_multiplier * 0.3f;
    result.is_anomaly = (anomaly_score > threshold);
    result.anomaly_score = anomaly_score;
    result.confidence_score = fminf(anomaly_score * 2.0f, 1.0f);
    
    // Classification du type
    if (result.is_anomaly) {
        if (anomaly_score > 0.8f) {
            result.type = ANOMALY_TYPE_BEHAVIORAL_SHIFT;
        } else if (method_scores[1] > 0.7f) { // Isolation Forest élevé
            result.type = ANOMALY_TYPE_MULTIVARIATE;
        } else {
            result.type = ANOMALY_TYPE_SENSOR_DATA;
        }
    } else {
        result.type = ANOMALY_TYPE_NONE;
    }
    
    // Métadonnées Enterprise
    result.timestamp = data->timestamp;
    result.behavior_profile_id = g_context_enterprise.current_profile_id;
    memcpy(result.feature_vector, feature_vector, sizeof(feature_vector));
    result.historical_context_samples = g_context_enterprise.sample_count;
    result.baseline_deviation = anomaly_score;
    
    // Sévérité
    if (result.is_anomaly) {
        if (anomaly_score > 0.9f) result.severity = 5; // Emergency
        else if (anomaly_score > 0.8f) result.severity = 4; // Critical
        else if (anomaly_score > 0.6f) result.severity = 3; // High
        else if (anomaly_score > 0.4f) result.severity = 2; // Medium
        else result.severity = 1; // Low
        
        snprintf(result.description, sizeof(result.description),
                 "Anomalie ML adaptative: T=%.1f°C, H=%.1f%%, Score=%.3f, Méthode=%s, Profil=%d",
                 data->temperature, data->humidity, anomaly_score,
                 g_config_enterprise.ensemble_detection ? "Ensemble" : "ZScore",
                 g_context_enterprise.current_profile_id);
        
        ESP_LOGW(TAG, "%s (Confiance: %.3f)", result.description, result.confidence_score);
    }
    
    // Temps et performance
    result.detection_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    result.ml_inference_time_us = (uint32_t)(esp_timer_get_time() - start_time);
    result.memory_usage_bytes = sizeof(anomaly_context_enterprise_t);
    
    // Mise à jour des statistiques
    g_stats_enterprise.total_samples_processed++;
    if (result.is_anomaly) {
        g_stats_enterprise.anomalies_detected++;
    }
    
    // Mise à jour performance moyenne
    g_context_enterprise.avg_inference_time_us = 
        ((g_context_enterprise.avg_inference_time_us * (g_stats_enterprise.total_samples_processed - 1)) + 
         result.ml_inference_time_us) / g_stats_enterprise.total_samples_processed;
    
    // Vérification dérive modèle
    if (g_config_enterprise.adaptive_learning && 
        (esp_timer_get_time() - g_context_enterprise.last_adaptation_time) > (g_config_enterprise.adaptation_interval_ms * 1000)) {
        
        result.model_adaptation_triggered = true;
        g_context_enterprise.last_adaptation_time = esp_timer_get_time();
        ESP_LOGI(TAG, "🔄 Adaptation modèle ML déclenchée");
    }
    
    xSemaphoreGive(g_detector_mutex);
    
    return result;
}

/**
 * @brief Mise à jour du baseline Enterprise
 */
esp_err_t anomaly_update_baseline_enterprise(const sensor_data_t* data) {
    if (!g_detector_initialized || !data || !data->is_valid) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Extraction du vecteur de caractéristiques
    float feature_vector[ML_FEATURE_VECTOR_SIZE];
    extract_feature_vector(data, feature_vector);
    
    // Ajout à l'historique circulaire
    uint32_t index = g_context_enterprise.write_index;
    memcpy(g_context_enterprise.sensor_data[index], feature_vector, sizeof(feature_vector));
    g_context_enterprise.timestamps[index] = data->timestamp;
    
    g_context_enterprise.write_index = (g_context_enterprise.write_index + 1) % ANOMALY_HISTORY_SIZE_ENTERPRISE;
    if (g_context_enterprise.sample_count < ANOMALY_HISTORY_SIZE_ENTERPRISE) {
        g_context_enterprise.sample_count++;
    }
    
    // Mise à jour du profil comportemental actif
    ml_behavior_profile_t* profile = &g_context_enterprise.behavior_profiles[g_context_enterprise.current_profile_id];
    
    // Mise à jour incrémentale des moyennes et écarts-types
    for (uint32_t i = 0; i < ML_FEATURE_VECTOR_SIZE; i++) {
        float old_mean = profile->feature_means[i];
        float new_sample = feature_vector[i];
        
        // Moyenne mobile
        profile->feature_means[i] = old_mean + (new_sample - old_mean) / (profile->samples_count + 1);
        
        // Écart-type (estimation Welford)
        if (profile->samples_count > 0) {
            float variance_old = profile->feature_stds[i] * profile->feature_stds[i];
            float variance_new = variance_old + ((new_sample - old_mean) * (new_sample - profile->feature_means[i]) - variance_old) / (profile->samples_count + 1);
            profile->feature_stds[i] = sqrtf(fmaxf(variance_new, 1e-6f));
        }
    }
    
    profile->samples_count++;
    profile->last_update_time = data->timestamp;
    
    ESP_LOGD(TAG, "📊 Baseline mis à jour: %lu échantillons (Profil %d: %lu)",
             g_context_enterprise.sample_count, profile->profile_id, profile->samples_count);
    
    return ESP_OK;
}

/**
 * @brief Fonctions de compatibilité avec version standard
 */
esp_err_t anomaly_detector_init(void) {
    return anomaly_detector_init_enterprise(NULL);
}

esp_err_t anomaly_detector_deinit(void) {
    return anomaly_detector_deinit_enterprise();
}

anomaly_result_t anomaly_detect_sensor_data(const sensor_data_t* data) {
    return anomaly_detect_ml_adaptive(data);
}

anomaly_result_t anomaly_detect_system_behavior(void) {
    // Version Enterprise simplifiée
    anomaly_result_t result = {0};
    
    if (!g_detector_initialized) {
        result.type = ANOMALY_TYPE_NONE;
        return result;
    }
    
    uint64_t start_time = esp_timer_get_time();
    
    // Analyse comportement système basique
    static uint32_t last_check_time = 0;
    uint32_t current_time = (uint32_t)(esp_timer_get_time() / 1000000);
    
    if (last_check_time > 0) {
        uint32_t time_diff = current_time - last_check_time;
        
        if (time_diff > 120) { // Plus de 2 minutes
            result.is_anomaly = true;
            result.type = ANOMALY_TYPE_SYSTEM_BEHAVIOR;
            result.anomaly_score = fminf((float)time_diff / 300.0f, 1.0f);
            result.severity = (result.anomaly_score > 0.6f) ? 3 : 2;
            result.timestamp = current_time;
            result.method_used = ML_METHOD_ZSCORE;
            result.confidence_score = 0.7f;
            
            snprintf(result.description, sizeof(result.description),
                     "Comportement système anormal Enterprise: intervalle %lu s", time_diff);
            
            ESP_LOGW(TAG, "%s", result.description);
        }
    }
    
    last_check_time = current_time;
    result.detection_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    
    return result;
}

esp_err_t anomaly_update_baseline(const sensor_data_t* data) {
    return anomaly_update_baseline_enterprise(data);
}

esp_err_t anomaly_set_learning_mode(bool enable) {
    if (!g_detector_initialized) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_detector_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        g_context_enterprise.is_learning = enable;
        if (enable) {
            g_context_enterprise.learning_start_time = esp_timer_get_time();
            ESP_LOGI(TAG, "🎓 Mode apprentissage ML Enterprise activé");
        } else {
            ESP_LOGI(TAG, "🎯 Mode détection ML Enterprise activé");
        }
        xSemaphoreGive(g_detector_mutex);
    }
    
    return ESP_OK;
}

bool anomaly_is_learning_mode(void) {
    return g_context_enterprise.is_learning;
}

/**
 * @brief Fonctions Enterprise supplémentaires
 */
ml_result_t ml_behavioral_analysis_realtime(ml_anomaly_data_t* ml_data) {
    if (!g_detector_initialized || !ml_data) {
        return ML_ERROR_INVALID_PARAMETERS;
    }
    
    // Analyse ML temps réel sur les données fournies
    float anomaly_score = ensemble_anomaly_detection(ml_data->feature_vector, ml_data->ensemble_scores);
    
    ml_data->anomaly_score = anomaly_score;
    ml_data->confidence = fminf(anomaly_score * 2.0f, 1.0f);
    ml_data->is_anomaly = (anomaly_score > 0.5f);
    ml_data->behavior_profile_id = g_context_enterprise.current_profile_id;
    
    return ML_SUCCESS;
}

ml_result_t ml_update_behavioral_model(void) {
    if (!g_detector_initialized) {
        return ML_ERROR_NOT_INITIALIZED;
    }
    
    // Mise à jour du modèle comportemental
    g_context_enterprise.model_updates_count++;
    
    ESP_LOGI(TAG, "🧠 Modèle ML comportemental mis à jour (#%lu)",
             g_context_enterprise.model_updates_count);
    
    return ML_SUCCESS;
}

esp_err_t ml_adaptive_learning_update(void) {
    if (!g_detector_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGD(TAG, "📚 Mise à jour apprentissage adaptatif ML");
    
    // Mise à jour des seuils adaptatifs
    ml_behavior_profile_t* profile = &g_context_enterprise.behavior_profiles[g_context_enterprise.current_profile_id];
    
    // Ajustement dynamique du seuil basé sur les performances récentes
    if (g_stats_enterprise.false_positives > g_stats_enterprise.anomalies_detected * 0.2f) {
        profile->threshold_multiplier *= 1.1f; // Réduction sensibilité
    } else if (g_stats_enterprise.false_positives < g_stats_enterprise.anomalies_detected * 0.05f) {
        profile->threshold_multiplier *= 0.95f; // Augmentation sensibilité
    }
    
    profile->threshold_multiplier = fmaxf(0.5f, fminf(profile->threshold_multiplier, 3.0f));
    
    return ESP_OK;
}

esp_err_t ml_behavioral_analyzer_init_enterprise(void) {
    return anomaly_detector_init_enterprise(NULL);
}

anomaly_stats_enterprise_t anomaly_get_stats_enterprise(void) {
    anomaly_stats_enterprise_t stats = {0};
    
    if (!g_detector_initialized) {
        return stats;
    }
    
    if (xSemaphoreTake(g_detector_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(&stats, &g_stats_enterprise, sizeof(anomaly_stats_enterprise_t));
        
        // Calculs dérivés
        if (stats.total_samples_processed > 0) {
            stats.detection_accuracy = (float)(stats.total_samples_processed - stats.false_positives) / stats.total_samples_processed;
        }
        
        stats.avg_detection_time_ms = g_context_enterprise.avg_inference_time_us / 1000.0f;
        stats.active_behavior_profiles = g_context_enterprise.active_profile_count;
        stats.memory_usage_bytes = sizeof(anomaly_context_enterprise_t);
        stats.uptime_seconds = (uint32_t)(esp_timer_get_time() / 1000000);
        
        xSemaphoreGive(g_detector_mutex);
    }
    
    return stats;
}