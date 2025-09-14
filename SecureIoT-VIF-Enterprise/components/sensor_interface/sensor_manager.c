/**
 * @file sensor_manager.c
 * @brief Gestionnaire de capteurs Enterprise avec fonctionnalités avancées
 * 
 * Version Enterprise avec validation avancée, calibration automatique,
 * redondance multi-capteurs, monitoring temps réel et intégration crypto.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "sensor_manager.h"
#include "esp32_crypto_manager.h"
#include "app_config.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <math.h>

static const char *TAG = "SENSOR_MANAGER_ENTERPRISE";

// Variables globales Enterprise
static bool g_sensor_initialized = false;
static sensor_stats_enterprise_t g_stats_enterprise = {0};
static sensor_data_t g_last_reading_enterprise = {0};
static SemaphoreHandle_t g_sensor_mutex = NULL;

// Configuration multi-capteurs
static sensor_config_enterprise_t g_sensor_configs[MAX_SENSORS_ENTERPRISE];
static uint8_t g_active_sensor_count = 0;
static uint64_t g_sequence_number = 0;

// Historique pour monitoring
static sensor_data_t g_monitoring_history[SENSOR_MONITORING_HISTORY_SIZE];
static uint32_t g_history_write_index = 0;
static bool g_history_full = false;

// Calibration
static sensor_calibration_info_t g_calibration_info[MAX_SENSORS_ENTERPRISE];

// Timer monitoring
static esp_timer_handle_t g_monitoring_timer = NULL;

/**
 * @brief Callback timer monitoring temps réel
 */
static void sensor_monitoring_timer_callback(void* arg) {
    if (!g_sensor_initialized) return;
    
    // Monitoring des capteurs actifs
    for (uint8_t i = 0; i < g_active_sensor_count; i++) {
        sensor_monitor_realtime(i);
    }
}

/**
 * @brief Calcul du hash des données pour intégrité
 */
static uint32_t calculate_data_hash(const sensor_data_t* data) {
    if (!data) return 0;
    
    // Hash simple basé sur les données principales
    uint32_t hash = 0;
    uint32_t temp_int = (uint32_t)(data->temperature * 100);
    uint32_t humidity_int = (uint32_t)(data->humidity * 100);
    
    hash = temp_int ^ (humidity_int << 16) ^ data->timestamp;
    return hash;
}

/**
 * @brief Application de la calibration aux données
 */
static void apply_calibration(uint8_t sensor_id, sensor_data_t* data) {
    if (sensor_id >= MAX_SENSORS_ENTERPRISE || !data) return;
    
    sensor_calibration_info_t* cal = &g_calibration_info[sensor_id];
    if (!cal->is_calibrated) return;
    
    // Application offset et gain
    data->temperature = (data->temperature + cal->temperature_offset) * cal->temperature_gain;
    data->humidity = (data->humidity + cal->humidity_offset) * cal->humidity_gain;
    
    // Calcul dérivées
    data->dewpoint = dht22_calculate_dewpoint(data->temperature, data->humidity);
    data->heatindex = dht22_calculate_heatindex(data->temperature, data->humidity);
    
    data->is_calibrated = true;
    data->calibration_offset_temp = cal->temperature_offset;
    data->calibration_offset_humidity = cal->humidity_offset;
}

/**
 * @brief Calcul des tendances et dérivées
 */
static void calculate_trends(sensor_data_t* data) {
    if (!data || !g_history_full && g_history_write_index < 2) {
        data->temperature_trend = 0.0f;
        data->humidity_trend = 0.0f;
        return;
    }
    
    // Calcul tendance sur dernières mesures
    uint32_t prev_index = (g_history_write_index - 1 + SENSOR_MONITORING_HISTORY_SIZE) % SENSOR_MONITORING_HISTORY_SIZE;
    const sensor_data_t* prev_data = &g_monitoring_history[prev_index];
    
    if (prev_data->is_valid && data->timestamp > prev_data->timestamp) {
        float time_diff = (float)(data->timestamp - prev_data->timestamp) / 60.0f; // en minutes
        
        if (time_diff > 0.1f) { // Au moins 6 secondes
            data->temperature_trend = (data->temperature - prev_data->temperature) / time_diff;
            data->humidity_trend = (data->humidity - prev_data->humidity) / time_diff;
            
            // Dérivées (simplifié)
            data->temperature_derivative = data->temperature_trend;
            data->humidity_derivative = data->humidity_trend;
        }
    }
}

/**
 * @brief Validation redondante multi-capteurs
 */
static bool validate_with_redundancy(const sensor_data_t* data) {
    if (!data || g_active_sensor_count < 2) return true; // Pas de redondance
    
    // Comparer avec autres capteurs actifs (implémentation simplifiée)
    float temp_tolerance = 2.0f; // ±2°C
    float humidity_tolerance = 5.0f; // ±5%
    
    uint8_t valid_sensors = 0;
    
    for (uint8_t i = 0; i < g_active_sensor_count; i++) {
        sensor_data_t other_data;
        if (sensor_read_enterprise(i, &other_data) == ESP_OK && other_data.is_valid) {
            float temp_diff = fabsf(data->temperature - other_data.temperature);
            float humidity_diff = fabsf(data->humidity - other_data.humidity);
            
            if (temp_diff <= temp_tolerance && humidity_diff <= humidity_tolerance) {
                valid_sensors++;
            }
        }
    }
    
    return (valid_sensors >= (g_active_sensor_count / 2)); // Majorité
}

/**
 * @brief Ajout données à l'historique monitoring
 */
static void add_to_monitoring_history(const sensor_data_t* data) {
    if (!data) return;
    
    memcpy(&g_monitoring_history[g_history_write_index], data, sizeof(sensor_data_t));
    g_history_write_index = (g_history_write_index + 1) % SENSOR_MONITORING_HISTORY_SIZE;
    
    if (g_history_write_index == 0) {
        g_history_full = true;
    }
}

/**
 * @brief Initialisation du gestionnaire capteurs Enterprise
 */
esp_err_t sensor_manager_init_enterprise(const sensor_config_enterprise_t* config) {
    if (g_sensor_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🌡️ Initialisation gestionnaire capteurs Enterprise");
    
    // Création du mutex thread-safe
    g_sensor_mutex = xSemaphoreCreateMutex();
    if (g_sensor_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex capteurs");
        return ESP_FAIL;
    }
    
    // Configuration par défaut DHT22
    sensor_config_enterprise_t default_config = {
        .type = SENSOR_TYPE_DHT22,
        .sensor_id = 0,
        .gpio_pin = DHT22_GPIO_PIN,
        .power_pin = DHT22_POWER_GPIO,
        .read_interval_ms = 2000,
        .max_retries = 3,
        .calibration_enabled = true,
        .redundancy_enabled = false,
        .crypto_verification_enabled = true,
        .monitoring_enabled = true,
        .validation_tolerance = 5.0f,
        .monitoring_interval_ms = 30000,
        .temperature_min = -40.0f,
        .temperature_max = 80.0f,
        .humidity_min = 0.0f,
        .humidity_max = 100.0f
    };
    
    if (config) {
        g_sensor_configs[0] = *config;
    } else {
        g_sensor_configs[0] = default_config;
    }
    
    // Initialisation DHT22 Enterprise
    dht22_config_enterprise_t dht_config = {
        .gpio_pin = g_sensor_configs[0].gpio_pin,
        .power_pin = g_sensor_configs[0].power_pin,
        .read_interval_ms = g_sensor_configs[0].read_interval_ms,
        .max_retries = g_sensor_configs[0].max_retries,
        .timeout_us = 1000,
        .calibration_enabled = g_sensor_configs[0].calibration_enabled,
        .validation_enhanced = true,
        .monitoring_enabled = g_sensor_configs[0].monitoring_enabled,
        .power_management_enabled = true,
        .temperature_min = g_sensor_configs[0].temperature_min,
        .temperature_max = g_sensor_configs[0].temperature_max,
        .humidity_min = g_sensor_configs[0].humidity_min,
        .humidity_max = g_sensor_configs[0].humidity_max,
        .noise_threshold = 0.1f,
        .max_consecutive_errors = 5,
        .temperature_offset = 0.0f,
        .humidity_offset = 0.0f,
        .temperature_gain = 1.0f,
        .humidity_gain = 1.0f
    };
    
    esp_err_t ret = dht22_init_enterprise(&dht_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation DHT22 Enterprise: %s", esp_err_to_name(ret));
        return ret;
    }
    
    g_active_sensor_count = 1;
    
    // Initialisation des statistiques
    memset(&g_stats_enterprise, 0, sizeof(sensor_stats_enterprise_t));
    g_stats_enterprise.min_temperature = 999.0f;
    g_stats_enterprise.max_temperature = -999.0f;
    g_stats_enterprise.min_humidity = 999.0f;
    g_stats_enterprise.max_humidity = -999.0f;
    g_stats_enterprise.overall_status = SENSOR_STATUS_HEALTHY;
    g_stats_enterprise.active_sensor_count = g_active_sensor_count;
    
    // Initialisation calibration
    memset(g_calibration_info, 0, sizeof(g_calibration_info));
    g_calibration_info[0].temperature_gain = 1.0f;
    g_calibration_info[0].humidity_gain = 1.0f;
    
    // Initialisation historique
    memset(g_monitoring_history, 0, sizeof(g_monitoring_history));
    g_history_write_index = 0;
    g_history_full = false;
    g_sequence_number = 0;
    
    // Configuration timer monitoring
    if (g_sensor_configs[0].monitoring_enabled) {
        esp_timer_create_args_t timer_args = {
            .callback = &sensor_monitoring_timer_callback,
            .arg = NULL,
            .name = "sensor_monitoring_enterprise"
        };
        
        ret = esp_timer_create(&timer_args, &g_monitoring_timer);
        if (ret == ESP_OK) {
            ret = esp_timer_start_periodic(g_monitoring_timer, g_sensor_configs[0].monitoring_interval_ms * 1000);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "✅ Timer monitoring activé (%lums)", g_sensor_configs[0].monitoring_interval_ms);
            }
        }
    }
    
    g_sensor_initialized = true;
    
    ESP_LOGI(TAG, "✅ Gestionnaire capteurs Enterprise initialisé");
    ESP_LOGI(TAG, "   🌡️ Capteurs actifs: %d", g_active_sensor_count);
    ESP_LOGI(TAG, "   📐 Calibration: %s", g_sensor_configs[0].calibration_enabled ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   🔄 Redondance: %s", g_sensor_configs[0].redundancy_enabled ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   🔐 Vérification crypto: %s", g_sensor_configs[0].crypto_verification_enabled ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   📊 Monitoring: %s", g_sensor_configs[0].monitoring_enabled ? "Activé" : "Désactivé");
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation du gestionnaire Enterprise
 */
esp_err_t sensor_manager_deinit_enterprise(void) {
    if (!g_sensor_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation gestionnaire capteurs Enterprise");
    
    // Arrêt timer monitoring
    if (g_monitoring_timer != NULL) {
        esp_timer_stop(g_monitoring_timer);
        esp_timer_delete(g_monitoring_timer);
        g_monitoring_timer = NULL;
    }
    
    // Dé-initialisation DHT22
    dht22_deinit_enterprise();
    
    // Suppression mutex
    if (g_sensor_mutex != NULL) {
        vSemaphoreDelete(g_sensor_mutex);
        g_sensor_mutex = NULL;
    }
    
    g_sensor_initialized = false;
    
    ESP_LOGI(TAG, "✅ Gestionnaire capteurs Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Lecture capteur avec validation Enterprise avancée
 */
esp_err_t sensor_read_enterprise(uint8_t sensor_id, sensor_data_t* data) {
    if (!g_sensor_initialized || !data || sensor_id >= g_active_sensor_count) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (xSemaphoreTake(g_sensor_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex capteur");
        return ESP_ERR_TIMEOUT;
    }
    
    uint64_t start_time = esp_timer_get_time();
    esp_err_t ret = ESP_OK;
    
    // Lecture DHT22 Enterprise
    dht22_reading_enterprise_t dht_reading;
    ret = dht22_read_enterprise(&dht_reading);
    
    // Mise à jour statistiques globales
    g_stats_enterprise.total_readings++;
    
    if (ret == ESP_OK && dht_reading.is_valid && dht22_validate_data_enterprise(&dht_reading)) {
        // Construction des données Enterprise
        memset(data, 0, sizeof(sensor_data_t));
        
        // Données de base
        data->temperature = dht_reading.temperature_calibrated;
        data->humidity = dht_reading.humidity_calibrated;
        data->timestamp = dht_reading.timestamp;
        data->is_valid = true;
        data->sensor_id = sensor_id;
        data->quality_score = dht_reading.quality_score;
        
        // Extensions Enterprise
        data->sensor_type = SENSOR_TYPE_DHT22;
        data->status = SENSOR_STATUS_HEALTHY;
        data->quality_level = (data->quality_score >= 90) ? SENSOR_QUALITY_PERFECT :
                              (data->quality_score >= 80) ? SENSOR_QUALITY_EXCELLENT :
                              (data->quality_score >= 60) ? SENSOR_QUALITY_GOOD :
                              (data->quality_score >= 40) ? SENSOR_QUALITY_FAIR :
                              (data->quality_score >= 20) ? SENSOR_QUALITY_POOR :
                              SENSOR_QUALITY_INVALID;
        
        // Données supplémentaires
        data->pressure = 0.0f; // DHT22 ne mesure pas la pression
        data->dewpoint = dht_reading.dewpoint;
        data->heatindex = dht_reading.heatindex;
        
        // Application calibration
        apply_calibration(sensor_id, data);
        
        // Calcul tendances
        calculate_trends(data);
        
        // Validation redondance
        if (g_sensor_configs[sensor_id].redundancy_enabled) {
            data->is_redundant_validated = validate_with_redundancy(data);
            data->redundant_sensor_count = g_active_sensor_count;
        } else {
            data->is_redundant_validated = true;
            data->redundant_sensor_count = 1;
        }
        
        // Métadonnées diagnostic
        data->read_duration_us = (uint32_t)(esp_timer_get_time() - start_time);
        data->retry_count = dht_reading.retry_count;
        data->error_flags = 0;
        data->noise_level = dht_reading.noise_level;
        
        // Sécurité et intégrité
        data->sequence_number = ++g_sequence_number;
        data->data_hash = calculate_data_hash(data);
        
        // Vérification crypto si activée
        if (g_sensor_configs[sensor_id].crypto_verification_enabled) {
            esp32_crypto_result_t crypto_result = esp32_crypto_verify_sensor_data((uint8_t*)data, sizeof(sensor_data_t));
            data->crypto_verified = (crypto_result == ESP32_CRYPTO_SUCCESS);
        } else {
            data->crypto_verified = false;
        }
        
        // Mise à jour statistiques réussies
        g_stats_enterprise.valid_readings++;
        g_stats_enterprise.avg_temperature = ((g_stats_enterprise.avg_temperature * (g_stats_enterprise.valid_readings - 1)) + data->temperature) / g_stats_enterprise.valid_readings;
        g_stats_enterprise.avg_humidity = ((g_stats_enterprise.avg_humidity * (g_stats_enterprise.valid_readings - 1)) + data->humidity) / g_stats_enterprise.valid_readings;
        g_stats_enterprise.avg_quality_score = ((g_stats_enterprise.avg_quality_score * (g_stats_enterprise.valid_readings - 1)) + data->quality_score) / g_stats_enterprise.valid_readings;
        
        // Min/Max
        if (data->temperature < g_stats_enterprise.min_temperature) g_stats_enterprise.min_temperature = data->temperature;
        if (data->temperature > g_stats_enterprise.max_temperature) g_stats_enterprise.max_temperature = data->temperature;
        if (data->humidity < g_stats_enterprise.min_humidity) g_stats_enterprise.min_humidity = data->humidity;
        if (data->humidity > g_stats_enterprise.max_humidity) g_stats_enterprise.max_humidity = data->humidity;
        
        g_stats_enterprise.last_reading_time = esp_timer_get_time();
        
        // Détection anomalie
        if (g_last_reading_enterprise.is_valid && sensor_is_anomaly(data, &g_last_reading_enterprise)) {
            ESP_LOGW(TAG, "🚨 Anomalie capteur détectée: T=%.1f°C->%.1f°C, H=%.1f%%->%.1f%%",
                     g_last_reading_enterprise.temperature, data->temperature,
                     g_last_reading_enterprise.humidity, data->humidity);
            data->quality_score = MAX(data->quality_score / 2, 10); // Réduction qualité
            g_stats_enterprise.anomaly_detections++;
        }
        
        // Mise à jour historique
        add_to_monitoring_history(data);
        memcpy(&g_last_reading_enterprise, data, sizeof(sensor_data_t));
        
        ESP_LOGD(TAG, "📊 Lecture capteur #%d: T=%.1f°C, H=%.1f%%, Q=%d, Séq=%llu", 
                 sensor_id, data->temperature, data->humidity, data->quality_score, data->sequence_number);
        
    } else {
        // Lecture échouée
        memset(data, 0, sizeof(sensor_data_t));
        data->is_valid = false;
        data->sensor_id = sensor_id;
        data->sensor_type = SENSOR_TYPE_DHT22;
        data->status = SENSOR_STATUS_ERROR;
        data->quality_score = 0;
        data->timestamp = (uint32_t)(esp_timer_get_time() / 1000000);
        
        g_stats_enterprise.error_readings++;
        g_stats_enterprise.consecutive_errors++;
        
        ESP_LOGW(TAG, "⚠️ Lecture capteur #%d échouée: %s", 
                 sensor_id, dht22_error_to_string_enterprise((dht22_error_code_enterprise_t)dht_reading.error_code));
    }
    
    // Mise à jour durée lecture moyenne
    uint32_t read_duration_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    g_stats_enterprise.avg_read_duration_ms = ((g_stats_enterprise.avg_read_duration_ms * (g_stats_enterprise.total_readings - 1)) + read_duration_ms) / g_stats_enterprise.total_readings;
    
    xSemaphoreGive(g_sensor_mutex);
    
    return ret;
}

/**
 * @brief Calibration automatique capteur (Innovation Enterprise)
 */
esp_err_t sensor_calibrate_automatic(uint8_t sensor_id, float reference_temp, float reference_humidity) {
    if (!g_sensor_initialized || sensor_id >= g_active_sensor_count) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "📐 Calibration automatique capteur #%d (Ref: T=%.1f°C, H=%.1f%%)", 
             sensor_id, reference_temp, reference_humidity);
    
    if (xSemaphoreTake(g_sensor_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    
    // Calibration DHT22
    esp_err_t ret = dht22_calibrate_automatic(reference_temp, reference_humidity);
    
    if (ret == ESP_OK) {
        // Mise à jour informations calibration
        sensor_calibration_info_t* cal = &g_calibration_info[sensor_id];
        
        // Lecture pour obtenir offset (implémentation simplifiée)
        sensor_data_t test_data;
        if (sensor_read_enterprise(sensor_id, &test_data) == ESP_OK && test_data.is_valid) {
            cal->temperature_offset = reference_temp - test_data.temperature;
            cal->humidity_offset = reference_humidity - test_data.humidity;
            cal->is_calibrated = true;
            cal->last_calibration_time = (uint32_t)(esp_timer_get_time() / 1000000);
            
            g_stats_enterprise.calibration_count++;
            
            ESP_LOGI(TAG, "✅ Calibration terminée - Offsets: T=%.2f°C, H=%.2f%%", 
                     cal->temperature_offset, cal->humidity_offset);
        }
    }
    
    xSemaphoreGive(g_sensor_mutex);
    
    return ret;
}

/**
 * @brief Monitoring temps réel capteur
 */
esp_err_t sensor_monitor_realtime(uint8_t sensor_id) {
    if (!g_sensor_initialized || sensor_id >= g_active_sensor_count) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Diagnostic santé DHT22
    uint8_t health_score = 0;
    esp_err_t ret = dht22_diagnose_health(&health_score);
    
    if (ret == ESP_OK) {
        // Mise à jour santé système
        g_stats_enterprise.system_health_score = ((g_stats_enterprise.system_health_score * g_active_sensor_count) + health_score) / (g_active_sensor_count + 1);
        
        // Détermination statut global
        if (health_score >= 90) {
            g_stats_enterprise.overall_status = SENSOR_STATUS_HEALTHY;
        } else if (health_score >= 70) {
            g_stats_enterprise.overall_status = SENSOR_STATUS_WARNING;
        } else if (health_score >= 50) {
            g_stats_enterprise.overall_status = SENSOR_STATUS_ERROR;
        } else {
            g_stats_enterprise.overall_status = SENSOR_STATUS_CRITICAL;
        }
        
        ESP_LOGD(TAG, "💗 Santé capteur #%d: %d%%, Statut: %d", sensor_id, health_score, g_stats_enterprise.overall_status);
    }
    
    return ret;
}

/**
 * @brief Fonctions de compatibilité avec version standard
 */
esp_err_t sensor_manager_init(void) {
    return sensor_manager_init_enterprise(NULL);
}

esp_err_t sensor_manager_deinit(void) {
    return sensor_manager_deinit_enterprise();
}

esp_err_t sensor_read_dht22(sensor_data_t* data) {
    return sensor_read_enterprise(0, data);
}

esp_err_t sensor_get_statistics(sensor_stats_t* stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;
    
    sensor_stats_enterprise_t enterprise_stats;
    esp_err_t ret = sensor_get_statistics_enterprise(&enterprise_stats);
    
    if (ret == ESP_OK) {
        // Conversion format standard
        stats->total_readings = enterprise_stats.total_readings;
        stats->valid_readings = enterprise_stats.valid_readings;
        stats->error_readings = enterprise_stats.error_readings;
        stats->avg_temperature = enterprise_stats.avg_temperature;
        stats->avg_humidity = enterprise_stats.avg_humidity;
        stats->min_temperature = enterprise_stats.min_temperature;
        stats->max_temperature = enterprise_stats.max_temperature;
        stats->min_humidity = enterprise_stats.min_humidity;
        stats->max_humidity = enterprise_stats.max_humidity;
        stats->last_reading_time = enterprise_stats.last_reading_time;
    }
    
    return ret;
}

esp_err_t sensor_get_statistics_enterprise(sensor_stats_enterprise_t* stats) {
    if (!stats || !g_sensor_initialized) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_sensor_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(stats, &g_stats_enterprise, sizeof(sensor_stats_enterprise_t));
        
        // Calculs temps réel
        stats->uptime_seconds = (uint32_t)(esp_timer_get_time() / 1000000);
        
        // Tendances 24h (simulation)
        stats->temperature_trend_24h = 0.1f; // Simulation
        stats->humidity_trend_24h = -0.5f;   // Simulation
        stats->readings_last_24h = MIN(stats->total_readings, 2880); // 1 lecture/30s sur 24h
        
        xSemaphoreGive(g_sensor_mutex);
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

void sensor_reset_statistics(void) {
    if (!g_sensor_initialized) return;
    
    if (xSemaphoreTake(g_sensor_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memset(&g_stats_enterprise, 0, sizeof(sensor_stats_enterprise_t));
        g_stats_enterprise.min_temperature = 999.0f;
        g_stats_enterprise.max_temperature = -999.0f;
        g_stats_enterprise.min_humidity = 999.0f;
        g_stats_enterprise.max_humidity = -999.0f;
        g_stats_enterprise.overall_status = SENSOR_STATUS_HEALTHY;
        g_stats_enterprise.active_sensor_count = g_active_sensor_count;
        g_stats_enterprise.system_health_score = 100.0f;
        
        xSemaphoreGive(g_sensor_mutex);
        
        ESP_LOGI(TAG, "🔄 Statistiques capteurs Enterprise remises à zéro");
    }
}

bool sensor_is_anomaly(const sensor_data_t* current, const sensor_data_t* previous) {
    if (!current || !previous || !current->is_valid || !previous->is_valid) {
        return false;
    }
    
    // Seuils d'anomalie Enterprise renforcés
    float temp_diff = fabsf(current->temperature - previous->temperature);
    float humidity_diff = fabsf(current->humidity - previous->humidity);
    
    // Seuils adaptatifs basés sur qualité
    float temp_threshold = TEMP_ANOMALY_THRESHOLD * (1.0f + (100 - current->quality_score) / 100.0f);
    float humidity_threshold = HUMIDITY_ANOMALY_THRESHOLD * (1.0f + (100 - current->quality_score) / 100.0f);
    
    return (temp_diff > temp_threshold || humidity_diff > humidity_threshold);
}

// Fonctions Enterprise supplémentaires
esp_err_t sensor_read_redundant(sensor_data_t* data) {
    if (!data || g_active_sensor_count < 2) {
        // Fallback vers lecture simple
        return sensor_read_enterprise(0, data);
    }
    
    ESP_LOGD(TAG, "🔄 Lecture redondante multi-capteurs");
    
    // Implémentation simplifiée - lecture moyenne
    sensor_data_t readings[MAX_SENSORS_ENTERPRISE];
    uint8_t valid_count = 0;
    
    for (uint8_t i = 0; i < g_active_sensor_count; i++) {
        if (sensor_read_enterprise(i, &readings[i]) == ESP_OK && readings[i].is_valid) {
            valid_count++;
        }
    }
    
    if (valid_count == 0) {
        return ESP_FAIL;
    }
    
    // Calcul moyenne pondérée
    memset(data, 0, sizeof(sensor_data_t));
    float total_weight = 0.0f;
    
    for (uint8_t i = 0; i < g_active_sensor_count; i++) {
        if (readings[i].is_valid) {
            float weight = (float)readings[i].quality_score / 100.0f;
            data->temperature += readings[i].temperature * weight;
            data->humidity += readings[i].humidity * weight;
            total_weight += weight;
        }
    }
    
    if (total_weight > 0.0f) {
        data->temperature /= total_weight;
        data->humidity /= total_weight;
        data->is_valid = true;
        data->is_redundant_validated = true;
        data->redundant_sensor_count = valid_count;
        data->timestamp = (uint32_t)(esp_timer_get_time() / 1000000);
        data->quality_score = (uint8_t)(total_weight / valid_count * 100);
        
        ESP_LOGI(TAG, "✅ Lecture redondante: T=%.1f°C, H=%.1f%% (%d capteurs)", 
                 data->temperature, data->humidity, valid_count);
    }
    
    return ESP_OK;
}

esp_err_t sensor_validate_redundancy(const sensor_data_t* primary_data, bool* is_valid) {
    if (!primary_data || !is_valid) return ESP_ERR_INVALID_ARG;
    
    *is_valid = validate_with_redundancy(primary_data);
    return ESP_OK;
}

esp_err_t sensor_diagnose_health(uint8_t sensor_id, sensor_status_enterprise_t* status) {
    if (!status || sensor_id >= g_active_sensor_count) return ESP_ERR_INVALID_ARG;
    
    uint8_t health_score = 0;
    esp_err_t ret = dht22_diagnose_health(&health_score);
    
    if (ret == ESP_OK) {
        if (health_score >= 90) *status = SENSOR_STATUS_HEALTHY;
        else if (health_score >= 70) *status = SENSOR_STATUS_WARNING;
        else if (health_score >= 50) *status = SENSOR_STATUS_ERROR;
        else *status = SENSOR_STATUS_CRITICAL;
    } else {
        *status = SENSOR_STATUS_UNKNOWN;
    }
    
    return ret;
}

esp_err_t sensor_configure_enterprise(uint8_t sensor_id, const sensor_config_enterprise_t* config) {
    if (!config || sensor_id >= MAX_SENSORS_ENTERPRISE) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "⚙️ Configuration capteur Enterprise #%d", sensor_id);
    
    if (xSemaphoreTake(g_sensor_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(&g_sensor_configs[sensor_id], config, sizeof(sensor_config_enterprise_t));
        xSemaphoreGive(g_sensor_mutex);
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

esp_err_t sensor_reset_calibration(uint8_t sensor_id) {
    if (sensor_id >= MAX_SENSORS_ENTERPRISE) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "🔄 Réinitialisation calibration capteur #%d", sensor_id);
    
    memset(&g_calibration_info[sensor_id], 0, sizeof(sensor_calibration_info_t));
    g_calibration_info[sensor_id].temperature_gain = 1.0f;
    g_calibration_info[sensor_id].humidity_gain = 1.0f;
    
    return dht22_reset_calibration();
}

esp_err_t sensor_verify_data_integrity(const sensor_data_t* data, bool* is_valid) {
    if (!data || !is_valid) return ESP_ERR_INVALID_ARG;
    
    // Vérification hash
    uint32_t calculated_hash = calculate_data_hash(data);
    *is_valid = (calculated_hash == data->data_hash);
    
    return ESP_OK;
}