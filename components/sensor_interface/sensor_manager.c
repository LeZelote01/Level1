/**
 * @file sensor_manager.c
 * @brief Implémentation du gestionnaire de capteurs
 */

#include "sensor_manager.h"
#include "app_config.h"
#include "esp_log.h"
#include <string.h>
#include <math.h>

static const char *TAG = "SENSOR_MANAGER";
static bool g_sensor_initialized = false;
static sensor_stats_t g_stats;
static sensor_data_t g_last_reading;

esp_err_t sensor_manager_init(void) {
    if (g_sensor_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Initialisation gestionnaire de capteurs");
    
    // Configuration DHT22
    dht22_config_t dht_config = {
        .gpio_pin = DHT22_GPIO_PIN,
        .power_pin = DHT22_POWER_GPIO,
        .read_interval_ms = 2000,
        .max_retries = 3,
        .timeout_us = 1000
    };
    
    esp_err_t ret = dht22_init(&dht_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Échec initialisation DHT22: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Initialisation des statistiques
    memset(&g_stats, 0, sizeof(sensor_stats_t));
    g_stats.min_temperature = 999.0f;
    g_stats.max_temperature = -999.0f;
    g_stats.min_humidity = 999.0f;
    g_stats.max_humidity = -999.0f;
    
    memset(&g_last_reading, 0, sizeof(sensor_data_t));
    g_sensor_initialized = true;
    
    ESP_LOGI(TAG, "Gestionnaire de capteurs initialisé");
    return ESP_OK;
}

esp_err_t sensor_manager_deinit(void) {
    if (!g_sensor_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Dé-initialisation gestionnaire de capteurs");
    dht22_deinit();
    g_sensor_initialized = false;
    
    return ESP_OK;
}

esp_err_t sensor_read_dht22(sensor_data_t* data) {
    if (!g_sensor_initialized || !data) return ESP_ERR_INVALID_ARG;
    
    dht22_reading_t dht_reading;
    esp_err_t ret = dht22_read_with_retry(&dht_reading, 3);
    
    // Mise à jour des statistiques
    g_stats.total_readings++;
    
    if (ret == ESP_OK && dht22_is_data_valid(&dht_reading)) {
        // Données valides
        data->temperature = dht_reading.temperature;
        data->humidity = dht_reading.humidity;
        data->timestamp = dht_reading.timestamp;
        data->is_valid = true;
        data->sensor_id = 1; // DHT22
        data->quality_score = 100; // Score parfait si données valides
        
        // Mise à jour des statistiques
        g_stats.valid_readings++;
        g_stats.avg_temperature = ((g_stats.avg_temperature * (g_stats.valid_readings - 1)) + data->temperature) / g_stats.valid_readings;
        g_stats.avg_humidity = ((g_stats.avg_humidity * (g_stats.valid_readings - 1)) + data->humidity) / g_stats.valid_readings;
        
        if (data->temperature < g_stats.min_temperature) g_stats.min_temperature = data->temperature;
        if (data->temperature > g_stats.max_temperature) g_stats.max_temperature = data->temperature;
        if (data->humidity < g_stats.min_humidity) g_stats.min_humidity = data->humidity;
        if (data->humidity > g_stats.max_humidity) g_stats.max_humidity = data->humidity;
        
        g_stats.last_reading_time = esp_timer_get_time();
        
        // Détection d'anomalie par rapport à la lecture précédente
        if (g_last_reading.is_valid && sensor_is_anomaly(data, &g_last_reading)) {
            ESP_LOGW(TAG, "Anomalie détectée: T=%.1f°C (prev=%.1f), H=%.1f%% (prev=%.1f)",
                     data->temperature, g_last_reading.temperature,
                     data->humidity, g_last_reading.humidity);
            data->quality_score = 50; // Score réduit en cas d'anomalie
        }
        
        memcpy(&g_last_reading, data, sizeof(sensor_data_t));
        
        ESP_LOGD(TAG, "Lecture capteur: T=%.1f°C, H=%.1f%%, Q=%d", 
                 data->temperature, data->humidity, data->quality_score);
    } else {
        // Données invalides
        memset(data, 0, sizeof(sensor_data_t));
        data->is_valid = false;
        data->sensor_id = 1;
        data->quality_score = 0;
        g_stats.error_readings++;
        
        ESP_LOGW(TAG, "Lecture capteur échouée: %s", 
                 dht22_error_to_string(dht_reading.error_code));
    }
    
    return ret;
}

esp_err_t sensor_get_statistics(sensor_stats_t* stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;
    
    memcpy(stats, &g_stats, sizeof(sensor_stats_t));
    return ESP_OK;
}

void sensor_reset_statistics(void) {
    memset(&g_stats, 0, sizeof(sensor_stats_t));
    g_stats.min_temperature = 999.0f;
    g_stats.max_temperature = -999.0f;
    g_stats.min_humidity = 999.0f;
    g_stats.max_humidity = -999.0f;
    
    ESP_LOGI(TAG, "Statistiques capteurs remises à zéro");
}

bool sensor_is_anomaly(const sensor_data_t* current, const sensor_data_t* previous) {
    if (!current || !previous || !current->is_valid || !previous->is_valid) {
        return false;
    }
    
    // Seuils d'anomalie définis dans app_config.h
    float temp_diff = fabsf(current->temperature - previous->temperature);
    float humidity_diff = fabsf(current->humidity - previous->humidity);
    
    return (temp_diff > TEMP_ANOMALY_THRESHOLD || humidity_diff > HUMIDITY_ANOMALY_THRESHOLD);
}