/**
 * @file dht22_driver.c
 * @brief Driver DHT22 Enterprise avec fonctionnalités avancées
 * 
 * Version Enterprise avec validation renforcée, retry intelligent,
 * calibration automatique, monitoring performance et gestion alimentation optimisée.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "dht22_driver.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <math.h>

static const char *TAG = "DHT22_DRIVER_ENTERPRISE";

// Variables globales Enterprise
static bool g_dht22_initialized = false;
static dht22_config_enterprise_t g_config_enterprise = {0};
static uint64_t g_last_read_time = 0;
static dht22_stats_enterprise_t g_stats_enterprise = {0};
static SemaphoreHandle_t g_dht22_mutex = NULL;

// Historique de lectures pour calibration et validation
static dht22_reading_enterprise_t g_reading_history[DHT22_CALIBRATION_SAMPLES];
static uint8_t g_history_write_index = 0;
static bool g_history_full = false;

// Calibration
static float g_temperature_offset = 0.0f;
static float g_humidity_offset = 0.0f;
static float g_temperature_gain = 1.0f;
static float g_humidity_gain = 1.0f;
static bool g_calibration_valid = false;

// Monitoring erreurs consécutives
static uint32_t g_consecutive_errors = 0;
static uint64_t g_last_error_time = 0;

/**
 * @brief Calcul du point de rosée
 */
float dht22_calculate_dewpoint(float temperature, float humidity) {
    if (humidity <= 0.0f || humidity > 100.0f) return NAN;
    
    // Formule Magnus-Tetens
    const float a = 17.27f;
    const float b = 237.7f;
    
    float gamma = (a * temperature) / (b + temperature) + logf(humidity / 100.0f);
    float dewpoint = (b * gamma) / (a - gamma);
    
    return dewpoint;
}

/**
 * @brief Calcul de l'indice de chaleur
 */
float dht22_calculate_heatindex(float temperature, float humidity) {
    if (temperature < 26.7f) return temperature; // Pas d'indice en dessous de 80°F (26.7°C)
    
    // Formule Rothfusz
    const float c1 = -8.78469475556f;
    const float c2 = 1.61139411f;
    const float c3 = 2.33854883889f;
    const float c4 = -0.14611605f;
    const float c5 = -0.012308094f;
    const float c6 = -0.0164248277778f;
    const float c7 = 0.002211732f;
    const float c8 = 0.00072546f;
    const float c9 = -0.000003582f;
    
    float t = temperature;
    float h = humidity;
    
    float heatindex = c1 + c2*t + c3*h + c4*t*h + c5*t*t + c6*h*h + c7*t*t*h + c8*t*h*h + c9*t*t*h*h;
    
    return heatindex;
}

/**
 * @brief Ajout d'une lecture à l'historique
 */
static void add_to_history(const dht22_reading_enterprise_t* reading) {
    if (!reading) return;
    
    memcpy(&g_reading_history[g_history_write_index], reading, sizeof(dht22_reading_enterprise_t));
    g_history_write_index = (g_history_write_index + 1) % DHT22_CALIBRATION_SAMPLES;
    
    if (g_history_write_index == 0) {
        g_history_full = true;
    }
}

/**
 * @brief Validation des données avancée Enterprise
 */
static bool validate_reading_advanced(const dht22_reading_enterprise_t* reading) {
    if (!reading || !reading->is_valid) return false;
    
    // Validation des plages configurées
    if (reading->temperature < g_config_enterprise.temperature_min || 
        reading->temperature > g_config_enterprise.temperature_max) {
        return false;
    }
    
    if (reading->humidity < g_config_enterprise.humidity_min || 
        reading->humidity > g_config_enterprise.humidity_max) {
        return false;
    }
    
    // Validation du niveau de bruit
    if (reading->noise_level > g_config_enterprise.noise_threshold) {
        return false;
    }
    
    // Validation cohérence historique
    if (g_history_full || g_history_write_index > 2) {
        uint8_t prev_index = (g_history_write_index - 1 + DHT22_CALIBRATION_SAMPLES) % DHT22_CALIBRATION_SAMPLES;
        const dht22_reading_enterprise_t* prev = &g_reading_history[prev_index];
        
        if (prev->is_valid) {
            float temp_diff = fabsf(reading->temperature - prev->temperature);
            float humidity_diff = fabsf(reading->humidity - prev->humidity);
            
            // Seuils de cohérence (max 10°C/min et 20%/min)
            float time_diff = (float)(reading->timestamp - prev->timestamp) / 60.0f;
            if (time_diff > 0.1f) {
                float max_temp_change = 10.0f * time_diff;
                float max_humidity_change = 20.0f * time_diff;
                
                if (temp_diff > max_temp_change || humidity_diff > max_humidity_change) {
                    return false;
                }
            }
        }
    }
    
    return true;
}

/**
 * @brief Application de la calibration
 */
static void apply_calibration(dht22_reading_enterprise_t* reading) {
    if (!reading || !g_calibration_valid) return;
    
    reading->temperature_raw = reading->temperature;
    reading->humidity_raw = reading->humidity;
    
    reading->temperature_calibrated = (reading->temperature + g_temperature_offset) * g_temperature_gain;
    reading->humidity_calibrated = (reading->humidity + g_humidity_offset) * g_humidity_gain;
    
    // Limitation des plages après calibration
    reading->temperature_calibrated = fmaxf(fminf(reading->temperature_calibrated, 80.0f), -40.0f);
    reading->humidity_calibrated = fmaxf(fminf(reading->humidity_calibrated, 100.0f), 0.0f);
    
    reading->calibration_applied = true;
    
    // Mise à jour des valeurs principales
    reading->temperature = reading->temperature_calibrated;
    reading->humidity = reading->humidity_calibrated;
}

/**
 * @brief Calcul du score de qualité
 */
static uint8_t calculate_quality_score(const dht22_reading_enterprise_t* reading) {
    if (!reading || !reading->is_valid) return 0;
    
    uint8_t score = 100;
    
    // Pénalité pour retry
    if (reading->retry_count > 0) {
        score -= (reading->retry_count * 10);
    }
    
    // Pénalité pour temps de lecture élevé
    if (reading->read_duration_us > 5000) {
        score -= 10;
    }
    
    // Pénalité pour bruit
    if (reading->noise_level > 0.05f) {
        score -= (uint8_t)(reading->noise_level * 100);
    }
    
    // Bonus pour calibration
    if (reading->calibration_applied) {
        score = MIN(score + 5, 100);
    }
    
    // Pénalité pour erreurs récentes
    if (g_consecutive_errors > 0) {
        score -= (g_consecutive_errors * 5);
    }
    
    return MAX(score, 0);
}

/**
 * @brief Initialisation driver DHT22 Enterprise
 */
esp_err_t dht22_init_enterprise(const dht22_config_enterprise_t* config) {
    if (g_dht22_initialized) return ESP_OK;
    
    if (!config) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "🌡️ Initialisation DHT22 Enterprise GPIO %d", config->gpio_pin);
    
    // Création du mutex thread-safe
    g_dht22_mutex = xSemaphoreCreateMutex();
    if (g_dht22_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex DHT22");
        return ESP_FAIL;
    }
    
    memcpy(&g_config_enterprise, config, sizeof(dht22_config_enterprise_t));
    
    // Configuration GPIO données
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_INPUT_OUTPUT_OD,
        .pin_bit_mask = (1ULL << config->gpio_pin),
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    esp_err_t ret = gpio_config(&io_conf);
    if (ret != ESP_OK) {
        vSemaphoreDelete(g_dht22_mutex);
        return ret;
    }
    
    // Configuration GPIO alimentation si spécifié
    if (config->power_pin >= 0) {
        gpio_config_t power_conf = {
            .intr_type = GPIO_INTR_DISABLE,
            .mode = GPIO_MODE_OUTPUT,
            .pin_bit_mask = (1ULL << config->power_pin),
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .pull_up_en = GPIO_PULLUP_DISABLE,
        };
        ret = gpio_config(&power_conf);
        if (ret != ESP_OK) {
            vSemaphoreDelete(g_dht22_mutex);
            return ret;
        }
        
        if (config->power_management_enabled) {
            gpio_set_level(config->power_pin, 1); // Alimenter le capteur
            vTaskDelay(pdMS_TO_TICKS(100)); // Attendre stabilisation
        }
    }
    
    gpio_set_level(config->gpio_pin, 1);
    
    // Initialisation des variables globales
    g_last_read_time = 0;
    g_consecutive_errors = 0;
    g_last_error_time = 0;
    
    // Initialisation calibration
    g_temperature_offset = config->temperature_offset;
    g_humidity_offset = config->humidity_offset;
    g_temperature_gain = config->temperature_gain;
    g_humidity_gain = config->humidity_gain;
    g_calibration_valid = (g_temperature_offset != 0.0f || g_humidity_offset != 0.0f || 
                          g_temperature_gain != 1.0f || g_humidity_gain != 1.0f);
    
    // Initialisation statistiques
    memset(&g_stats_enterprise, 0, sizeof(dht22_stats_enterprise_t));
    g_stats_enterprise.min_temperature = 999.0f;
    g_stats_enterprise.max_temperature = -999.0f;
    g_stats_enterprise.min_humidity = 999.0f;
    g_stats_enterprise.max_humidity = -999.0f;
    
    // Initialisation historique
    memset(g_reading_history, 0, sizeof(g_reading_history));
    g_history_write_index = 0;
    g_history_full = false;
    
    g_dht22_initialized = true;
    
    ESP_LOGI(TAG, "✅ DHT22 Enterprise initialisé avec succès");
    ESP_LOGI(TAG, "   📐 Calibration: %s (T:%+.2f*%.3f, H:%+.2f*%.3f)", 
             g_calibration_valid ? "Activée" : "Désactivée",
             g_temperature_offset, g_temperature_gain,
             g_humidity_offset, g_humidity_gain);
    ESP_LOGI(TAG, "   ✅ Validation renforcée: %s", config->validation_enhanced ? "Activée" : "Désactivée");
    ESP_LOGI(TAG, "   📊 Monitoring: %s", config->monitoring_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "   🔋 Gestion alimentation: %s", config->power_management_enabled ? "Activée" : "Désactivée");
    
    return ESP_OK;
}

/**
 * @brief Dé-initialisation driver Enterprise
 */
esp_err_t dht22_deinit_enterprise(void) {
    if (!g_dht22_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "🔚 Dé-initialisation DHT22 Enterprise");
    
    // Couper alimentation si gérée
    if (g_config_enterprise.power_pin >= 0 && g_config_enterprise.power_management_enabled) {
        gpio_set_level(g_config_enterprise.power_pin, 0);
    }
    
    // Suppression mutex
    if (g_dht22_mutex != NULL) {
        vSemaphoreDelete(g_dht22_mutex);
        g_dht22_mutex = NULL;
    }
    
    g_dht22_initialized = false;
    
    ESP_LOGI(TAG, "✅ DHT22 Enterprise dé-initialisé");
    return ESP_OK;
}

/**
 * @brief Lecture DHT22 avec fonctionnalités Enterprise complètes
 */
esp_err_t dht22_read_enterprise(dht22_reading_enterprise_t* reading) {
    if (!g_dht22_initialized || !reading) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_dht22_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        ESP_LOGW(TAG, "⚠️ Timeout acquisition mutex DHT22");
        return ESP_ERR_TIMEOUT;
    }
    
    memset(reading, 0, sizeof(dht22_reading_enterprise_t));
    uint64_t start_time = esp_timer_get_time();
    
    // Vérification de l'intervalle minimum
    uint64_t current_time = esp_timer_get_time();
    if (current_time - g_last_read_time < (g_config_enterprise.read_interval_ms * 1000)) {
        reading->error_code = DHT22_ERROR_TOO_SOON;
        xSemaphoreGive(g_dht22_mutex);
        return ESP_ERR_INVALID_STATE;
    }
    
    // Gestion alimentation optimisée
    if (g_config_enterprise.power_pin >= 0 && g_config_enterprise.power_management_enabled) {
        gpio_set_level(g_config_enterprise.power_pin, 1);
        vTaskDelay(pdMS_TO_TICKS(10)); // Stabilisation
    }
    
    // Mise à jour des statistiques
    g_stats_enterprise.total_reads++;
    
    // Désactivation des interruptions pour timing précis
    portDISABLE_INTERRUPTS();
    
    // Signal de start - LOW pendant 1ms puis HIGH pendant 30µs
    gpio_set_direction(g_config_enterprise.gpio_pin, GPIO_MODE_OUTPUT);
    gpio_set_level(g_config_enterprise.gpio_pin, 0);
    esp_rom_delay_us(1000);
    gpio_set_level(g_config_enterprise.gpio_pin, 1);
    esp_rom_delay_us(30);
    
    // Passage en mode lecture
    gpio_set_direction(g_config_enterprise.gpio_pin, GPIO_MODE_INPUT);
    
    // Attente de la réponse du capteur (80µs LOW + 80µs HIGH)
    uint32_t timeout = 100;
    while (gpio_get_level(g_config_enterprise.gpio_pin) == 1 && timeout--) {
        esp_rom_delay_us(1);
    }
    if (timeout == 0) {
        portENABLE_INTERRUPTS();
        reading->error_code = DHT22_ERROR_NO_RESPONSE;
        g_stats_enterprise.failed_reads++;
        g_consecutive_errors++;
        xSemaphoreGive(g_dht22_mutex);
        return ESP_FAIL;
    }
    
    timeout = 100;
    while (gpio_get_level(g_config_enterprise.gpio_pin) == 0 && timeout--) {
        esp_rom_delay_us(1);
    }
    if (timeout == 0) {
        portENABLE_INTERRUPTS();
        reading->error_code = DHT22_ERROR_NO_RESPONSE;
        g_stats_enterprise.failed_reads++;
        g_consecutive_errors++;
        xSemaphoreGive(g_dht22_mutex);
        return ESP_FAIL;
    }
    
    timeout = 100;
    while (gpio_get_level(g_config_enterprise.gpio_pin) == 1 && timeout--) {
        esp_rom_delay_us(1);
    }
    if (timeout == 0) {
        portENABLE_INTERRUPTS();
        reading->error_code = DHT22_ERROR_NO_RESPONSE;
        g_stats_enterprise.failed_reads++;
        g_consecutive_errors++;
        xSemaphoreGive(g_dht22_mutex);
        return ESP_FAIL;
    }
    
    // Lecture des 40 bits de données
    uint8_t data[5] = {0};
    uint8_t timing_data[40]; // Pour analyse du signal
    
    for (int i = 0; i < 40; i++) {
        // Attendre la fin du LOW de synchronisation
        timeout = 100;
        while (gpio_get_level(g_config_enterprise.gpio_pin) == 0 && timeout--) {
            esp_rom_delay_us(1);
        }
        if (timeout == 0) {
            portENABLE_INTERRUPTS();
            reading->error_code = DHT22_ERROR_TIMEOUT;
            g_stats_enterprise.timeout_errors++;
            g_consecutive_errors++;
            xSemaphoreGive(g_dht22_mutex);
            return ESP_FAIL;
        }
        
        // Mesurer la durée du HIGH pour déterminer le bit
        uint32_t high_time = 0;
        while (gpio_get_level(g_config_enterprise.gpio_pin) == 1 && high_time < 100) {
            esp_rom_delay_us(1);
            high_time++;
        }
        
        timing_data[i] = (uint8_t)high_time;
        
        // Si HIGH > 40µs, c'est un '1', sinon '0'
        if (high_time > 40) {
            data[i / 8] |= (1 << (7 - (i % 8)));
        }
    }
    
    portENABLE_INTERRUPTS();
    
    // Vérification du checksum
    uint8_t checksum = data[0] + data[1] + data[2] + data[3];
    if (checksum != data[4]) {
        reading->error_code = DHT22_ERROR_CHECKSUM;
        reading->checksum_valid = false;
        g_stats_enterprise.checksum_errors++;
        g_consecutive_errors++;
        xSemaphoreGive(g_dht22_mutex);
        return ESP_FAIL;
    }
    
    reading->checksum_valid = true;
    
    // Extraction des données
    uint16_t humidity_raw = (data[0] << 8) | data[1];
    uint16_t temperature_raw = (data[2] << 8) | data[3];
    
    reading->humidity = humidity_raw / 10.0f;
    reading->temperature = temperature_raw / 10.0f;
    
    // Gestion du signe pour la température
    if (temperature_raw & 0x8000) {
        reading->temperature = -(reading->temperature);
    }
    
    // Métadonnées de lecture
    reading->timestamp = (uint32_t)(current_time / 1000000);
    reading->read_duration_us = (uint32_t)(esp_timer_get_time() - start_time);
    reading->is_valid = true;
    reading->error_code = DHT22_ERROR_NONE;
    
    // Calcul niveau de bruit basé sur variation timing
    float timing_variance = 0.0f;
    float timing_mean = 0.0f;
    for (int i = 0; i < 40; i++) {
        timing_mean += timing_data[i];
    }
    timing_mean /= 40.0f;
    
    for (int i = 0; i < 40; i++) {
        float diff = timing_data[i] - timing_mean;
        timing_variance += diff * diff;
    }
    timing_variance /= 40.0f;
    reading->noise_level = sqrtf(timing_variance) / 100.0f; // Normalisation
    
    // Validation plages
    reading->range_valid = (reading->temperature >= g_config_enterprise.temperature_min &&
                           reading->temperature <= g_config_enterprise.temperature_max &&
                           reading->humidity >= g_config_enterprise.humidity_min &&
                           reading->humidity <= g_config_enterprise.humidity_max);
    
    // Application calibration
    if (g_config_enterprise.calibration_enabled) {
        apply_calibration(reading);
    } else {
        reading->temperature_calibrated = reading->temperature;
        reading->humidity_calibrated = reading->humidity;
    }
    
    // Calcul données dérivées
    reading->dewpoint = dht22_calculate_dewpoint(reading->temperature, reading->humidity);
    reading->heatindex = dht22_calculate_heatindex(reading->temperature, reading->humidity);
    
    // Calcul humidité absolue (g/m³)
    float saturated_vapor_pressure = 6.112f * expf((17.67f * reading->temperature) / (reading->temperature + 243.5f));
    reading->absolute_humidity = (saturated_vapor_pressure * reading->humidity * 2.1674f) / (273.15f + reading->temperature);
    
    // Diagnostic Enterprise
    reading->signal_strength = 100 - (uint8_t)(reading->noise_level * 100);
    reading->timing_accuracy = 100 - MIN((uint8_t)(timing_variance), 50);
    reading->data_consistency = reading->range_valid ? 100 : 50;
    
    // Calcul score qualité
    reading->quality_score = calculate_quality_score(reading);
    
    // Validation avancée
    if (g_config_enterprise.validation_enhanced) {
        if (!validate_reading_advanced(reading)) {
            reading->error_code = DHT22_ERROR_VALIDATION_FAILED;
            reading->is_valid = false;
            g_stats_enterprise.failed_reads++;
            g_consecutive_errors++;
            xSemaphoreGive(g_dht22_mutex);
            return ESP_FAIL;
        }
    }
    
    // Mise à jour statistiques succès
    g_stats_enterprise.successful_reads++;
    g_stats_enterprise.avg_read_duration_us = ((g_stats_enterprise.avg_read_duration_us * (g_stats_enterprise.successful_reads - 1)) + reading->read_duration_us) / g_stats_enterprise.successful_reads;
    g_stats_enterprise.avg_temperature = ((g_stats_enterprise.avg_temperature * (g_stats_enterprise.successful_reads - 1)) + reading->temperature) / g_stats_enterprise.successful_reads;
    g_stats_enterprise.avg_humidity = ((g_stats_enterprise.avg_humidity * (g_stats_enterprise.successful_reads - 1)) + reading->humidity) / g_stats_enterprise.successful_reads;
    
    // Min/Max
    if (reading->temperature < g_stats_enterprise.min_temperature) g_stats_enterprise.min_temperature = reading->temperature;
    if (reading->temperature > g_stats_enterprise.max_temperature) g_stats_enterprise.max_temperature = reading->temperature;
    if (reading->humidity < g_stats_enterprise.min_humidity) g_stats_enterprise.min_humidity = reading->humidity;
    if (reading->humidity > g_stats_enterprise.max_humidity) g_stats_enterprise.max_humidity = reading->humidity;
    
    // Réinitialisation erreurs consécutives en cas de succès
    g_consecutive_errors = 0;
    g_last_read_time = current_time;
    
    // Ajout à l'historique
    add_to_history(reading);
    
    // Gestion alimentation
    if (g_config_enterprise.power_pin >= 0 && g_config_enterprise.power_management_enabled) {
        gpio_set_level(g_config_enterprise.power_pin, 0); // Couper alimentation pour économie
    }
    
    xSemaphoreGive(g_dht22_mutex);
    
    ESP_LOGD(TAG, "📊 DHT22 Enterprise: T=%.1f°C, H=%.1f%%, Q=%d, Bruit=%.3f", 
             reading->temperature, reading->humidity, reading->quality_score, reading->noise_level);
    
    return ESP_OK;
}

/**
 * @brief Fonctions de compatibilité avec version standard
 */
esp_err_t dht22_init(const dht22_config_t* config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    
    // Conversion vers configuration Enterprise
    dht22_config_enterprise_t enterprise_config = {
        .gpio_pin = config->gpio_pin,
        .power_pin = config->power_pin,
        .read_interval_ms = config->read_interval_ms,
        .max_retries = config->max_retries,
        .timeout_us = config->timeout_us,
        .calibration_enabled = false,
        .validation_enhanced = false,
        .monitoring_enabled = false,
        .power_management_enabled = false,
        .temperature_min = -40.0f,
        .temperature_max = 80.0f,
        .humidity_min = 0.0f,
        .humidity_max = 100.0f,
        .noise_threshold = 1.0f,
        .max_consecutive_errors = 10,
        .temperature_offset = 0.0f,
        .humidity_offset = 0.0f,
        .temperature_gain = 1.0f,
        .humidity_gain = 1.0f
    };
    
    return dht22_init_enterprise(&enterprise_config);
}

esp_err_t dht22_deinit(void) {
    return dht22_deinit_enterprise();
}

esp_err_t dht22_read(dht22_reading_t* reading) {
    if (!reading) return ESP_ERR_INVALID_ARG;
    
    dht22_reading_enterprise_t enterprise_reading;
    esp_err_t ret = dht22_read_enterprise(&enterprise_reading);
    
    if (ret == ESP_OK) {
        // Conversion vers format standard
        reading->temperature = enterprise_reading.temperature;
        reading->humidity = enterprise_reading.humidity;
        reading->timestamp = enterprise_reading.timestamp;
        reading->is_valid = enterprise_reading.is_valid;
        reading->error_code = (uint8_t)enterprise_reading.error_code;
    }
    
    return ret;
}

esp_err_t dht22_read_with_retry(dht22_reading_t* reading, uint8_t max_retries) {
    if (!reading) return ESP_ERR_INVALID_ARG;
    
    dht22_reading_enterprise_t enterprise_reading;
    esp_err_t ret = dht22_read_with_intelligent_retry(&enterprise_reading, max_retries);
    
    if (ret == ESP_OK) {
        reading->temperature = enterprise_reading.temperature;
        reading->humidity = enterprise_reading.humidity;
        reading->timestamp = enterprise_reading.timestamp;
        reading->is_valid = enterprise_reading.is_valid;
        reading->error_code = (uint8_t)enterprise_reading.error_code;
    }
    
    return ret;
}

bool dht22_is_data_valid(const dht22_reading_t* reading) {
    if (!reading || !reading->is_valid) return false;
    
    // Vérification des plages valides
    if (reading->temperature < -40.0f || reading->temperature > 80.0f) return false;
    if (reading->humidity < 0.0f || reading->humidity > 100.0f) return false;
    
    return true;
}

const char* dht22_error_to_string(uint8_t error_code) {
    return dht22_error_to_string_enterprise((dht22_error_code_enterprise_t)error_code);
}

// Fonctions Enterprise supplémentaires
esp_err_t dht22_read_with_intelligent_retry(dht22_reading_enterprise_t* reading, uint8_t max_retries) {
    if (!reading) return ESP_ERR_INVALID_ARG;
    
    esp_err_t ret = ESP_FAIL;
    uint8_t attempts = 0;
    uint32_t delay_ms = 100; // Délai initial
    
    do {
        ret = dht22_read_enterprise(reading);
        if (ret == ESP_OK) {
            reading->retry_count = attempts;
            break;
        }
        
        attempts++;
        if (attempts < max_retries) {
            ESP_LOGW(TAG, "🔄 Tentative DHT22 %d/%d échouée: %s", 
                     attempts, max_retries, dht22_error_to_string_enterprise((dht22_error_code_enterprise_t)reading->error_code));
            
            // Délai adaptatif
            vTaskDelay(pdMS_TO_TICKS(delay_ms));
            delay_ms = MIN(delay_ms * 2, 2000); // Backoff exponentiel max 2s
        }
    } while (attempts < max_retries);
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec lecture DHT22 Enterprise après %d tentatives", max_retries);
        reading->retry_count = attempts;
    }
    
    return ret;
}

esp_err_t dht22_calibrate_automatic(float reference_temp, float reference_humidity) {
    if (!g_dht22_initialized) return ESP_ERR_INVALID_STATE;
    
    ESP_LOGI(TAG, "📐 Calibration automatique DHT22 (Ref: T=%.1f°C, H=%.1f%%)", 
             reference_temp, reference_humidity);
    
    // Prendre plusieurs mesures pour calibration
    const uint8_t calibration_samples = 10;
    float temp_sum = 0.0f, humidity_sum = 0.0f;
    uint8_t valid_samples = 0;
    
    for (uint8_t i = 0; i < calibration_samples; i++) {
        dht22_reading_enterprise_t reading;
        if (dht22_read_enterprise(&reading) == ESP_OK && reading.is_valid) {
            temp_sum += reading.temperature_raw;
            humidity_sum += reading.humidity_raw;
            valid_samples++;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    if (valid_samples < (calibration_samples / 2)) {
        ESP_LOGE(TAG, "❌ Échec calibration: échantillons insuffisants (%d/%d)", valid_samples, calibration_samples);
        return ESP_FAIL;
    }
    
    // Calcul des offsets
    float avg_temp = temp_sum / valid_samples;
    float avg_humidity = humidity_sum / valid_samples;
    
    g_temperature_offset = reference_temp - avg_temp;
    g_humidity_offset = reference_humidity - avg_humidity;
    g_calibration_valid = true;
    
    g_stats_enterprise.calibration_count++;
    
    ESP_LOGI(TAG, "✅ Calibration terminée - Offsets: T=%+.2f°C, H=%+.2f%%", 
             g_temperature_offset, g_humidity_offset);
    
    return ESP_OK;
}

bool dht22_validate_data_enterprise(const dht22_reading_enterprise_t* reading) {
    return validate_reading_advanced(reading);
}

esp_err_t dht22_diagnose_health(uint8_t* health_score) {
    if (!health_score) return ESP_ERR_INVALID_ARG;
    
    if (!g_dht22_initialized) {
        *health_score = 0;
        return ESP_ERR_INVALID_STATE;
    }
    
    uint8_t score = 100;
    
    // Pénalité pour erreurs récentes
    if (g_consecutive_errors > 0) {
        score -= MIN(g_consecutive_errors * 10, 50);
    }
    
    // Pénalité basée sur taux d'erreur
    if (g_stats_enterprise.total_reads > 10) {
        float error_rate = (float)g_stats_enterprise.failed_reads / g_stats_enterprise.total_reads;
        score -= (uint8_t)(error_rate * 100);
    }
    
    // Pénalité pour temps de lecture élevé
    if (g_stats_enterprise.avg_read_duration_us > 10000) {
        score -= 10;
    }
    
    // Bonus pour calibration
    if (g_calibration_valid) {
        score = MIN(score + 5, 100);
    }
    
    *health_score = MAX(score, 0);
    
    ESP_LOGD(TAG, "💗 Diagnostic santé DHT22: %d%% (Erreurs: %lu, Taux: %.1f%%)", 
             *health_score, g_consecutive_errors, 
             g_stats_enterprise.total_reads > 0 ? (float)g_stats_enterprise.failed_reads / g_stats_enterprise.total_reads * 100 : 0);
    
    return ESP_OK;
}

esp_err_t dht22_power_management(bool enable) {
    if (!g_dht22_initialized || g_config_enterprise.power_pin < 0) {
        return ESP_ERR_INVALID_STATE;
    }
    
    gpio_set_level(g_config_enterprise.power_pin, enable ? 1 : 0);
    
    if (enable) {
        vTaskDelay(pdMS_TO_TICKS(10)); // Stabilisation
    }
    
    ESP_LOGD(TAG, "🔋 Alimentation DHT22: %s", enable ? "ON" : "OFF");
    
    return ESP_OK;
}

esp_err_t dht22_get_statistics_enterprise(dht22_stats_enterprise_t* stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_dht22_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(stats, &g_stats_enterprise, sizeof(dht22_stats_enterprise_t));
        stats->uptime_seconds = (uint32_t)(esp_timer_get_time() / 1000000);
        xSemaphoreGive(g_dht22_mutex);
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

esp_err_t dht22_configure_enterprise(const dht22_config_enterprise_t* config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "⚙️ Configuration DHT22 Enterprise mise à jour");
    
    if (xSemaphoreTake(g_dht22_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memcpy(&g_config_enterprise, config, sizeof(dht22_config_enterprise_t));
        
        // Mise à jour calibration
        g_temperature_offset = config->temperature_offset;
        g_humidity_offset = config->humidity_offset;
        g_temperature_gain = config->temperature_gain;
        g_humidity_gain = config->humidity_gain;
        g_calibration_valid = (g_temperature_offset != 0.0f || g_humidity_offset != 0.0f || 
                              g_temperature_gain != 1.0f || g_humidity_gain != 1.0f);
        
        xSemaphoreGive(g_dht22_mutex);
        return ESP_OK;
    }
    
    return ESP_ERR_TIMEOUT;
}

esp_err_t dht22_reset_calibration(void) {
    ESP_LOGI(TAG, "🔄 Réinitialisation calibration DHT22");
    
    g_temperature_offset = 0.0f;
    g_humidity_offset = 0.0f;
    g_temperature_gain = 1.0f;
    g_humidity_gain = 1.0f;
    g_calibration_valid = false;
    
    return ESP_OK;
}

const char* dht22_error_to_string_enterprise(dht22_error_code_enterprise_t error_code) {
    switch (error_code) {
        case DHT22_ERROR_NONE: return "Aucune erreur";
        case DHT22_ERROR_TIMEOUT: return "Timeout";
        case DHT22_ERROR_CHECKSUM: return "Erreur checksum";
        case DHT22_ERROR_NO_RESPONSE: return "Pas de réponse";
        case DHT22_ERROR_BAD_DATA: return "Données invalides";
        case DHT22_ERROR_TOO_SOON: return "Lecture trop rapprochée";
        case DHT22_ERROR_POWER_FAILURE: return "Défaillance alimentation";
        case DHT22_ERROR_GPIO_CONFIG: return "Erreur configuration GPIO";
        case DHT22_ERROR_CALIBRATION_FAILED: return "Échec calibration";
        case DHT22_ERROR_VALIDATION_FAILED: return "Échec validation";
        case DHT22_ERROR_CONSECUTIVE_ERRORS: return "Erreurs consécutives";
        case DHT22_ERROR_TEMPERATURE_OUT_OF_RANGE: return "Température hors plage";
        case DHT22_ERROR_HUMIDITY_OUT_OF_RANGE: return "Humidité hors plage";
        case DHT22_ERROR_NOISE_TOO_HIGH: return "Bruit trop élevé";
        case DHT22_ERROR_DRIFT_DETECTED: return "Dérive détectée";
        default: return "Erreur inconnue";
    }
}