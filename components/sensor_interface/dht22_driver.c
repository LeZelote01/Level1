/**
 * @file dht22_driver.c
 * @brief Implémentation du driver DHT22
 */

#include "dht22_driver.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "DHT22_DRIVER";
static bool g_dht22_initialized = false;
static dht22_config_t g_config;
static uint64_t g_last_read_time = 0;

// Codes d'erreur DHT22
#define DHT22_ERROR_NONE            (0)
#define DHT22_ERROR_TIMEOUT         (1)
#define DHT22_ERROR_CHECKSUM        (2)
#define DHT22_ERROR_NO_RESPONSE     (3)
#define DHT22_ERROR_BAD_DATA        (4)
#define DHT22_ERROR_TOO_SOON        (5)

esp_err_t dht22_init(const dht22_config_t* config) {
    if (g_dht22_initialized) return ESP_OK;
    
    if (!config) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGI(TAG, "Initialisation DHT22 GPIO %d", config->gpio_pin);
    
    memcpy(&g_config, config, sizeof(dht22_config_t));
    
    // Configuration GPIO données
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_INPUT_OUTPUT_OD,
        .pin_bit_mask = (1ULL << config->gpio_pin),
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    esp_err_t ret = gpio_config(&io_conf);
    if (ret != ESP_OK) return ret;
    
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
        if (ret != ESP_OK) return ret;
        
        gpio_set_level(config->power_pin, 1); // Alimenter le capteur
        vTaskDelay(pdMS_TO_TICKS(100)); // Attendre stabilisation
    }
    
    gpio_set_level(config->gpio_pin, 1);
    g_dht22_initialized = true;
    
    ESP_LOGI(TAG, "DHT22 initialisé avec succès");
    return ESP_OK;
}

esp_err_t dht22_deinit(void) {
    if (!g_dht22_initialized) return ESP_OK;
    
    if (g_config.power_pin >= 0) {
        gpio_set_level(g_config.power_pin, 0);
    }
    
    g_dht22_initialized = false;
    ESP_LOGI(TAG, "DHT22 dé-initialisé");
    return ESP_OK;
}

esp_err_t dht22_read(dht22_reading_t* reading) {
    if (!g_dht22_initialized || !reading) return ESP_ERR_INVALID_ARG;
    
    memset(reading, 0, sizeof(dht22_reading_t));
    
    // Vérification de l'intervalle minimum
    uint64_t current_time = esp_timer_get_time();
    if (current_time - g_last_read_time < (g_config.read_interval_ms * 1000)) {
        reading->error_code = DHT22_ERROR_TOO_SOON;
        return ESP_ERR_INVALID_STATE;
    }
    
    // Désactivation des interruptions pour timing précis
    portDISABLE_INTERRUPTS();
    
    // Signal de start - LOW pendant 1ms puis HIGH pendant 30µs
    gpio_set_direction(g_config.gpio_pin, GPIO_MODE_OUTPUT);
    gpio_set_level(g_config.gpio_pin, 0);
    esp_rom_delay_us(1000);
    gpio_set_level(g_config.gpio_pin, 1);
    esp_rom_delay_us(30);
    
    // Passage en mode lecture
    gpio_set_direction(g_config.gpio_pin, GPIO_MODE_INPUT);
    
    // Attente de la réponse du capteur (80µs LOW + 80µs HIGH)
    uint32_t timeout = 100;
    while (gpio_get_level(g_config.gpio_pin) == 1 && timeout--) {
        esp_rom_delay_us(1);
    }
    if (timeout == 0) {
        portENABLE_INTERRUPTS();
        reading->error_code = DHT22_ERROR_NO_RESPONSE;
        return ESP_FAIL;
    }
    
    timeout = 100;
    while (gpio_get_level(g_config.gpio_pin) == 0 && timeout--) {
        esp_rom_delay_us(1);
    }
    if (timeout == 0) {
        portENABLE_INTERRUPTS();
        reading->error_code = DHT22_ERROR_NO_RESPONSE;
        return ESP_FAIL;
    }
    
    timeout = 100;
    while (gpio_get_level(g_config.gpio_pin) == 1 && timeout--) {
        esp_rom_delay_us(1);
    }
    if (timeout == 0) {
        portENABLE_INTERRUPTS();
        reading->error_code = DHT22_ERROR_NO_RESPONSE;
        return ESP_FAIL;
    }
    
    // Lecture des 40 bits de données
    uint8_t data[5] = {0};
    for (int i = 0; i < 40; i++) {
        // Attendre la fin du LOW de synchronisation
        timeout = 100;
        while (gpio_get_level(g_config.gpio_pin) == 0 && timeout--) {
            esp_rom_delay_us(1);
        }
        if (timeout == 0) {
            portENABLE_INTERRUPTS();
            reading->error_code = DHT22_ERROR_TIMEOUT;
            return ESP_FAIL;
        }
        
        // Mesurer la durée du HIGH pour déterminer le bit
        uint32_t high_time = 0;
        while (gpio_get_level(g_config.gpio_pin) == 1 && high_time < 100) {
            esp_rom_delay_us(1);
            high_time++;
        }
        
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
        return ESP_FAIL;
    }
    
    // Extraction des données
    uint16_t humidity_raw = (data[0] << 8) | data[1];
    uint16_t temperature_raw = (data[2] << 8) | data[3];
    
    reading->humidity = humidity_raw / 10.0f;
    reading->temperature = temperature_raw / 10.0f;
    
    // Gestion du signe pour la température
    if (temperature_raw & 0x8000) {
        reading->temperature = -(reading->temperature);
    }
    
    reading->timestamp = (uint32_t)(current_time / 1000000);
    reading->is_valid = true;
    reading->error_code = DHT22_ERROR_NONE;
    
    g_last_read_time = current_time;
    
    ESP_LOGD(TAG, "DHT22: T=%.1f°C, H=%.1f%%", reading->temperature, reading->humidity);
    return ESP_OK;
}

esp_err_t dht22_read_with_retry(dht22_reading_t* reading, uint8_t max_retries) {
    if (!reading) return ESP_ERR_INVALID_ARG;
    
    esp_err_t ret = ESP_FAIL;
    uint8_t attempts = 0;
    
    do {
        ret = dht22_read(reading);
        if (ret == ESP_OK) break;
        
        attempts++;
        if (attempts < max_retries) {
            ESP_LOGW(TAG, "Tentative DHT22 %d/%d échouée: %s", 
                     attempts, max_retries, dht22_error_to_string(reading->error_code));
            vTaskDelay(pdMS_TO_TICKS(100)); // Attendre avant retry
        }
    } while (attempts < max_retries);
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Échec lecture DHT22 après %d tentatives", max_retries);
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
    switch (error_code) {
        case DHT22_ERROR_NONE: return "Aucune erreur";
        case DHT22_ERROR_TIMEOUT: return "Timeout";
        case DHT22_ERROR_CHECKSUM: return "Erreur checksum";
        case DHT22_ERROR_NO_RESPONSE: return "Pas de réponse";
        case DHT22_ERROR_BAD_DATA: return "Données invalides";
        case DHT22_ERROR_TOO_SOON: return "Lecture trop rapprochée";
        default: return "Erreur inconnue";
    }
}