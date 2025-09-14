/**
 * @file dht22_driver.c
 * @brief Driver DHT22 pour SecureIoT-VIF Community Edition
 * 
 * Driver complet identique à Enterprise - pas de simplification nécessaire.
 * Basé sur le fichier original du projet.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "driver/gpio.h"
#include "rom/ets_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include "dht22_driver.h"

static const char *TAG = "DHT22_COMMUNITY";

// Variables globales du driver DHT22
static bool dht22_initialized = false;
static dht22_stats_t dht22_stats = {0};

/**
 * @brief Initialise le driver DHT22
 */
esp_err_t dht22_driver_init(void) {
    if (dht22_initialized) {
        ESP_LOGW(TAG, "Driver DHT22 déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "🌡️ Initialisation driver DHT22 Community");
    ESP_LOGI(TAG, "📍 Configuration DHT22 sur GPIO %d", DHT22_GPIO_PIN);
    
    // Configuration GPIO pour DHT22
    gpio_config_t gpio_conf = {
        .pin_bit_mask = (1ULL << DHT22_GPIO_PIN),
        .mode = GPIO_MODE_INPUT_OUTPUT_OD,  // Open drain
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    
    esp_err_t ret = gpio_config(&gpio_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Erreur configuration GPIO DHT22: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Configuration GPIO d'alimentation (optionnel)
    if (DHT22_POWER_GPIO >= 0) {
        gpio_config_t power_conf = {
            .pin_bit_mask = (1ULL << DHT22_POWER_GPIO),
            .mode = GPIO_MODE_OUTPUT,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE
        };
        
        ret = gpio_config(&power_conf);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "❌ Erreur configuration GPIO power: %s", esp_err_to_name(ret));
            return ret;
        }
        
        // Activer l'alimentation du capteur
        gpio_set_level(DHT22_POWER_GPIO, 1);
        ESP_LOGI(TAG, "⚡ Alimentation DHT22 activée sur GPIO %d", DHT22_POWER_GPIO);
        
        // Attendre que le capteur se stabilise
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
    
    // Initialiser les statistiques
    memset(&dht22_stats, 0, sizeof(dht22_stats));
    dht22_stats.init_time = esp_timer_get_time() / 1000;
    
    // Test initial
    gpio_set_level(DHT22_GPIO_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    dht22_initialized = true;
    ESP_LOGI(TAG, "✅ Driver DHT22 Community initialisé");
    ESP_LOGI(TAG, "💡 Fonctionnalité complète - identique à Enterprise");
    
    return ESP_OK;
}

/**
 * @brief Deinitialise le driver DHT22
 */
esp_err_t dht22_driver_deinit(void) {
    if (!dht22_initialized) {
        return ESP_OK;
    }
    
    // Désactiver l'alimentation si utilisée
    if (DHT22_POWER_GPIO >= 0) {
        gpio_set_level(DHT22_POWER_GPIO, 0);
        ESP_LOGI(TAG, "⚡ Alimentation DHT22 désactivée");
    }
    
    dht22_initialized = false;
    ESP_LOGI(TAG, "🔓 Driver DHT22 déinitialisé");
    
    return ESP_OK;
}

/**
 * @brief Lit une impulsion sur le GPIO DHT22
 */
static uint32_t dht22_read_pulse(int level, uint32_t timeout_us) {
    uint32_t start_time = esp_timer_get_time();
    uint32_t current_time = start_time;
    
    // Attendre que le niveau change
    while (gpio_get_level(DHT22_GPIO_PIN) == level) {
        current_time = esp_timer_get_time();
        if ((current_time - start_time) > timeout_us) {
            return 0; // Timeout
        }
    }
    
    return current_time - start_time;
}

/**
 * @brief Lit les données du capteur DHT22
 */
esp_err_t dht22_read_data(float *temperature, float *humidity) {
    if (!dht22_initialized) {
        ESP_LOGE(TAG, "❌ Driver DHT22 non initialisé");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (temperature == NULL || humidity == NULL) {
        ESP_LOGE(TAG, "❌ Paramètres invalides");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGD(TAG, "📊 Début lecture DHT22...");
    
    uint32_t start_time = esp_timer_get_time() / 1000;
    dht22_stats.total_reads++;
    
    uint8_t data[5] = {0};
    uint32_t pulse_durations[40];
    
    // Désactiver les interruptions pour un timing précis
    portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
    portENTER_CRITICAL(&mux);
    
    // Phase 1: Signal de démarrage
    gpio_set_level(DHT22_GPIO_PIN, 0);  // LOW pendant 1ms
    ets_delay_us(1000);
    
    gpio_set_level(DHT22_GPIO_PIN, 1);  // HIGH pendant 30µs
    ets_delay_us(30);
    
    // Phase 2: Attendre la réponse du capteur
    // Attendre que DHT22 mette la ligne à LOW
    uint32_t timeout = dht22_read_pulse(1, 100);
    if (timeout == 0) {
        portEXIT_CRITICAL(&mux);
        ESP_LOGE(TAG, "❌ Timeout attente réponse DHT22");
        dht22_stats.failed_reads++;
        return ESP_ERR_TIMEOUT;
    }
    
    // Attendre le signal HIGH de préparation (80µs)
    timeout = dht22_read_pulse(0, 100);
    if (timeout == 0) {
        portEXIT_CRITICAL(&mux);
        ESP_LOGE(TAG, "❌ Timeout signal préparation DHT22");
        dht22_stats.failed_reads++;
        return ESP_ERR_TIMEOUT;
    }
    
    // Attendre le signal LOW de fin préparation (80µs)
    timeout = dht22_read_pulse(1, 100);
    if (timeout == 0) {
        portEXIT_CRITICAL(&mux);
        ESP_LOGE(TAG, "❌ Timeout fin préparation DHT22");
        dht22_stats.failed_reads++;
        return ESP_ERR_TIMEOUT;
    }
    
    // Phase 3: Lecture des 40 bits de données
    for (int i = 0; i < 40; i++) {
        // Chaque bit commence par un LOW de 50µs
        uint32_t low_duration = dht22_read_pulse(0, 70);
        if (low_duration == 0) {
            portEXIT_CRITICAL(&mux);
            ESP_LOGE(TAG, "❌ Timeout bit %d (LOW)", i);
            dht22_stats.failed_reads++;
            return ESP_ERR_TIMEOUT;
        }
        
        // Puis un HIGH dont la durée détermine le bit (26-28µs=0, 70µs=1)
        uint32_t high_duration = dht22_read_pulse(1, 80);
        if (high_duration == 0) {
            portEXIT_CRITICAL(&mux);
            ESP_LOGE(TAG, "❌ Timeout bit %d (HIGH)", i);
            dht22_stats.failed_reads++;
            return ESP_ERR_TIMEOUT;
        }
        
        pulse_durations[i] = high_duration;
    }
    
    portEXIT_CRITICAL(&mux);
    
    // Phase 4: Décodage des données
    for (int i = 0; i < 40; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        
        // Si l'impulsion HIGH > 40µs, c'est un bit 1
        if (pulse_durations[i] > 40) {
            data[byte_idx] |= (1 << bit_idx);
        }
    }
    
    // Phase 5: Vérification du checksum
    uint8_t checksum = data[0] + data[1] + data[2] + data[3];
    if (checksum != data[4]) {
        ESP_LOGE(TAG, "❌ Erreur checksum DHT22: calculé=0x%02X, reçu=0x%02X", 
                 checksum, data[4]);
        dht22_stats.checksum_errors++;
        return ESP_ERR_INVALID_CRC;
    }
    
    // Phase 6: Conversion des données
    // Humidité: 16 bits (bytes 0-1)
    uint16_t humidity_raw = (data[0] << 8) | data[1];
    *humidity = (float)humidity_raw / 10.0f;
    
    // Température: 16 bits (bytes 2-3), bit 15 = signe
    uint16_t temperature_raw = (data[2] << 8) | data[3];
    if (temperature_raw & 0x8000) {
        // Température négative
        temperature_raw &= 0x7FFF;
        *temperature = -((float)temperature_raw / 10.0f);
    } else {
        // Température positive
        *temperature = (float)temperature_raw / 10.0f;
    }
    
    // Vérification des plages
    if (*temperature < DHT22_TEMP_MIN || *temperature > DHT22_TEMP_MAX ||
        *humidity < DHT22_HUMIDITY_MIN || *humidity > DHT22_HUMIDITY_MAX) {
        ESP_LOGW(TAG, "⚠️  Valeurs hors plage: T=%.1f°C, H=%.1f%%", *temperature, *humidity);
        dht22_stats.out_of_range_reads++;
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    // Mise à jour des statistiques
    uint32_t read_duration = (esp_timer_get_time() / 1000) - start_time;
    dht22_stats.successful_reads++;
    dht22_stats.last_read_time = esp_timer_get_time() / 1000;
    dht22_stats.total_read_time_ms += read_duration;
    
    // Mise à jour min/max
    if (dht22_stats.successful_reads == 1 || *temperature < dht22_stats.min_temperature) {
        dht22_stats.min_temperature = *temperature;
    }
    if (dht22_stats.successful_reads == 1 || *temperature > dht22_stats.max_temperature) {
        dht22_stats.max_temperature = *temperature;
    }
    if (dht22_stats.successful_reads == 1 || *humidity < dht22_stats.min_humidity) {
        dht22_stats.min_humidity = *humidity;
    }
    if (dht22_stats.successful_reads == 1 || *humidity > dht22_stats.max_humidity) {
        dht22_stats.max_humidity = *humidity;
    }
    
    ESP_LOGD(TAG, "✅ DHT22 lu avec succès: T=%.1f°C, H=%.1f%% (durée=%dms)",
             *temperature, *humidity, read_duration);
    
    return ESP_OK;
}

/**
 * @brief Obtient les statistiques du driver DHT22
 */
esp_err_t dht22_get_stats(dht22_stats_t *stats) {
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!dht22_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memcpy(stats, &dht22_stats, sizeof(dht22_stats_t));
    return ESP_OK;
}

/**
 * @brief Affiche les statistiques du driver DHT22
 */
void dht22_print_stats(void) {
    if (!dht22_initialized) {
        ESP_LOGW(TAG, "Driver DHT22 non initialisé");
        return;
    }
    
    ESP_LOGI(TAG, "📊 === Statistiques DHT22 Community ===");
    ESP_LOGI(TAG, "Lectures totales: %d", dht22_stats.total_reads);
    ESP_LOGI(TAG, "Lectures réussies: %d", dht22_stats.successful_reads);
    ESP_LOGI(TAG, "Lectures échouées: %d", dht22_stats.failed_reads);
    ESP_LOGI(TAG, "Erreurs checksum: %d", dht22_stats.checksum_errors);
    ESP_LOGI(TAG, "Lectures hors plage: %d", dht22_stats.out_of_range_reads);
    
    if (dht22_stats.total_reads > 0) {
        float success_rate = (float)dht22_stats.successful_reads / dht22_stats.total_reads * 100.0f;
        ESP_LOGI(TAG, "Taux de réussite: %.1f%%", success_rate);
    }
    
    if (dht22_stats.successful_reads > 0) {
        ESP_LOGI(TAG, "Température: min=%.1f°C, max=%.1f°C",
                 dht22_stats.min_temperature, dht22_stats.max_temperature);
        ESP_LOGI(TAG, "Humidité: min=%.1f%%, max=%.1f%%",
                 dht22_stats.min_humidity, dht22_stats.max_humidity);
        
        uint32_t avg_read_time = dht22_stats.total_read_time_ms / dht22_stats.successful_reads;
        ESP_LOGI(TAG, "Temps lecture moyen: %dms", avg_read_time);
    }
    
    ESP_LOGI(TAG, "===================================");
}

/**
 * @brief Réinitialise les statistiques du driver DHT22
 */
esp_err_t dht22_reset_stats(void) {
    if (!dht22_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memset(&dht22_stats, 0, sizeof(dht22_stats));
    dht22_stats.init_time = esp_timer_get_time() / 1000;
    
    ESP_LOGI(TAG, "🔄 Statistiques DHT22 réinitialisées");
    return ESP_OK;
}

/**
 * @brief Test de fonctionnement du driver DHT22
 */
esp_err_t dht22_self_test(void) {
    ESP_LOGI(TAG, "🧪 Auto-test driver DHT22 Community...");
    
    // Test d'initialisation
    esp_err_t ret = dht22_driver_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation driver");
        return ret;
    }
    
    // Test de lecture (peut échouer si pas de capteur physique)
    float temperature, humidity;
    ret = dht22_read_data(&temperature, &humidity);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "⚠️  Échec lecture DHT22 (normal si pas de capteur connecté)");
        ESP_LOGW(TAG, "🔌 Vérifiez les connexions:");
        ESP_LOGW(TAG, "   GPIO %d → DHT22 Data", DHT22_GPIO_PIN);
        if (DHT22_POWER_GPIO >= 0) {
            ESP_LOGW(TAG, "   GPIO %d → DHT22 Power", DHT22_POWER_GPIO);
        }
        ESP_LOGW(TAG, "   3.3V → DHT22 VCC");
        ESP_LOGW(TAG, "   GND → DHT22 GND");
        // Ne pas faire échouer le test
    } else {
        ESP_LOGI(TAG, "✅ Lecture DHT22 réussie: T=%.1f°C, H=%.1f%%", temperature, humidity);
    }
    
    // Test des statistiques
    dht22_stats_t stats;
    ret = dht22_get_stats(&stats);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec récupération statistiques");
        return ret;
    }
    
    ESP_LOGI(TAG, "✅ Auto-test driver DHT22 terminé");
    ESP_LOGI(TAG, "💡 Driver complet disponible en Community");
    
    return ESP_OK;
}

/**
 * @brief Affiche les informations du driver DHT22
 */
void dht22_print_info(void) {
    ESP_LOGI(TAG, "📋 === Driver DHT22 Community ===");
    ESP_LOGI(TAG, "Capteur: DHT22 (AM2302)");
    ESP_LOGI(TAG, "Type: Température et humidité numérique");
    ESP_LOGI(TAG, "Précision: ±0.5°C, ±2-5%RH");
    ESP_LOGI(TAG, "Plage: -40 à +80°C, 0 à 100%RH");
    ESP_LOGI(TAG, "Configuration:");
    ESP_LOGI(TAG, "  📍 GPIO Data: %d", DHT22_GPIO_PIN);
    if (DHT22_POWER_GPIO >= 0) {
        ESP_LOGI(TAG, "  ⚡ GPIO Power: %d", DHT22_POWER_GPIO);
    }
    ESP_LOGI(TAG, "Fonctionnalités:");
    ESP_LOGI(TAG, "  ✅ Lecture température/humidité");
    ESP_LOGI(TAG, "  ✅ Vérification checksum automatique");
    ESP_LOGI(TAG, "  ✅ Validation plages de données");
    ESP_LOGI(TAG, "  ✅ Statistiques complètes");
    ESP_LOGI(TAG, "  ✅ Gestion d'erreurs robuste");
    ESP_LOGI(TAG, "🎓 Identique à Enterprise Edition!");
    ESP_LOGI(TAG, "===============================");
}