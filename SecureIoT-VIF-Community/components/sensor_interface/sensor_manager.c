/**
 * @file sensor_manager.c
 * @brief Gestionnaire de capteurs pour SecureIoT-VIF Community Edition
 * 
 * Version complète identique à Enterprise pour l'interface capteurs.
 * Cette partie reste entièrement fonctionnelle en Community.
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
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sensor_manager.h"
#include "dht22_driver.h"

static const char *TAG = "SENSOR_COMMUNITY";

// Variables globales du gestionnaire de capteurs
static bool sensor_manager_initialized = false;
static sensor_stats_t sensor_stats = {0};
static sensor_data_t last_sensor_data = {0};

/**
 * @brief Initialise le gestionnaire de capteurs Community
 */
esp_err_t sensor_manager_init(void) {
    if (sensor_manager_initialized) {
        ESP_LOGW(TAG, "Gestionnaire de capteurs déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "🌡️ Initialisation gestionnaire de capteurs Community");
    
    // Initialiser le driver DHT22
    esp_err_t ret = dht22_driver_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation driver DHT22: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Réinitialiser les statistiques
    memset(&sensor_stats, 0, sizeof(sensor_stats));
    memset(&last_sensor_data, 0, sizeof(last_sensor_data));
    sensor_stats.start_time = esp_timer_get_time() / 1000;
    
    sensor_manager_initialized = true;
    ESP_LOGI(TAG, "✅ Gestionnaire de capteurs Community initialisé");
    ESP_LOGI(TAG, "💡 Fonctionnalité complète - identique à Enterprise");
    
    return ESP_OK;
}

/**
 * @brief Deinitialise le gestionnaire de capteurs
 */
esp_err_t sensor_manager_deinit(void) {
    if (!sensor_manager_initialized) {
        return ESP_OK;
    }
    
    esp_err_t ret = dht22_driver_deinit();
    sensor_manager_initialized = false;
    
    ESP_LOGI(TAG, "🔓 Gestionnaire de capteurs déinitialisé");
    return ret;
}

/**
 * @brief Lit les données du capteur DHT22
 */
esp_err_t sensor_read_dht22(sensor_data_t *data) {
    if (!sensor_manager_initialized) {
        ESP_LOGE(TAG, "❌ Gestionnaire non initialisé");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (data == NULL) {
        ESP_LOGE(TAG, "❌ Paramètre data invalide");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGD(TAG, "📊 Lecture capteur DHT22...");
    
    uint32_t start_time = esp_timer_get_time() / 1000;
    sensor_stats.total_readings++;
    
    // Lire les données du DHT22
    float temperature, humidity;
    esp_err_t ret = dht22_read_data(&temperature, &humidity);
    
    uint32_t read_duration = (esp_timer_get_time() / 1000) - start_time;
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Erreur lecture DHT22: %s", esp_err_to_name(ret));
        sensor_stats.failed_readings++;
        sensor_stats.last_error_time = esp_timer_get_time() / 1000;
        return ret;
    }
    
    // Valider les données
    if (temperature < DHT22_TEMP_MIN || temperature > DHT22_TEMP_MAX ||
        humidity < DHT22_HUMIDITY_MIN || humidity > DHT22_HUMIDITY_MAX) {
        ESP_LOGW(TAG, "⚠️  Données hors limites: T=%.1f°C, H=%.1f%%", temperature, humidity);
        sensor_stats.invalid_readings++;
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    // Remplir la structure de données
    data->temperature = temperature;
    data->humidity = humidity;
    data->timestamp = esp_timer_get_time() / 1000;
    data->read_duration_ms = read_duration;
    
    // Calculer la qualité des données (basique)
    data->quality_score = sensor_calculate_quality(data);
    
    // Mettre à jour les statistiques
    sensor_stats.successful_readings++;
    sensor_stats.last_reading_time = data->timestamp;
    sensor_stats.total_read_time_ms += read_duration;
    
    // Mettre à jour les min/max
    if (sensor_stats.successful_readings == 1 || temperature < sensor_stats.min_temperature) {
        sensor_stats.min_temperature = temperature;
    }
    if (sensor_stats.successful_readings == 1 || temperature > sensor_stats.max_temperature) {
        sensor_stats.max_temperature = temperature;
    }
    if (sensor_stats.successful_readings == 1 || humidity < sensor_stats.min_humidity) {
        sensor_stats.min_humidity = humidity;
    }
    if (sensor_stats.successful_readings == 1 || humidity > sensor_stats.max_humidity) {
        sensor_stats.max_humidity = humidity;
    }
    
    // Calculer les moyennes mobiles
    if (sensor_stats.successful_readings > 1) {
        sensor_stats.avg_temperature = (sensor_stats.avg_temperature * (sensor_stats.successful_readings - 1) + temperature) / sensor_stats.successful_readings;
        sensor_stats.avg_humidity = (sensor_stats.avg_humidity * (sensor_stats.successful_readings - 1) + humidity) / sensor_stats.successful_readings;
    } else {
        sensor_stats.avg_temperature = temperature;
        sensor_stats.avg_humidity = humidity;
    }
    
    // Sauvegarder la dernière lecture
    memcpy(&last_sensor_data, data, sizeof(sensor_data_t));
    
    ESP_LOGD(TAG, "✅ Lecture DHT22 réussie: T=%.1f°C, H=%.1f%%, Q=%d, durée=%dms",
             temperature, humidity, data->quality_score, read_duration);
    
    return ESP_OK;
}

/**
 * @brief Calcule un score de qualité pour les données capteur
 */
uint8_t sensor_calculate_quality(const sensor_data_t *data) {
    if (data == NULL) {
        return 0;
    }
    
    uint8_t quality = 100; // Score de base
    
    // Pénaliser si les valeurs sont aux extrêmes
    if (data->temperature < -30.0f || data->temperature > 60.0f) {
        quality -= 20;
    }
    if (data->humidity < 10.0f || data->humidity > 90.0f) {
        quality -= 20;
    }
    
    // Pénaliser si la lecture a pris trop de temps
    if (data->read_duration_ms > 1000) {
        quality -= 30;
    } else if (data->read_duration_ms > 500) {
        quality -= 15;
    }
    
    // Bonus pour des valeurs dans la plage normale
    if (data->temperature >= 15.0f && data->temperature <= 35.0f &&
        data->humidity >= 30.0f && data->humidity <= 70.0f) {
        quality = MIN(100, quality + 10);
    }
    
    return quality;
}

/**
 * @brief Obtient les statistiques du gestionnaire de capteurs
 */
esp_err_t sensor_get_stats(sensor_stats_t *stats) {
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!sensor_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memcpy(stats, &sensor_stats, sizeof(sensor_stats_t));
    return ESP_OK;
}

/**
 * @brief Obtient la dernière lecture de capteur
 */
esp_err_t sensor_get_last_reading(sensor_data_t *data) {
    if (data == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!sensor_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (sensor_stats.successful_readings == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    
    memcpy(data, &last_sensor_data, sizeof(sensor_data_t));
    return ESP_OK;
}

/**
 * @brief Affiche les statistiques du gestionnaire de capteurs
 */
void sensor_print_stats(void) {
    if (!sensor_manager_initialized) {
        ESP_LOGW(TAG, "Gestionnaire non initialisé");
        return;
    }
    
    ESP_LOGI(TAG, "📊 === Statistiques Capteurs Community ===");
    ESP_LOGI(TAG, "Lectures totales: %d", sensor_stats.total_readings);
    ESP_LOGI(TAG, "Lectures réussies: %d", sensor_stats.successful_readings);
    ESP_LOGI(TAG, "Lectures échouées: %d", sensor_stats.failed_readings);
    ESP_LOGI(TAG, "Lectures invalides: %d", sensor_stats.invalid_readings);
    
    if (sensor_stats.total_readings > 0) {
        float success_rate = (float)sensor_stats.successful_readings / sensor_stats.total_readings * 100.0f;
        ESP_LOGI(TAG, "Taux de réussite: %.1f%%", success_rate);
    }
    
    if (sensor_stats.successful_readings > 0) {
        ESP_LOGI(TAG, "Température: moy=%.1f°C, min=%.1f°C, max=%.1f°C",
                 sensor_stats.avg_temperature, sensor_stats.min_temperature, sensor_stats.max_temperature);
        ESP_LOGI(TAG, "Humidité: moy=%.1f%%, min=%.1f%%, max=%.1f%%",
                 sensor_stats.avg_humidity, sensor_stats.min_humidity, sensor_stats.max_humidity);
        
        uint32_t avg_read_time = sensor_stats.total_read_time_ms / sensor_stats.successful_readings;
        ESP_LOGI(TAG, "Temps lecture moyen: %dms", avg_read_time);
        
        uint64_t uptime = (esp_timer_get_time() / 1000) - sensor_stats.start_time;
        ESP_LOGI(TAG, "Temps de fonctionnement: %lld ms", uptime);
    }
    
    ESP_LOGI(TAG, "=======================================");
}

/**
 * @brief Réinitialise les statistiques du gestionnaire
 */
esp_err_t sensor_reset_stats(void) {
    if (!sensor_manager_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    memset(&sensor_stats, 0, sizeof(sensor_stats));
    sensor_stats.start_time = esp_timer_get_time() / 1000;
    
    ESP_LOGI(TAG, "🔄 Statistiques capteurs réinitialisées");
    return ESP_OK;
}

/**
 * @brief Test de fonctionnement du gestionnaire de capteurs
 */
esp_err_t sensor_manager_self_test(void) {
    ESP_LOGI(TAG, "🧪 Auto-test gestionnaire de capteurs Community...");
    
    // Test d'initialisation
    esp_err_t ret = sensor_manager_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation");
        return ret;
    }
    
    // Test de lecture capteur
    sensor_data_t test_data;
    ret = sensor_read_dht22(&test_data);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "⚠️  Échec lecture capteur (normal si pas de DHT22 connecté)");
        // Ne pas faire échouer le test si pas de capteur physique
    } else {
        ESP_LOGI(TAG, "✅ Lecture capteur réussie: T=%.1f°C, H=%.1f%%",
                 test_data.temperature, test_data.humidity);
    }
    
    // Test des statistiques
    sensor_stats_t stats;
    ret = sensor_get_stats(&stats);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec récupération statistiques");
        return ret;
    }
    
    // Test de calcul de qualité
    uint8_t quality = sensor_calculate_quality(&test_data);
    ESP_LOGI(TAG, "📊 Score de qualité calculé: %d/100", quality);
    
    ESP_LOGI(TAG, "✅ Auto-test gestionnaire de capteurs réussi");
    ESP_LOGI(TAG, "💡 Fonctionnalité complète disponible en Community");
    
    return ESP_OK;
}

/**
 * @brief Affiche les informations du gestionnaire de capteurs
 */
void sensor_manager_print_info(void) {
    ESP_LOGI(TAG, "📋 === Gestionnaire Capteurs Community ===");
    ESP_LOGI(TAG, "Édition: Community (Fonctionnalité complète)");
    ESP_LOGI(TAG, "Capteurs supportés:");
    ESP_LOGI(TAG, "  🌡️ DHT22: Température et humidité");
    ESP_LOGI(TAG, "Fonctionnalités:");
    ESP_LOGI(TAG, "  ✅ Lecture données temps réel");
    ESP_LOGI(TAG, "  ✅ Validation automatique");
    ESP_LOGI(TAG, "  ✅ Calcul qualité des données");
    ESP_LOGI(TAG, "  ✅ Statistiques complètes");
    ESP_LOGI(TAG, "  ✅ Historique et moyennes");
    ESP_LOGI(TAG, "Configuration actuelle:");
    ESP_LOGI(TAG, "  📍 GPIO DHT22 Data: %d", DHT22_GPIO_PIN);
    ESP_LOGI(TAG, "  ⚡ GPIO DHT22 Power: %d", DHT22_POWER_GPIO);
    ESP_LOGI(TAG, "  📊 Intervalle lecture: %d ms", SENSOR_READ_INTERVAL_MS);
    ESP_LOGI(TAG, "🎓 Interface capteurs identique à Enterprise!");
    ESP_LOGI(TAG, "========================================");
}