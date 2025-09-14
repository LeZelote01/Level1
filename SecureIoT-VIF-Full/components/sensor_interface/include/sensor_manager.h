/**
 * @file sensor_manager.h
 * @brief Gestionnaire de capteurs pour SecureIoT-VIF
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#ifndef SENSOR_MANAGER_H
#define SENSOR_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "dht22_driver.h"

typedef struct {
    float temperature;      // Température en °C
    float humidity;         // Humidité en %
    uint32_t timestamp;     // Timestamp de lecture
    bool is_valid;          // Données valides
    uint8_t sensor_id;      // ID du capteur
    uint8_t quality_score;  // Score de qualité (0-100)
} sensor_data_t;

typedef struct {
    uint32_t total_readings;
    uint32_t valid_readings;
    uint32_t error_readings;
    float avg_temperature;
    float avg_humidity;
    float min_temperature;
    float max_temperature;
    float min_humidity;
    float max_humidity;
    uint64_t last_reading_time;
} sensor_stats_t;

esp_err_t sensor_manager_init(void);
esp_err_t sensor_manager_deinit(void);
esp_err_t sensor_read_dht22(sensor_data_t* data);
esp_err_t sensor_get_statistics(sensor_stats_t* stats);
void sensor_reset_statistics(void);
bool sensor_is_anomaly(const sensor_data_t* current, const sensor_data_t* previous);

#ifdef __cplusplus
}
#endif

#endif /* SENSOR_MANAGER_H */