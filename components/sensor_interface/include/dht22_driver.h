/**
 * @file dht22_driver.h
 * @brief Driver DHT22 pour SecureIoT-VIF
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#ifndef DHT22_DRIVER_H
#define DHT22_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef struct {
    float temperature;      // Température en °C
    float humidity;         // Humidité en %
    uint32_t timestamp;     // Timestamp de lecture
    bool is_valid;          // Données valides
    uint8_t error_code;     // Code d'erreur si applicable
} dht22_reading_t;

typedef struct {
    int gpio_pin;           // Pin GPIO pour données
    int power_pin;          // Pin GPIO pour alimentation (-1 si non utilisé)
    uint32_t read_interval_ms; // Intervalle minimum entre lectures
    uint8_t max_retries;    // Nombre max de tentatives
    uint32_t timeout_us;    // Timeout de lecture en µs
} dht22_config_t;

esp_err_t dht22_init(const dht22_config_t* config);
esp_err_t dht22_deinit(void);
esp_err_t dht22_read(dht22_reading_t* reading);
esp_err_t dht22_read_with_retry(dht22_reading_t* reading, uint8_t max_retries);
bool dht22_is_data_valid(const dht22_reading_t* reading);
const char* dht22_error_to_string(uint8_t error_code);

#ifdef __cplusplus
}
#endif

#endif /* DHT22_DRIVER_H */