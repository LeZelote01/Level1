/**
 * @file dht22_driver.h
 * @brief Driver DHT22 Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec validation renforcée, retry intelligent,
 * calibration automatique et monitoring performance.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
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

// ================================
// Constantes Enterprise
// ================================

#define DHT22_DRIVER_VERSION_ENTERPRISE "2.0.0"
#define DHT22_MAX_CONSECUTIVE_ERRORS    (10)     // Erreurs consécutives max
#define DHT22_TEMPERATURE_PRECISION     (0.1f)   // Précision température
#define DHT22_HUMIDITY_PRECISION        (0.1f)   // Précision humidité
#define DHT22_CALIBRATION_SAMPLES       (20)     // Échantillons calibration

// ================================
// Types Enterprise étendus
// ================================

/**
 * @brief Codes d'erreur DHT22 Enterprise étendus
 */
typedef enum {
    DHT22_ERROR_NONE = 0,
    DHT22_ERROR_TIMEOUT,
    DHT22_ERROR_CHECKSUM,
    DHT22_ERROR_NO_RESPONSE,
    DHT22_ERROR_BAD_DATA,
    DHT22_ERROR_TOO_SOON,
    // Erreurs Enterprise spécifiques
    DHT22_ERROR_POWER_FAILURE,
    DHT22_ERROR_GPIO_CONFIG,
    DHT22_ERROR_CALIBRATION_FAILED,
    DHT22_ERROR_VALIDATION_FAILED,
    DHT22_ERROR_CONSECUTIVE_ERRORS,
    DHT22_ERROR_TEMPERATURE_OUT_OF_RANGE,
    DHT22_ERROR_HUMIDITY_OUT_OF_RANGE,
    DHT22_ERROR_NOISE_TOO_HIGH,
    DHT22_ERROR_DRIFT_DETECTED
} dht22_error_code_enterprise_t;

/**
 * @brief Lecture DHT22 Enterprise étendues
 */
typedef struct {
    // Champs de base
    float temperature;                      // Température en °C
    float humidity;                         // Humidité en %
    uint32_t timestamp;                     // Timestamp de lecture
    bool is_valid;                          // Données valides
    uint8_t error_code;                     // Code d'erreur si applicable
    
    // Extensions Enterprise
    float temperature_raw;                  // Température brute (avant calibration)
    float humidity_raw;                     // Humidité brute (avant calibration)
    float temperature_calibrated;           // Température calibrée
    float humidity_calibrated;              // Humidité calibrée
    
    // Métadonnées de qualité
    uint8_t quality_score;                  // Score qualité (0-100)
    float noise_level;                      // Niveau de bruit
    uint8_t retry_count;                    // Nombre de tentatives
    uint32_t read_duration_us;              // Durée lecture en µs
    
    // Validation et diagnostic
    bool checksum_valid;                    // Checksum valide
    bool range_valid;                       // Plage valide
    bool calibration_applied;               // Calibration appliquée
    bool drift_detected;                    // Dérive détectée
    
    // Données dérivées
    float dewpoint;                         // Point de rosée
    float heatindex;                        // Indice de chaleur
    float absolute_humidity;                // Humidité absolue
    
    // Diagnostic Enterprise
    uint8_t signal_strength;                // Force du signal
    uint8_t timing_accuracy;                // Précision timing
    uint8_t data_consistency;               // Cohérence données
} dht22_reading_enterprise_t;

/**
 * @brief Configuration DHT22 Enterprise
 */
typedef struct {
    // Configuration de base
    int gpio_pin;                           // Pin GPIO pour données
    int power_pin;                          // Pin GPIO pour alimentation (-1 si non utilisé)
    uint32_t read_interval_ms;              // Intervalle minimum entre lectures
    uint8_t max_retries;                    // Nombre max de tentatives
    uint32_t timeout_us;                    // Timeout de lecture en µs
    
    // Configuration Enterprise
    bool calibration_enabled;               // Calibration automatique
    bool validation_enhanced;               // Validation renforcée
    bool monitoring_enabled;                // Monitoring performance
    bool power_management_enabled;          // Gestion alimentation
    
    // Seuils et limites Enterprise
    float temperature_min;                  // Température minimum valide
    float temperature_max;                  // Température maximum valide
    float humidity_min;                     // Humidité minimum valide
    float humidity_max;                     // Humidité maximum valide
    float noise_threshold;                  // Seuil bruit acceptable
    uint8_t max_consecutive_errors;         // Erreurs consécutives max
    
    // Calibration
    float temperature_offset;               // Offset température
    float humidity_offset;                  // Offset humidité
    float temperature_gain;                 // Gain température
    float humidity_gain;                    // Gain humidité
} dht22_config_enterprise_t;

/**
 * @brief Statistiques DHT22 Enterprise
 */
typedef struct {
    uint32_t total_reads;
    uint32_t successful_reads;
    uint32_t failed_reads;
    uint32_t checksum_errors;
    uint32_t timeout_errors;
    uint32_t range_errors;
    uint32_t consecutive_errors;
    float avg_read_duration_us;
    float avg_temperature;
    float avg_humidity;
    float min_temperature;
    float max_temperature;
    float min_humidity;
    float max_humidity;
    uint32_t calibration_count;
    uint32_t uptime_seconds;
} dht22_stats_enterprise_t;

// Structures de compatibilité
typedef struct {
    float temperature;
    float humidity;
    uint32_t timestamp;
    bool is_valid;
    uint8_t error_code;
} dht22_reading_t;

typedef struct {
    int gpio_pin;
    int power_pin;
    uint32_t read_interval_ms;
    uint8_t max_retries;
    uint32_t timeout_us;
} dht22_config_t;

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation driver DHT22 Enterprise
 * @param config Configuration Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_init_enterprise(const dht22_config_enterprise_t* config);

/**
 * @brief Dé-initialisation driver Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_deinit_enterprise(void);

/**
 * @brief Lecture DHT22 avec fonctionnalités Enterprise complètes
 * @param reading Lecture Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_read_enterprise(dht22_reading_enterprise_t* reading);

/**
 * @brief Lecture DHT22 avec retry intelligent et validation
 * @param reading Lecture Enterprise
 * @param max_retries Nombre maximum de tentatives
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_read_with_intelligent_retry(dht22_reading_enterprise_t* reading, uint8_t max_retries);

/**
 * @brief Calibration automatique DHT22 (Innovation Enterprise)
 * @param reference_temp Température de référence
 * @param reference_humidity Humidité de référence
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_calibrate_automatic(float reference_temp, float reference_humidity);

/**
 * @brief Validation données Enterprise avec contrôles étendus
 * @param reading Lecture à valider
 * @return true si données valides
 */
bool dht22_validate_data_enterprise(const dht22_reading_enterprise_t* reading);

/**
 * @brief Diagnostic santé capteur DHT22
 * @param health_score Score de santé (0-100)
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_diagnose_health(uint8_t* health_score);

/**
 * @brief Gestion alimentation optimisée
 * @param enable Activer/désactiver alimentation
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_power_management(bool enable);

/**
 * @brief Obtention statistiques Enterprise
 * @param stats Statistiques DHT22 Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_get_statistics_enterprise(dht22_stats_enterprise_t* stats);

/**
 * @brief Configuration Enterprise du capteur
 * @param config Nouvelle configuration
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_configure_enterprise(const dht22_config_enterprise_t* config);

/**
 * @brief Réinitialisation calibration
 * @return ESP_OK en cas de succès
 */
esp_err_t dht22_reset_calibration(void);

/**
 * @brief Calcul point de rosée
 * @param temperature Température en °C
 * @param humidity Humidité en %
 * @return Point de rosée en °C
 */
float dht22_calculate_dewpoint(float temperature, float humidity);

/**
 * @brief Calcul indice de chaleur
 * @param temperature Température en °C
 * @param humidity Humidité en %
 * @return Indice de chaleur en °C
 */
float dht22_calculate_heatindex(float temperature, float humidity);

/**
 * @brief Conversion code erreur vers texte Enterprise
 * @param error_code Code d'erreur Enterprise
 * @return Description textuelle
 */
const char* dht22_error_to_string_enterprise(dht22_error_code_enterprise_t error_code);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Initialisation (compatibilité)
 */
esp_err_t dht22_init(const dht22_config_t* config);

/**
 * @brief Dé-initialisation (compatibilité)
 */
esp_err_t dht22_deinit(void);

/**
 * @brief Lecture (compatibilité)
 */
esp_err_t dht22_read(dht22_reading_t* reading);

/**
 * @brief Lecture avec retry (compatibilité)
 */
esp_err_t dht22_read_with_retry(dht22_reading_t* reading, uint8_t max_retries);

/**
 * @brief Validation données (compatibilité)
 */
bool dht22_is_data_valid(const dht22_reading_t* reading);

/**
 * @brief Conversion erreur vers texte (compatibilité)
 */
const char* dht22_error_to_string(uint8_t error_code);

#ifdef __cplusplus
}
#endif

#endif /* DHT22_DRIVER_H */