/**
 * @file sensor_manager.h
 * @brief Gestionnaire de capteurs Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec validation avancée, calibration automatique,
 * redondance, monitoring temps réel et intégration crypto.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
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

// ================================
// Constantes Enterprise
// ================================

#define SENSOR_MANAGER_VERSION_ENTERPRISE "2.0.0"
#define MAX_SENSORS_ENTERPRISE                (8)      // Capteurs multiples
#define SENSOR_CALIBRATION_POINTS            (10)     // Points calibration
#define SENSOR_REDUNDANCY_THRESHOLD          (3)      // Seuil redondance
#define SENSOR_MONITORING_HISTORY_SIZE       (100)    // Historique monitoring

// Compatibilité version standard
#define MAX_SENSORS_STANDARD (1)

// ================================
// Types Enterprise étendus
// ================================

/**
 * @brief Types de capteurs Enterprise supportés
 */
typedef enum {
    SENSOR_TYPE_DHT22 = 0,
    SENSOR_TYPE_DS18B20,                    // Température précise
    SENSOR_TYPE_BME280,                     // Pression atmosphérique
    SENSOR_TYPE_SHT30,                      // Haute précision
    SENSOR_TYPE_ANALOG_TEMP,                // Température analogique
    SENSOR_TYPE_ANALOG_HUMIDITY,            // Humidité analogique
    SENSOR_TYPE_VIRTUAL,                    // Capteur virtuel
    SENSOR_TYPE_REDUNDANT                   // Capteur de redondance
} sensor_type_enterprise_t;

/**
 * @brief États de capteur Enterprise
 */
typedef enum {
    SENSOR_STATUS_UNKNOWN = 0,
    SENSOR_STATUS_HEALTHY,
    SENSOR_STATUS_WARNING,
    SENSOR_STATUS_ERROR,
    SENSOR_STATUS_CRITICAL,
    SENSOR_STATUS_MAINTENANCE,
    SENSOR_STATUS_CALIBRATING,
    SENSOR_STATUS_REDUNDANT_FAIL
} sensor_status_enterprise_t;

/**
 * @brief Niveau de qualité Enterprise
 */
typedef enum {
    SENSOR_QUALITY_INVALID = 0,             // 0-19
    SENSOR_QUALITY_POOR,                    // 20-39
    SENSOR_QUALITY_FAIR,                    // 40-59
    SENSOR_QUALITY_GOOD,                    // 60-79
    SENSOR_QUALITY_EXCELLENT,               // 80-89
    SENSOR_QUALITY_PERFECT                  // 90-100
} sensor_quality_level_t;

/**
 * @brief Données capteur Enterprise étendues
 */
typedef struct {
    // Champs de base
    float temperature;                      // Température en °C
    float humidity;                         // Humidité en %
    uint32_t timestamp;                     // Timestamp de lecture
    bool is_valid;                          // Données valides
    uint8_t sensor_id;                      // ID du capteur
    uint8_t quality_score;                  // Score de qualité (0-100)
    
    // Extensions Enterprise
    sensor_type_enterprise_t sensor_type;  // Type de capteur
    sensor_status_enterprise_t status;     // État du capteur
    sensor_quality_level_t quality_level;  // Niveau de qualité
    
    // Données supplémentaires
    float pressure;                         // Pression (si supportée)
    float dewpoint;                         // Point de rosée calculé
    float heatindex;                        // Indice de chaleur calculé
    
    // Métadonnées Enterprise
    float calibration_offset_temp;          // Offset calibration température
    float calibration_offset_humidity;      // Offset calibration humidité
    bool is_calibrated;                     // Capteur calibré
    bool is_redundant_validated;            // Validé par redondance
    uint8_t redundant_sensor_count;         // Nombre capteurs redondants
    
    // Tendances et dérivées
    float temperature_trend;                // Tendance température (°C/min)
    float humidity_trend;                   // Tendance humidité (%/min)
    float temperature_derivative;           // Dérivée température
    float humidity_derivative;              // Dérivée humidité
    
    // Diagnostic et monitoring
    uint32_t read_duration_us;              // Durée de lecture
    uint8_t retry_count;                    // Nombre tentatives
    uint8_t error_flags;                    // Flags d'erreur
    float noise_level;                      // Niveau de bruit
    
    // Sécurité et intégrité
    uint32_t data_hash;                     // Hash des données
    bool crypto_verified;                   // Vérifié cryptographiquement
    uint64_t sequence_number;               // Numéro de séquence
} sensor_data_t;

/**
 * @brief Configuration capteur Enterprise
 */
typedef struct {
    sensor_type_enterprise_t type;
    uint8_t sensor_id;
    int gpio_pin;
    int power_pin;
    uint32_t read_interval_ms;
    uint8_t max_retries;
    
    // Configuration Enterprise
    bool calibration_enabled;
    bool redundancy_enabled;
    bool crypto_verification_enabled;
    bool monitoring_enabled;
    float validation_tolerance;
    uint32_t monitoring_interval_ms;
    
    // Seuils
    float temperature_min;
    float temperature_max;
    float humidity_min;
    float humidity_max;
} sensor_config_enterprise_t;

/**
 * @brief Statistiques capteurs Enterprise
 */
typedef struct {
    // Statistiques de base
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
    
    // Statistiques Enterprise étendues
    uint32_t calibration_count;
    uint32_t redundancy_validations;
    uint32_t crypto_verifications;
    uint32_t anomaly_detections;
    float avg_read_duration_ms;
    float avg_quality_score;
    uint32_t consecutive_errors;
    uint32_t max_consecutive_errors;
    
    // Performance et diagnostic
    uint32_t uptime_seconds;
    sensor_status_enterprise_t overall_status;
    uint8_t active_sensor_count;
    float system_health_score;             // Score santé globale
    
    // Tendances
    float temperature_trend_24h;
    float humidity_trend_24h;
    uint32_t readings_last_24h;
} sensor_stats_enterprise_t;

/**
 * @brief Point de calibration
 */
typedef struct {
    float reference_temperature;
    float reference_humidity;
    float measured_temperature;
    float measured_humidity;
    uint32_t timestamp;
    bool is_valid;
} sensor_calibration_point_t;

/**
 * @brief Informations de calibration
 */
typedef struct {
    sensor_calibration_point_t points[SENSOR_CALIBRATION_POINTS];
    uint8_t point_count;
    float temperature_offset;
    float humidity_offset;
    float temperature_gain;
    float humidity_gain;
    uint32_t last_calibration_time;
    bool is_calibrated;
} sensor_calibration_info_t;

// Structures de compatibilité
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

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation du gestionnaire capteurs Enterprise
 * @param config Configuration Enterprise (NULL pour défaut)
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_manager_init_enterprise(const sensor_config_enterprise_t* config);

/**
 * @brief Dé-initialisation du gestionnaire Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_manager_deinit_enterprise(void);

/**
 * @brief Lecture capteur avec validation Enterprise avancée
 * @param sensor_id ID du capteur
 * @param data Données lues
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_read_enterprise(uint8_t sensor_id, sensor_data_t* data);

/**
 * @brief Lecture multi-capteurs avec redondance
 * @param data Données agrégées
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_read_redundant(sensor_data_t* data);

/**
 * @brief Calibration automatique capteur (Innovation Enterprise)
 * @param sensor_id ID du capteur
 * @param reference_temp Température de référence
 * @param reference_humidity Humidité de référence
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_calibrate_automatic(uint8_t sensor_id, float reference_temp, float reference_humidity);

/**
 * @brief Validation croisée avec redondance
 * @param primary_data Données capteur principal
 * @param is_valid Résultat validation
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_validate_redundancy(const sensor_data_t* primary_data, bool* is_valid);

/**
 * @brief Monitoring temps réel capteur
 * @param sensor_id ID du capteur
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_monitor_realtime(uint8_t sensor_id);

/**
 * @brief Diagnostic capteur avancé
 * @param sensor_id ID du capteur
 * @param status État diagnostiqué
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_diagnose_health(uint8_t sensor_id, sensor_status_enterprise_t* status);

/**
 * @brief Configuration capteur Enterprise
 * @param sensor_id ID du capteur
 * @param config Configuration
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_configure_enterprise(uint8_t sensor_id, const sensor_config_enterprise_t* config);

/**
 * @brief Obtention statistiques Enterprise
 * @param stats Statistiques Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_get_statistics_enterprise(sensor_stats_enterprise_t* stats);

/**
 * @brief Réinitialisation calibration
 * @param sensor_id ID du capteur
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_reset_calibration(uint8_t sensor_id);

/**
 * @brief Test intégrité données capteur
 * @param data Données à tester
 * @param is_valid Résultat test
 * @return ESP_OK en cas de succès
 */
esp_err_t sensor_verify_data_integrity(const sensor_data_t* data, bool* is_valid);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Initialisation (compatibilité)
 */
esp_err_t sensor_manager_init(void);

/**
 * @brief Dé-initialisation (compatibilité)
 */
esp_err_t sensor_manager_deinit(void);

/**
 * @brief Lecture DHT22 (compatibilité)
 */
esp_err_t sensor_read_dht22(sensor_data_t* data);

/**
 * @brief Obtention statistiques (compatibilité)
 */
esp_err_t sensor_get_statistics(sensor_stats_t* stats);

/**
 * @brief Réinitialisation statistiques (compatibilité)
 */
void sensor_reset_statistics(void);

/**
 * @brief Détection anomalie (compatibilité)
 */
bool sensor_is_anomaly(const sensor_data_t* current, const sensor_data_t* previous);

#ifdef __cplusplus
}
#endif

#endif /* SENSOR_MANAGER_H */