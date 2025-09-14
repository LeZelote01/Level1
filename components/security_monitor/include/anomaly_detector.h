/**
 * @file anomaly_detector.h
 * @brief Détecteur d'anomalies comportementales pour SecureIoT-VIF
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "sensor_manager.h"

#define ANOMALY_HISTORY_SIZE        (100)
#define ANOMALY_WINDOW_SIZE         (10)

typedef enum {
    ANOMALY_TYPE_NONE = 0,
    ANOMALY_TYPE_SENSOR_DATA,       // Anomalie dans les données capteur
    ANOMALY_TYPE_SYSTEM_BEHAVIOR,   // Comportement système anormal
    ANOMALY_TYPE_SECURITY_PATTERN,  // Pattern de sécurité suspect
    ANOMALY_TYPE_COMMUNICATION,     // Communication anormale
    ANOMALY_TYPE_PERFORMANCE        // Performance dégradée
} anomaly_type_t;

typedef struct {
    bool is_anomaly;
    anomaly_type_t type;
    float anomaly_score;        // Score 0.0-1.0
    uint32_t timestamp;
    char description[128];
    uint8_t severity;           // 1=Low, 2=Medium, 3=High, 4=Critical
    uint32_t detection_time_ms;
} anomaly_result_t;

typedef struct {
    float sensor_data[ANOMALY_HISTORY_SIZE][2]; // [temp, humidity]
    uint32_t timestamps[ANOMALY_HISTORY_SIZE];
    uint32_t write_index;
    uint32_t sample_count;
    bool is_learning;
    uint64_t learning_start_time;
} anomaly_context_t;

esp_err_t anomaly_detector_init(void);
esp_err_t anomaly_detector_deinit(void);
anomaly_result_t anomaly_detect_sensor_data(const sensor_data_t* data);
anomaly_result_t anomaly_detect_system_behavior(void);
esp_err_t anomaly_update_baseline(const sensor_data_t* data);
esp_err_t anomaly_set_learning_mode(bool enable);
bool anomaly_is_learning_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* ANOMALY_DETECTOR_H */