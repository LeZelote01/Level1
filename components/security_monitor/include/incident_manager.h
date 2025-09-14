/**
 * @file incident_manager.h
 * @brief Gestionnaire d'incidents de sécurité pour SecureIoT-VIF
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#ifndef INCIDENT_MANAGER_H
#define INCIDENT_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "app_config.h"

typedef struct {
    security_event_type_t type;
    uint32_t timestamp;
    uint8_t severity;
    char description[128];
    uint8_t data[64];
    size_t data_len;
} security_event_t;

typedef struct {
    uint32_t total_incidents;
    uint32_t critical_incidents;
    uint32_t resolved_incidents;
    uint32_t active_incidents;
    uint64_t last_incident_time;
    uint32_t integrity_failures;
    uint32_t anomaly_detections;
    uint32_t attestation_failures;
} incident_stats_t;

esp_err_t incident_manager_init(void);
esp_err_t incident_manager_deinit(void);
esp_err_t incident_handle_integrity_failure(const security_event_t* event);
esp_err_t incident_handle_anomaly(const security_event_t* event);
esp_err_t incident_handle_attestation_failure(const security_event_t* event);
esp_err_t incident_handle_unauthorized_access(const security_event_t* event);
esp_err_t incident_get_statistics(incident_stats_t* stats);

#ifdef __cplusplus
}
#endif

#endif /* INCIDENT_MANAGER_H */