/**
 * @file incident_manager.h
 * @brief Gestionnaire d'incidents de sécurité Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec gestion avancée des incidents, escalade automatique,
 * réponse adaptative et intégration compliance.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
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

// ================================
// Constantes Enterprise
// ================================

#define INCIDENT_MANAGER_VERSION_ENTERPRISE "2.0.0"
#define MAX_CONCURRENT_INCIDENTS_ENTERPRISE (32)    // Incidents simultanés max
#define INCIDENT_DESCRIPTION_SIZE_ENTERPRISE (512)  // Descriptions étendues
#define INCIDENT_FORENSICS_DATA_SIZE        (1024)  // Données forensiques
#define MAX_INCIDENT_HISTORY_ENTERPRISE     (100)   // Historique incidents

// Compatibilité version standard  
#define MAX_CONCURRENT_INCIDENTS (16)
#define INCIDENT_DESCRIPTION_SIZE (128)

// ================================
// Types Enterprise étendus
// ================================

/**
 * @brief Types d'incidents Enterprise étendus
 */
typedef enum {
    INCIDENT_TYPE_INTEGRITY_FAILURE = 0,
    INCIDENT_TYPE_ATTESTATION_FAILURE,
    INCIDENT_TYPE_ANOMALY_DETECTED,
    INCIDENT_TYPE_UNAUTHORIZED_ACCESS,
    INCIDENT_TYPE_SENSOR_MALFUNCTION,
    INCIDENT_TYPE_COMMUNICATION_FAILURE,
    INCIDENT_TYPE_TAMPERING_DETECTED,
    INCIDENT_TYPE_POWER_ANOMALY,
    INCIDENT_TYPE_MEMORY_CORRUPTION,
    INCIDENT_TYPE_CRYPTO_ERROR,
    INCIDENT_TYPE_EFUSE_CORRUPTION,
    INCIDENT_TYPE_SECURE_BOOT_FAILURE,
    // Types Enterprise spécifiques
    INCIDENT_TYPE_REALTIME_INTEGRITY_FAIL,
    INCIDENT_TYPE_CONTINUOUS_ATTESTATION_FAIL,
    INCIDENT_TYPE_BEHAVIORAL_ANOMALY,
    INCIDENT_TYPE_ML_MODEL_DRIFT,
    INCIDENT_TYPE_PERFORMANCE_DEGRADATION,
    INCIDENT_TYPE_EMERGENCY_SHUTDOWN,
    INCIDENT_TYPE_TAMPER_DETECTION,
    INCIDENT_TYPE_COMPLIANCE_VIOLATION,
    INCIDENT_TYPE_SECURITY_POLICY_BREACH,
    INCIDENT_TYPE_FORENSIC_EVIDENCE_REQUIRED
} incident_type_enterprise_t;

/**
 * @brief États d'incident Enterprise
 */
typedef enum {
    INCIDENT_STATUS_NEW = 0,
    INCIDENT_STATUS_INVESTIGATING,
    INCIDENT_STATUS_RESPONDING,
    INCIDENT_STATUS_MITIGATING,
    INCIDENT_STATUS_RESOLVED,
    INCIDENT_STATUS_CLOSED,
    // États Enterprise spécifiques
    INCIDENT_STATUS_ESCALATED,
    INCIDENT_STATUS_COMPLIANCE_REVIEW,
    INCIDENT_STATUS_FORENSIC_ANALYSIS,
    INCIDENT_STATUS_LEGAL_HOLD,
    INCIDENT_STATUS_AUDIT_REQUIRED
} incident_status_enterprise_t;

/**
 * @brief Niveaux de réponse Enterprise
 */
typedef enum {
    RESPONSE_LEVEL_NONE = 0,
    RESPONSE_LEVEL_LOG_ONLY,
    RESPONSE_LEVEL_MONITOR,
    RESPONSE_LEVEL_ALERT,
    RESPONSE_LEVEL_MITIGATE,
    RESPONSE_LEVEL_ISOLATE,
    RESPONSE_LEVEL_EMERGENCY_SHUTDOWN,
    RESPONSE_LEVEL_FORENSIC_CAPTURE
} incident_response_level_t;

/**
 * @brief Événement de sécurité Enterprise étendu
 */
typedef struct {
    security_event_type_t type;
    uint32_t timestamp;
    uint8_t severity;
    char description[INCIDENT_DESCRIPTION_SIZE_ENTERPRISE];
    uint8_t data[256];                      // Doublé vs Community
    size_t data_len;
    
    // Extensions Enterprise
    float confidence_score;                 // Confiance événement
    uint32_t source_component;              // Composant source
    incident_response_level_t response_level; // Niveau réponse
    bool forensic_capture_required;         // Capture forensique nécessaire
    uint32_t correlation_id;                // ID corrélation événements
    
    // Données forensiques
    uint8_t forensic_data[INCIDENT_FORENSICS_DATA_SIZE];
    size_t forensic_data_len;
    uint32_t chain_of_custody_id;           // ID chaîne de custody
    
    // Métadonnées compliance
    bool compliance_relevant;               // Pertinent pour compliance
    uint32_t regulation_codes[8];           // Codes réglementations
    uint8_t regulation_count;               // Nombre réglementations
} security_event_enterprise_t;

/**
 * @brief Incident Enterprise complet
 */
typedef struct {
    uint32_t incident_id;
    incident_type_enterprise_t type;
    incident_status_enterprise_t status;
    uint8_t severity;                       // 1-5 (5=Emergency)
    uint32_t start_time;
    uint32_t last_update_time;
    uint32_t resolution_time;
    
    // Description et contexte
    char title[128];
    char description[INCIDENT_DESCRIPTION_SIZE_ENTERPRISE];
    char resolution_summary[256];
    
    // Événements associés
    uint32_t event_count;
    uint32_t event_ids[16];                 // IDs événements liés
    
    // Réponse et mitigation
    incident_response_level_t response_level;
    char mitigation_actions[512];
    bool automated_response_triggered;
    
    // Escalade
    bool escalated;
    uint32_t escalation_time;
    char escalation_reason[256];
    
    // Forensique et compliance
    bool forensic_evidence_collected;
    uint32_t forensic_package_id;
    bool compliance_notification_sent;
    uint32_t compliance_case_id;
    
    // Métriques
    uint32_t detection_time_ms;
    uint32_t response_time_ms;
    uint32_t resolution_time_ms;
    float impact_score;                     // Impact business
} incident_enterprise_t;

/**
 * @brief Statistiques d'incidents Enterprise
 */
typedef struct {
    // Statistiques de base
    uint32_t total_incidents;
    uint32_t critical_incidents;
    uint32_t resolved_incidents;
    uint32_t active_incidents;
    uint64_t last_incident_time;
    uint32_t integrity_failures;
    uint32_t anomaly_detections;
    uint32_t attestation_failures;
    
    // Statistiques Enterprise étendues
    uint32_t emergency_incidents;
    uint32_t escalated_incidents;
    uint32_t compliance_incidents;
    uint32_t forensic_cases;
    float avg_detection_time_ms;
    float avg_response_time_ms;
    float avg_resolution_time_ms;
    
    // Efficacité et performance
    float incident_resolution_rate;         // Taux résolution
    float false_positive_rate;              // Taux faux positifs
    float automated_response_rate;          // Taux réponse automatisée
    uint32_t repeat_incidents;              // Incidents récurrents
    
    // Compliance et audit
    uint32_t compliance_violations;
    uint32_t audit_findings;
    uint32_t regulatory_reports_sent;
    
    // Tendances (sur 24h)
    uint32_t incidents_last_24h;
    uint32_t critical_incidents_last_24h;
    float incident_trend_score;             // Tendance incidents
} incident_stats_enterprise_t;

/**
 * @brief Configuration Enterprise du gestionnaire d'incidents
 */
typedef struct {
    bool automated_response_enabled;
    bool forensic_capture_enabled;
    bool compliance_monitoring_enabled;
    bool escalation_enabled;
    uint32_t auto_escalation_time_ms;
    uint32_t incident_retention_days;
    incident_response_level_t default_response_level;
    bool real_time_notification_enabled;
} incident_config_enterprise_t;

// Structures de compatibilité
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

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation du gestionnaire d'incidents Enterprise
 * @param config Configuration Enterprise (NULL pour défaut)
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_manager_init_enterprise(const incident_config_enterprise_t* config);

/**
 * @brief Dé-initialisation du gestionnaire Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_manager_deinit_enterprise(void);

/**
 * @brief Gestion incident intégrité temps réel (Innovation Enterprise)
 * @param event Événement d'intégrité temps réel
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_handle_realtime_integrity_failure(const security_event_enterprise_t* event);

/**
 * @brief Gestion incident attestation continue (Innovation Enterprise)
 * @param event Événement d'attestation continue
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_handle_continuous_attestation_failure(const security_event_enterprise_t* event);

/**
 * @brief Gestion anomalie comportementale ML (Innovation Enterprise)
 * @param event Événement d'anomalie comportementale
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_handle_behavioral_anomaly(const security_event_enterprise_t* event);

/**
 * @brief Gestion dérive modèle ML (Innovation Enterprise)  
 * @param event Événement de dérive ML
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_handle_ml_model_drift(const security_event_enterprise_t* event);

/**
 * @brief Gestion dégradation performance (Enterprise)
 * @param event Événement de dégradation performance
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_handle_performance_degradation(const security_event_enterprise_t* event);

/**
 * @brief Gestion détection de manipulation (Enterprise)
 * @param event Événement de détection manipulation
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_handle_tamper_detection(const security_event_enterprise_t* event);

/**
 * @brief Création d'un incident Enterprise
 * @param event Événement déclencheur
 * @param incident_id ID de l'incident créé
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_create_enterprise(const security_event_enterprise_t* event, uint32_t* incident_id);

/**
 * @brief Mise à jour du statut d'un incident
 * @param incident_id ID de l'incident
 * @param new_status Nouveau statut
 * @param update_notes Notes de mise à jour
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_update_status(uint32_t incident_id, incident_status_enterprise_t new_status, const char* update_notes);

/**
 * @brief Escalade automatique d'un incident
 * @param incident_id ID de l'incident
 * @param escalation_reason Raison de l'escalade
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_escalate(uint32_t incident_id, const char* escalation_reason);

/**
 * @brief Capture forensique pour un incident
 * @param incident_id ID de l'incident
 * @param forensic_package_id ID du package forensique créé
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_capture_forensics(uint32_t incident_id, uint32_t* forensic_package_id);

/**
 * @brief Configuration du gestionnaire Enterprise
 * @param config Configuration Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_configure_enterprise(const incident_config_enterprise_t* config);

/**
 * @brief Obtention des statistiques Enterprise
 * @param stats Statistiques Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_get_statistics_enterprise(incident_stats_enterprise_t* stats);

/**
 * @brief Génération rapport compliance
 * @param report_buffer Buffer pour le rapport
 * @param buffer_size Taille du buffer
 * @return ESP_OK en cas de succès
 */
esp_err_t incident_generate_compliance_report(char* report_buffer, size_t buffer_size);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Initialisation (compatibilité)
 */
esp_err_t incident_manager_init(void);

/**
 * @brief Dé-initialisation (compatibilité)
 */
esp_err_t incident_manager_deinit(void);

/**
 * @brief Gestion échec intégrité (compatibilité)
 */
esp_err_t incident_handle_integrity_failure(const security_event_t* event);

/**
 * @brief Gestion anomalie (compatibilité)
 */
esp_err_t incident_handle_anomaly(const security_event_t* event);

/**
 * @brief Gestion échec attestation (compatibilité)
 */
esp_err_t incident_handle_attestation_failure(const security_event_t* event);

/**
 * @brief Gestion accès non autorisé (compatibilité)
 */
esp_err_t incident_handle_unauthorized_access(const security_event_t* event);

/**
 * @brief Obtention statistiques (compatibilité)
 */
esp_err_t incident_get_statistics(incident_stats_t* stats);

#ifdef __cplusplus
}
#endif

#endif /* INCIDENT_MANAGER_H */