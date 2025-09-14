/**
 * @file anomaly_detector.h
 * @brief Détecteur d'anomalies ML comportemental Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec apprentissage adaptatif, analyse comportementale
 * avancée, modèles ML légers et détection temps réel.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
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

// ================================
// Constantes Enterprise
// ================================

#define ANOMALY_DETECTOR_VERSION_ENTERPRISE "2.0.0"
#define ANOMALY_HISTORY_SIZE_ENTERPRISE     (200)    // Doublé vs Community
#define ANOMALY_WINDOW_SIZE_ENTERPRISE      (20)     // Doublé vs Community
#define ML_FEATURE_VECTOR_SIZE              (32)     // Vecteur caractéristiques ML
#define ML_BEHAVIOR_PROFILES_MAX            (8)      // Profils comportementaux
#define ML_ADAPTATION_HISTORY_SIZE          (50)     // Historique adaptation

// Compatibilité version standard
#define ANOMALY_HISTORY_SIZE        (100)
#define ANOMALY_WINDOW_SIZE         (10)

// ================================
// Types Enterprise étendus
// ================================

/**
 * @brief Types d'anomalies Enterprise étendus
 */
typedef enum {
    ANOMALY_TYPE_NONE = 0,
    ANOMALY_TYPE_SENSOR_DATA,               // Anomalie données capteur
    ANOMALY_TYPE_SYSTEM_BEHAVIOR,           // Comportement système anormal
    ANOMALY_TYPE_SECURITY_PATTERN,          // Pattern sécurité suspect
    ANOMALY_TYPE_COMMUNICATION,             // Communication anormale
    ANOMALY_TYPE_PERFORMANCE,               // Performance dégradée
    // Types Enterprise spécifiques
    ANOMALY_TYPE_BEHAVIORAL_SHIFT,          // Changement comportemental
    ANOMALY_TYPE_ML_MODEL_DRIFT,            // Dérive modèle ML
    ANOMALY_TYPE_CRYPTO_PERFORMANCE,        // Performance crypto anormale
    ANOMALY_TYPE_TEMPORAL_PATTERN,          // Pattern temporel suspect
    ANOMALY_TYPE_MULTIVARIATE,              // Anomalie multivariée
    ANOMALY_TYPE_CONTEXTUAL,                // Anomalie contextuelle
    ANOMALY_TYPE_COLLECTIVE                 // Anomalie collective
} anomaly_type_t;

/**
 * @brief Méthodes de détection ML Enterprise
 */
typedef enum {
    ML_METHOD_ZSCORE = 0,                   // Z-score statistique
    ML_METHOD_ISOLATION_FOREST,             // Forêt d'isolation
    ML_METHOD_ONE_CLASS_SVM,                // SVM une classe
    ML_METHOD_AUTOENCODER,                  // Auto-encodeur léger
    ML_METHOD_ENSEMBLE,                     // Ensemble de méthodes
    ML_METHOD_ADAPTIVE                      // Adaptatif Enterprise
} ml_detection_method_t;

/**
 * @brief Résultat ML Enterprise détaillé
 */
typedef enum {
    ML_SUCCESS = 0,
    ML_ERROR_NOT_INITIALIZED = -1,
    ML_ERROR_INSUFFICIENT_DATA = -2,
    ML_ERROR_MODEL_CORRUPTION = -3,
    ML_ERROR_ADAPTATION_FAILED = -4,
    ML_ERROR_MEMORY_ALLOCATION = -5,
    ML_ERROR_INVALID_PARAMETERS = -6
} ml_result_t;

/**
 * @brief Profil comportemental Enterprise
 */
typedef struct {
    uint8_t profile_id;
    char name[32];
    float feature_means[ML_FEATURE_VECTOR_SIZE];
    float feature_stds[ML_FEATURE_VECTOR_SIZE];
    float threshold_multiplier;
    uint32_t samples_count;
    uint32_t last_update_time;
    bool is_active;
    float confidence_score;
} ml_behavior_profile_t;

/**
 * @brief Résultat de détection d'anomalie Enterprise
 */
typedef struct {
    // Champs de base
    bool is_anomaly;
    anomaly_type_t type;
    float anomaly_score;                    // Score 0.0-1.0
    uint32_t timestamp;
    char description[256];                  // Étendu vs Community
    uint8_t severity;                       // 1=Low, 2=Medium, 3=High, 4=Critical, 5=Emergency
    uint32_t detection_time_ms;
    
    // Extensions Enterprise ML
    ml_detection_method_t method_used;
    float confidence_score;                 // Confiance détection
    uint8_t behavior_profile_id;            // Profil comportemental associé
    float feature_vector[ML_FEATURE_VECTOR_SIZE]; // Vecteur caractéristiques
    bool model_adaptation_triggered;        // Adaptation modèle déclenchée
    float ensemble_scores[5];               // Scores des différentes méthodes
    
    // Métadonnées contextuelles
    uint32_t historical_context_samples;   // Nombre échantillons historiques
    float temporal_context_score;          // Score contexte temporel
    bool contextual_anomaly;               // Anomalie contextuelle
    float baseline_deviation;              // Déviation par rapport baseline
    
    // Diagnostics et debugging
    uint32_t ml_inference_time_us;         // Temps inférence ML
    uint32_t memory_usage_bytes;           // Utilisation mémoire
    uint8_t cpu_usage_percent;             // Utilisation CPU
} anomaly_result_t;

/**
 * @brief Contexte ML Enterprise étendu
 */
typedef struct {
    // Données historiques Enterprise
    float sensor_data[ANOMALY_HISTORY_SIZE_ENTERPRISE][ML_FEATURE_VECTOR_SIZE];
    uint32_t timestamps[ANOMALY_HISTORY_SIZE_ENTERPRISE];
    uint32_t write_index;
    uint32_t sample_count;
    
    // Mode d'apprentissage
    bool is_learning;
    uint64_t learning_start_time;
    uint32_t learning_samples_required;
    
    // Modèles ML
    ml_behavior_profile_t behavior_profiles[ML_BEHAVIOR_PROFILES_MAX];
    uint8_t active_profile_count;
    uint8_t current_profile_id;
    ml_detection_method_t active_method;
    
    // Adaptation et apprentissage continu
    bool adaptive_learning_enabled;
    float adaptation_rate;
    uint32_t last_adaptation_time;
    float model_drift_threshold;
    
    // Statistiques Enterprise
    uint32_t total_detections;
    uint32_t false_positives;
    uint32_t true_positives;
    float detection_accuracy;
    uint32_t model_updates_count;
    
    // Performance
    float avg_inference_time_us;
    uint32_t max_memory_usage;
    bool performance_monitoring_enabled;
} anomaly_context_enterprise_t;

/**
 * @brief Configuration ML Enterprise
 */
typedef struct {
    bool ml_enabled;
    bool adaptive_learning;
    bool behavioral_profiling;
    bool ensemble_detection;
    bool performance_optimization;
    ml_detection_method_t preferred_method;
    float sensitivity_level;                // 0.1-1.0
    uint32_t adaptation_interval_ms;
    uint32_t min_samples_for_detection;
    float false_positive_tolerance;
} anomaly_config_enterprise_t;

/**
 * @brief Statistiques ML Enterprise
 */
typedef struct {
    uint32_t total_samples_processed;
    uint32_t anomalies_detected;
    uint32_t false_positives;
    uint32_t model_adaptations;
    float detection_accuracy;
    float avg_detection_time_ms;
    uint32_t active_behavior_profiles;
    uint32_t memory_usage_bytes;
    uint32_t uptime_seconds;
} anomaly_stats_enterprise_t;

// Structures de compatibilité
typedef struct {
    bool is_learning;
    uint64_t learning_start_time;
    uint32_t sample_count;
    uint32_t write_index;
} anomaly_context_t;

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation du détecteur d'anomalies ML Enterprise
 * @param config Configuration ML Enterprise (NULL pour défaut)
 * @return ESP_OK en cas de succès
 */
esp_err_t anomaly_detector_init_enterprise(const anomaly_config_enterprise_t* config);

/**
 * @brief Dé-initialisation du détecteur Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t anomaly_detector_deinit_enterprise(void);

/**
 * @brief Détection d'anomalie ML comportementale temps réel
 * @param ml_data Données ML à analyser
 * @return Résultat ML
 */
ml_result_t ml_behavioral_analysis_realtime(ml_anomaly_data_t* ml_data);

/**
 * @brief Mise à jour du modèle ML comportemental
 * @return Résultat de la mise à jour
 */
ml_result_t ml_update_behavioral_model(void);

/**
 * @brief Apprentissage adaptatif ML
 * @return ESP_OK en cas de succès
 */
esp_err_t ml_adaptive_learning_update(void);

/**
 * @brief Initialisation ML comportemental Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t ml_behavioral_analyzer_init_enterprise(void);

/**
 * @brief Détection d'anomalie ML adaptative (Innovation Enterprise)
 * @param data Données capteur
 * @return Résultat de détection Enterprise
 */
anomaly_result_t anomaly_detect_ml_adaptive(const sensor_data_t* data);

/**
 * @brief Création d'un profil comportemental
 * @param profile_name Nom du profil
 * @param profile_id ID du profil créé
 * @return ESP_OK en cas de succès
 */
esp_err_t anomaly_create_behavior_profile(const char* profile_name, uint8_t* profile_id);

/**
 * @brief Sélection du profil comportemental actif
 * @param profile_id ID du profil à activer
 * @return ESP_OK en cas de succès
 */
esp_err_t anomaly_select_behavior_profile(uint8_t profile_id);

/**
 * @brief Configuration du détecteur Enterprise
 * @param config Configuration Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t anomaly_configure_enterprise(const anomaly_config_enterprise_t* config);

/**
 * @brief Obtention des statistiques ML Enterprise
 * @return Statistiques complètes
 */
anomaly_stats_enterprise_t anomaly_get_stats_enterprise(void);

/**
 * @brief Réinitialisation du modèle ML
 * @return ESP_OK en cas de succès
 */
esp_err_t anomaly_reset_ml_model(void);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Initialisation (compatibilité)
 */
esp_err_t anomaly_detector_init(void);

/**
 * @brief Dé-initialisation (compatibilité)
 */
esp_err_t anomaly_detector_deinit(void);

/**
 * @brief Détection anomalie capteur (compatibilité)
 */
anomaly_result_t anomaly_detect_sensor_data(const sensor_data_t* data);

/**
 * @brief Détection comportement système (compatibilité)
 */
anomaly_result_t anomaly_detect_system_behavior(void);

/**
 * @brief Mise à jour baseline (compatibilité)
 */
esp_err_t anomaly_update_baseline(const sensor_data_t* data);

/**
 * @brief Mode apprentissage (compatibilité)
 */
esp_err_t anomaly_set_learning_mode(bool enable);

/**
 * @brief État apprentissage (compatibilité)
 */
bool anomaly_is_learning_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* ANOMALY_DETECTOR_H */