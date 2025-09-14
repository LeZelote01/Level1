/**
 * @file app_config.h
 * @brief Configuration globale du framework SecureIoT-VIF Enterprise Edition
 * 
 * Version complète avec toutes les fonctionnalités avancées pour déploiements
 * production critiques et industriels.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// ================================
// Configuration générale Enterprise
// ================================

#define SECURE_IOT_VIF_VERSION "2.0.0-ENTERPRISE"
#define SECURE_IOT_VIF_NAME "SecureIoT-VIF-Enterprise"
#define SECURE_IOT_VIF_EDITION "Enterprise Edition"
#define SECURE_IOT_VIF_ENTERPRISE_BUILD 1

// ================================
// Configuration des tâches FreeRTOS Enterprise
// ================================

// Tâche de monitoring de sécurité (priorité maximale)
#define SECURITY_MONITOR_STACK_SIZE      (10240)   // Augmenté vs Community
#define SECURITY_MONITOR_PRIORITY        (12)      // Priorité maximale
#define SECURITY_MONITOR_INTERVAL_MS     (3000)    // 3 secondes (plus fréquent)

// Tâche de gestion des capteurs (optimisée)
#define SENSOR_TASK_STACK_SIZE           (6144)    // Augmenté
#define SENSOR_TASK_PRIORITY             (10)      // Priorité élevée
#define SENSOR_READ_INTERVAL_MS          (1000)    // 1 seconde (plus fréquent)

// Tâche d'attestation continue (Enterprise uniquement)
#define ATTESTATION_TASK_STACK_SIZE      (8192)    // Stack importante
#define ATTESTATION_TASK_PRIORITY        (11)      // Très haute priorité
#define ATTESTATION_INTERVAL_MS          (30000)   // 30 secondes

// Tâche ML anomaly detection (Enterprise uniquement)
#define ML_ANOMALY_TASK_STACK_SIZE       (8192)    // Pour calculs ML
#define ML_ANOMALY_TASK_PRIORITY         (9)       // Priorité élevée
#define ML_ANOMALY_INTERVAL_MS           (5000)    // 5 secondes

// ================================
// Configuration des timers Enterprise
// ================================

#define INTEGRITY_CHECK_INTERVAL_US      (60000000) // 60 secondes (temps réel)
#define HEARTBEAT_INTERVAL_US            (5000000)  // 5 secondes (plus fréquent)
#define ATTESTATION_RENEWAL_INTERVAL_US  (30000000) // 30 secondes
#define ML_LEARNING_UPDATE_INTERVAL_US   (300000000) // 5 minutes

// ================================
// Configuration des queues Enterprise
// ================================

#define SECURITY_EVENT_QUEUE_SIZE        (50)      // Augmenté vs Community
#define SENSOR_DATA_QUEUE_SIZE           (20)      // Augmenté
#define ATTESTATION_QUEUE_SIZE           (10)      // Nouveau Enterprise
#define ML_ANOMALY_QUEUE_SIZE            (15)      // Nouveau Enterprise

// ================================
// Configuration GPIO et hardware Enterprise
// ================================

// Configuration DHT22 - Grade industriel
#define DHT22_GPIO_PIN                  (4)
#define DHT22_POWER_GPIO                (5)        // Contrôle alimentation
#define DHT22_INDUSTRIAL_GRADE          (true)     // Enterprise uniquement

// LEDs de statut Enterprise
#define STATUS_LED_GPIO                 (2)        // LED principale
#define SECURITY_LED_GPIO               (16)       // LED sécurité Enterprise
#define ATTESTATION_LED_GPIO            (17)       // LED attestation Enterprise

// Boutons et contrôles Enterprise
#define SECURE_RESET_GPIO               (0)        // Boot button
#define EMERGENCY_SHUTDOWN_GPIO         (25)       // Arrêt d'urgence Enterprise
#define TAMPER_DETECT_GPIO              (26)       // Détection manipulation

// ================================
// Configuration ESP32 Crypto Enterprise COMPLET
// ================================

// Configuration eFuse complète (8 blocs)
#define ESP32_EFUSE_DEVICE_KEY_BLOCK     (0)       // Clé privée principale
#define ESP32_EFUSE_ATTESTATION_BLOCK    (1)       // Clé d'attestation
#define ESP32_EFUSE_ENCRYPTION_BLOCK     (2)       // Clé de chiffrement
#define ESP32_EFUSE_HMAC_BLOCK           (3)       // Clé HMAC
#define ESP32_EFUSE_BACKUP_KEY_BLOCK     (4)       // Clé de sauvegarde Enterprise
#define ESP32_EFUSE_SESSION_KEY_BLOCK    (5)       // Clé de session Enterprise
#define ESP32_EFUSE_ML_MODEL_BLOCK       (6)       // Clé modèle ML Enterprise
#define ESP32_EFUSE_RESERVED_BLOCK       (7)       // Réservé futur

// Configuration Secure Boot v2 Enterprise
#define ESP32_SECURE_BOOT_V2_ENABLED     (true)
#define ESP32_SECURE_BOOT_SIGNATURE_VERIFY (true)
#define ESP32_FLASH_ENCRYPTION_ENABLED   (true)
#define ESP32_EFUSE_PROTECTION_ENABLED   (true)
#define ESP32_TAMPER_DETECTION_ENABLED   (true)    // Enterprise uniquement

// Configuration TRNG Enterprise optimisé
#define ESP32_TRNG_ENTROPY_THRESHOLD     (1024)    // Seuil plus élevé
#define ESP32_RANDOM_GENERATION_TIMEOUT  (500)     // Timeout réduit
#define ESP32_TRNG_CONTINUOUS_TEST       (true)    // Tests continus Enterprise

// Configuration HSM Enterprise maximale
#define ESP32_HSM_MAX_PERFORMANCE        (true)    // Performance maximale
#define ESP32_CRYPTO_ACCELERATION_FULL   (true)    // Toutes accélérations
#define ESP32_CRYPTO_PARALLEL_OPERATIONS (true)    // Opérations parallèles

// ================================
// Configuration de sécurité Enterprise
// ================================

// Niveaux de sécurité Enterprise (5 niveaux)
#define SECURITY_LEVEL_LOW              (1)
#define SECURITY_LEVEL_MEDIUM           (2)
#define SECURITY_LEVEL_HIGH             (3)
#define SECURITY_LEVEL_CRITICAL         (4)
#define SECURITY_LEVEL_MAXIMUM          (5)        // Nouveau Enterprise

#define CURRENT_SECURITY_LEVEL          SECURITY_LEVEL_MAXIMUM

// Tailles des clés et algorithmes crypto Enterprise
#define ECDSA_KEY_SIZE_BITS             (256)      // ECDSA P-256
#define AES_KEY_SIZE_BITS               (256)      // AES-256
#define RSA_KEY_SIZE_BITS               (2048)     // RSA-2048
#define HMAC_KEY_SIZE_BYTES             (32)       // HMAC-SHA256
#define ENTERPRISE_KEY_ROTATION_SIZE    (384)      // Rotation Enterprise

// Tailles de hash et signatures Enterprise
#define SHA256_DIGEST_SIZE              (32)
#define SHA512_DIGEST_SIZE              (64)       // SHA-512 Enterprise
#define ECDSA_SIGNATURE_SIZE            (64)
#define RSA_SIGNATURE_SIZE              (256)
#define ENTERPRISE_COMPOSITE_SIG_SIZE   (320)      // Signature composite

// ================================
// Configuration de l'intégrité Enterprise
// ================================

#define FIRMWARE_SIGNATURE_SIZE         ECDSA_SIGNATURE_SIZE
#define FIRMWARE_HASH_SIZE              SHA256_DIGEST_SIZE
#define MAX_FIRMWARE_CHUNKS             (512)      // Augmenté vs Community
#define FIRMWARE_CHUNK_SIZE             (4096)     // Taille optimale

// Intervalles de vérification temps réel Enterprise
#define INTEGRITY_CHECK_BOOT_DELAY_MS   (2000)     // Démarrage rapide
#define INTEGRITY_CHECK_MAX_FAILURES    (2)        // Tolérance réduite
#define INTEGRITY_REALTIME_ENABLED      (true)     // Enterprise uniquement
#define INTEGRITY_SEGMENTED_CHECK       (true)     // Vérification segmentée

// ================================
// Configuration de l'attestation Enterprise
// ================================

#define ATTESTATION_CHALLENGE_SIZE      (64)       // Augmenté vs Community
#define ATTESTATION_RESPONSE_SIZE       (256)      // Augmenté
#define ATTESTATION_MAX_RETRIES         (2)        // Moins tolérant
#define ATTESTATION_TIMEOUT_MS          (3000)     // Timeout réduit
#define ATTESTATION_CONTINUOUS_ENABLED  (true)     // Enterprise uniquement
#define ATTESTATION_AUTONOMOUS_RENEWAL  (true)     // Renouvellement autonome

// Types d'attestation Enterprise
#define ATTESTATION_TYPE_STARTUP        (1)
#define ATTESTATION_TYPE_PERIODIC       (2)
#define ATTESTATION_TYPE_ON_DEMAND      (3)
#define ATTESTATION_TYPE_CONTINUOUS     (4)        // Enterprise uniquement
#define ATTESTATION_TYPE_EMERGENCY      (5)        // Attestation d'urgence

// ================================
// Configuration des capteurs Enterprise
// ================================

// Limites DHT22 grade industriel
#define DHT22_TEMP_MIN                  (-40.0f)
#define DHT22_TEMP_MAX                  (85.0f)    // Grade industriel
#define DHT22_HUMIDITY_MIN              (0.0f)
#define DHT22_HUMIDITY_MAX              (100.0f)

// Seuils d'anomalie Enterprise (plus stricts)
#define TEMP_ANOMALY_THRESHOLD          (3.0f)     // Plus strict
#define HUMIDITY_ANOMALY_THRESHOLD      (10.0f)    // Plus strict
#define SENSOR_READ_MAX_FAILURES        (3)        // Moins tolérant
#define SENSOR_INDUSTRIAL_VALIDATION    (true)     // Validation industrielle

// ================================
// Configuration réseau Enterprise
// ================================

#define WIFI_SSID_MAX_LEN               (32)
#define WIFI_PASSWORD_MAX_LEN           (64)
#define WIFI_CONNECTION_TIMEOUT_MS      (20000)    // Plus rapide
#define WIFI_MAX_RETRY                  (7)        // Plus de tentatives
#define WIFI_ENTERPRISE_SECURITY        (true)     // Sécurité renforcée

// Configuration MQTT Enterprise
#define MQTT_BROKER_MAX_LEN             (256)
#define MQTT_TOPIC_MAX_LEN              (128)
#define MQTT_MESSAGE_MAX_LEN            (2048)     // Messages plus longs
#define MQTT_CLIENT_ID_MAX_LEN          (64)
#define MQTT_TLS_ENABLED                (true)     // TLS obligatoire
#define MQTT_CERTIFICATE_VALIDATION     (true)     // Validation certificats

// ================================
// Configuration de logging Enterprise
// ================================

#define MAX_LOG_MESSAGE_SIZE            (512)      // Messages plus longs
#define SECURITY_LOG_BUFFER_SIZE        (8192)     // Buffer plus important
#define LOG_ROTATION_SIZE_KB            (128)      // Rotation plus fréquente
#define LOG_ENTERPRISE_ENCRYPTION       (true)     // Logs chiffrés
#define LOG_REMOTE_BACKUP               (true)     // Sauvegarde distante

// ================================
// Configuration ML Anomaly Detection Enterprise
// ================================

#define ANOMALY_HISTORY_SIZE            (200)      // Historique étendu
#define ANOMALY_DETECTION_WINDOW        (20)       // Fenêtre plus large
#define ANOMALY_SCORE_THRESHOLD         (0.7f)     // Plus sensible
#define ANOMALY_LEARNING_PERIOD_MS      (180000)   // 3 minutes
#define ML_MODEL_UPDATE_INTERVAL        (3600000)  // 1 heure
#define ML_ADAPTIVE_LEARNING            (true)     // Apprentissage adaptatif
#define ML_BEHAVIORAL_PROFILE           (true)     // Profiling comportemental
#define ML_REALTIME_INFERENCE           (true)     // Inférence temps réel

// Paramètres ML avancés
#define ML_FEATURE_VECTOR_SIZE          (32)       // Vecteur caractéristiques
#define ML_LEARNING_RATE                (0.01f)    // Taux d'apprentissage
#define ML_REGULARIZATION_FACTOR        (0.001f)   // Facteur régularisation
#define ML_CONFIDENCE_THRESHOLD         (0.8f)     // Seuil confiance

// ================================
// Types d'événements de sécurité Enterprise
// ================================

typedef enum {
    SECURITY_EVENT_NONE = 0,
    SECURITY_EVENT_INTEGRITY_FAILURE,
    SECURITY_EVENT_ATTESTATION_FAILURE,
    SECURITY_EVENT_ANOMALY_DETECTED,
    SECURITY_EVENT_UNAUTHORIZED_ACCESS,
    SECURITY_EVENT_SENSOR_MALFUNCTION,
    SECURITY_EVENT_COMMUNICATION_FAILURE,
    SECURITY_EVENT_TAMPERING_DETECTED,
    SECURITY_EVENT_POWER_ANOMALY,
    SECURITY_EVENT_MEMORY_CORRUPTION,
    SECURITY_EVENT_CRYPTO_ERROR,
    SECURITY_EVENT_EFUSE_CORRUPTION,
    SECURITY_EVENT_SECURE_BOOT_FAILURE,
    // Événements Enterprise uniquement
    SECURITY_EVENT_ML_MODEL_DRIFT,           // Dérive modèle ML
    SECURITY_EVENT_REALTIME_INTEGRITY_FAIL,  // Échec intégrité temps réel
    SECURITY_EVENT_CONTINUOUS_ATTESTATION_FAIL, // Échec attestation continue
    SECURITY_EVENT_BEHAVIORAL_ANOMALY,       // Anomalie comportementale
    SECURITY_EVENT_PERFORMANCE_DEGRADATION,  // Dégradation performance
    SECURITY_EVENT_EMERGENCY_SHUTDOWN,       // Arrêt d'urgence
    SECURITY_EVENT_TAMPER_DETECTION,         // Détection manipulation
    SECURITY_EVENT_KEY_ROTATION_REQUIRED,    // Rotation clés requise
    SECURITY_EVENT_COMPLIANCE_VIOLATION,     // Violation conformité
    SECURITY_EVENT_MAX
} security_event_type_t;

// ================================
// Niveaux de sévérité Enterprise
// ================================

typedef enum {
    SECURITY_SEVERITY_INFO = 1,
    SECURITY_SEVERITY_LOW,
    SECURITY_SEVERITY_MEDIUM,
    SECURITY_SEVERITY_HIGH,
    SECURITY_SEVERITY_CRITICAL,
    SECURITY_SEVERITY_EMERGENCY            // Nouveau Enterprise
} security_severity_t;

// ================================
// États système Enterprise
// ================================

typedef enum {
    SYSTEM_STATE_BOOTING = 0,
    SYSTEM_STATE_INITIALIZING,
    SYSTEM_STATE_CRYPTO_SETUP,
    SYSTEM_STATE_ATTESTATION_VALIDATION,    // Nouveau Enterprise
    SYSTEM_STATE_ML_MODEL_LOADING,          // Nouveau Enterprise
    SYSTEM_STATE_NORMAL_OPERATION,
    SYSTEM_STATE_SECURITY_ALERT,
    SYSTEM_STATE_PERFORMANCE_MONITORING,    // Nouveau Enterprise
    SYSTEM_STATE_EMERGENCY,
    SYSTEM_STATE_MAINTENANCE_MODE,          // Nouveau Enterprise
    SYSTEM_STATE_SHUTDOWN
} system_state_t;

// ================================
// Configuration gestion d'énergie Enterprise
// ================================

#define POWER_SAVE_MODE_ENABLED         (1)
#define SLEEP_MODE_DURATION_MS          (30000)    // 30 secondes
#define WAKEUP_STUB_SIZE_BYTES          (16384)    // Plus important

// Configuration économie d'énergie ESP32 Enterprise
#define ESP32_LIGHT_SLEEP_ENABLED       (true)
#define ESP32_CRYPTO_CLOCK_GATING       (true)
#define ESP32_POWER_MANAGEMENT_ENABLED  (true)
#define ESP32_ADAPTIVE_FREQUENCY        (true)    // Fréquence adaptative
#define ESP32_POWER_MONITORING          (true)    // Monitoring consommation

// ================================
// Macros utilitaires Enterprise
// ================================

#define ARRAY_SIZE(x)                   (sizeof(x) / sizeof((x)[0]))
#define MIN(a, b)                       ((a) < (b) ? (a) : (b))
#define MAX(a, b)                       ((a) > (b) ? (a) : (b))
#define ALIGN(x, a)                     (((x) + (a) - 1) & ~((a) - 1))
#define CLAMP(x, min, max)              (MIN(MAX(x, min), max))

// Macros de vérification Enterprise
#define CHECK_ERROR_ENTERPRISE(x) do { \
    esp_err_t __err_rc = (x); \
    if (__err_rc != ESP_OK) { \
        ESP_LOGE(TAG, "Enterprise Error: %s (0x%x) at %s:%d", esp_err_to_name(__err_rc), __err_rc, __FILE__, __LINE__); \
        return __err_rc; \
    } \
} while(0)

#define CHECK_NULL_ENTERPRISE(x) do { \
    if ((x) == NULL) { \
        ESP_LOGE(TAG, "NULL pointer Enterprise at %s:%d", __FILE__, __LINE__); \
        return ESP_ERR_INVALID_ARG; \
    } \
} while(0)

#define CHECK_CRYPTO_ERROR_ENTERPRISE(x) do { \
    esp32_crypto_result_t __crypto_rc = (x); \
    if (__crypto_rc != ESP32_CRYPTO_SUCCESS) { \
        ESP_LOGE(TAG, "Enterprise Crypto Error: %s at %s:%d", esp32_crypto_error_to_string(__crypto_rc), __FILE__, __LINE__); \
        return ESP_FAIL; \
    } \
} while(0)

#define CHECK_ML_ERROR_ENTERPRISE(x) do { \
    ml_result_t __ml_rc = (x); \
    if (__ml_rc != ML_SUCCESS) { \
        ESP_LOGE(TAG, "Enterprise ML Error: %d at %s:%d", __ml_rc, __FILE__, __LINE__); \
        return ESP_FAIL; \
    } \
} while(0)

// ================================
// Structure de configuration globale Enterprise
// ================================

typedef struct {
    // Configuration sécurité Enterprise
    uint8_t security_level;
    bool secure_boot_enabled;
    bool flash_encryption_enabled;
    bool efuse_protection_enabled;
    bool tamper_detection_enabled;          // Nouveau Enterprise
    
    // Configuration crypto ESP32 Enterprise
    bool hardware_crypto_enabled;
    bool trng_enabled;
    bool hsm_max_performance;               // Nouveau Enterprise
    uint8_t efuse_key_blocks_used;
    bool crypto_parallel_operations;        // Nouveau Enterprise
    
    // Configuration attestation Enterprise
    uint32_t attestation_interval;
    bool remote_attestation_enabled;
    bool continuous_attestation_enabled;    // Nouveau Enterprise
    bool autonomous_renewal_enabled;        // Nouveau Enterprise
    
    // Configuration ML Enterprise
    bool ml_anomaly_detection_enabled;      // Nouveau Enterprise
    bool behavioral_profiling_enabled;      // Nouveau Enterprise
    bool realtime_inference_enabled;        // Nouveau Enterprise
    float ml_learning_rate;                 // Nouveau Enterprise
    float ml_confidence_threshold;          // Nouveau Enterprise
    
    // Configuration réseau Enterprise
    char wifi_ssid[WIFI_SSID_MAX_LEN];
    char wifi_password[WIFI_PASSWORD_MAX_LEN];
    bool wifi_enterprise_security;          // Nouveau Enterprise
    bool mqtt_tls_enabled;                  // Nouveau Enterprise
    
    // Configuration capteurs Enterprise
    uint32_t sensor_read_interval;
    bool anomaly_detection_enabled;
    bool industrial_grade_sensors;          // Nouveau Enterprise
    bool sensor_validation_enabled;         // Nouveau Enterprise
    
    // Configuration monitoring Enterprise
    bool advanced_monitoring_enabled;       // Nouveau Enterprise
    bool performance_monitoring_enabled;    // Nouveau Enterprise
    bool log_encryption_enabled;            // Nouveau Enterprise
    bool remote_log_backup_enabled;         // Nouveau Enterprise
    
    // État système Enterprise
    system_state_t current_state;
    uint32_t boot_count;
    uint64_t uptime_seconds;
    
    // Métriques Enterprise
    uint32_t integrity_checks_performed;
    uint32_t attestations_performed;        // Nouveau Enterprise
    uint32_t ml_inferences_performed;       // Nouveau Enterprise
    uint32_t anomalies_detected;
    uint32_t security_events_processed;     // Nouveau Enterprise
    float system_performance_score;         // Nouveau Enterprise
    
    // Compliance et audit Enterprise
    bool compliance_mode_enabled;           // Nouveau Enterprise
    uint32_t last_security_audit;           // Nouveau Enterprise
    bool continuous_compliance_check;       // Nouveau Enterprise
    
} global_config_enterprise_t;

// ================================
// Variables globales Enterprise
// ================================

extern global_config_enterprise_t g_config_enterprise;

// ================================
// Fonctionnalités Enterprise complètes
// ================================

// Toutes les fonctionnalités sont activées en Enterprise
#define FEATURE_REAL_TIME_INTEGRITY     (true)    // Vérification temps réel
#define FEATURE_CONTINUOUS_ATTESTATION  (true)    // Attestation continue
#define FEATURE_ML_ANOMALY_DETECTION    (true)    // ML comportemental
#define FEATURE_HARDWARE_HSM            (true)    // HSM complet
#define FEATURE_EFUSE_PROTECTION        (true)    // Protection eFuse
#define FEATURE_SECURE_BOOT_V2          (true)    // Secure Boot v2
#define FEATURE_FLASH_ENCRYPTION        (true)    // Chiffrement flash
#define FEATURE_REMOTE_ATTESTATION      (true)    // Attestation distante
#define FEATURE_ADVANCED_MONITORING     (true)    // Monitoring avancé
#define FEATURE_ENTERPRISE_TOOLS        (true)    // Outils Enterprise
#define FEATURE_BEHAVIORAL_PROFILING    (true)    // Profiling comportemental
#define FEATURE_COMPLIANCE_MONITORING   (true)    // Monitoring conformité
#define FEATURE_PERFORMANCE_ANALYTICS   (true)    // Analytics performance

// ================================
// Messages informatifs Enterprise
// ================================

#define ENTERPRISE_WELCOME_MESSAGE      "\n🏢 SecureIoT-VIF Enterprise Edition v2.0.0\n" \
                                       "   ✅ Toutes fonctionnalités avancées activées\n" \
                                       "   🔐 Crypto HSM ESP32 intégré complet\n" \
                                       "   ⚡ Vérification intégrité temps réel\n" \
                                       "   🛡️ Attestation continue autonome\n" \
                                       "   🤖 Détection ML comportementale\n" \
                                       "   📊 Monitoring et analytics avancés\n" \
                                       "   🏆 Grade industriel et production critique\n" \
                                       "🚀 Enterprise Edition - Performance maximale!\n"

#define ENTERPRISE_SUPPORT_MESSAGE      "\n📞 Support Enterprise 24/7 disponible:\n" \
                                       "   Email: enterprise-support@secureiot-vif.com\n" \
                                       "   Tel: +33 1 XX XX XX XX\n" \
                                       "   Portal: https://enterprise.secureiot-vif.com\n"

// ================================
// Compatibility layer (nouvelles fonctions)
// ================================

// Extensions Enterprise des fonctions de base
#define se_manager_init_enterprise()                    esp32_crypto_manager_init_enterprise(NULL)
#define se_manager_deinit_enterprise()                  esp32_crypto_manager_deinit_enterprise()
#define se_health_check_enterprise()                    esp32_crypto_health_check_enterprise()
#define se_perform_attestation_enterprise(ch, sz, att)  esp32_crypto_perform_attestation_enterprise(ch, sz, att)
#define se_verify_integrity_enterprise()                esp32_crypto_verify_integrity_enterprise()
#define se_ml_anomaly_detect(data)                      ml_anomaly_detector_enterprise(data)
#define se_behavioral_analysis(profile)                 ml_behavioral_analyzer_enterprise(profile)

#ifdef __cplusplus
}
#endif

#endif /* APP_CONFIG_H */