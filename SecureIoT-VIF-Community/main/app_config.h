/**
 * @file app_config.h
 * @brief Configuration globale du framework SecureIoT-VIF Community Edition
 * 
 * Version simplifiée avec fonctionnalités de base pour éducation et recherche.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
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
// Configuration générale Community
// ================================

#define SECURE_IOT_VIF_VERSION "1.0.0-COMMUNITY"
#define SECURE_IOT_VIF_NAME "SecureIoT-VIF-Community"
#define SECURE_IOT_VIF_EDITION "Community Edition"

// ================================
// Configuration des tâches FreeRTOS
// ================================

// Tâche de monitoring de sécurité (priorité réduite)
#define SECURITY_MONITOR_STACK_SIZE      (6144)    // Réduit vs Enterprise
#define SECURITY_MONITOR_PRIORITY        (8)       // Réduit vs Enterprise 
#define SECURITY_MONITOR_INTERVAL_MS     (10000)   // 10 secondes vs 5s

// Tâche de gestion des capteurs
#define SENSOR_TASK_STACK_SIZE           (4096)
#define SENSOR_TASK_PRIORITY             (7)       // Réduit vs Enterprise
#define SENSOR_READ_INTERVAL_MS          (5000)    // 5 secondes vs 2s

// Pas de tâche d'attestation en Community Edition

// ================================
// Configuration des timers Community
// ================================

#define INTEGRITY_CHECK_INTERVAL_US_COMMUNITY    (300000000) // 5 minutes vs 60s Enterprise
#define HEARTBEAT_INTERVAL_US                    (30000000)  // 30 secondes vs 10s

// ================================
// Configuration des queues
// ================================

#define SECURITY_EVENT_QUEUE_SIZE        (10)      // Réduit vs Enterprise
#define SENSOR_DATA_QUEUE_SIZE           (5)       // Réduit vs Enterprise

// ================================
// Configuration GPIO et hardware
// ================================

// Configuration DHT22 (identique)
#define DHT22_GPIO_PIN                  (4)
#define DHT22_POWER_GPIO                (5)

// LED de statut
#define STATUS_LED_GPIO                 (2)

// Bouton de reset
#define SECURE_RESET_GPIO               (0)

// ================================
// Configuration Crypto Community (basique)
// ================================

// Pas de configuration HSM/eFuse avancée en Community
#define COMMUNITY_CRYPTO_BASIC_ONLY      (true)
#define COMMUNITY_SOFTWARE_CRYPTO        (true)
#define COMMUNITY_NO_HSM                 (true)

// Tailles des clés basiques
#define BASIC_ECDSA_KEY_SIZE_BITS       (256)
#define BASIC_AES_KEY_SIZE_BITS         (128)     // AES-128 vs AES-256
#define BASIC_HMAC_KEY_SIZE_BYTES       (16)      // Réduit vs Enterprise

// Tailles de hash et signatures
#define SHA256_DIGEST_SIZE              (32)
#define BASIC_ECDSA_SIGNATURE_SIZE      (64)

// ================================
// Configuration de l'intégrité Community
// ================================

#define FIRMWARE_SIGNATURE_SIZE         BASIC_ECDSA_SIGNATURE_SIZE
#define FIRMWARE_HASH_SIZE              SHA256_DIGEST_SIZE
#define MAX_FIRMWARE_CHUNKS             (64)       // Réduit vs Enterprise
#define FIRMWARE_CHUNK_SIZE             (8192)     // Plus gros chunks

// Intervalles de vérification (moins fréquents)
#define INTEGRITY_CHECK_BOOT_DELAY_MS   (5000)     // Plus long délai
#define INTEGRITY_CHECK_MAX_FAILURES    (5)        // Plus tolérant

// Pas d'attestation continue en Community Edition
#define COMMUNITY_NO_ATTESTATION        (true)

// ================================
// Configuration des capteurs (identique)
// ================================

// Limites DHT22
#define DHT22_TEMP_MIN                  (-40.0f)
#define DHT22_TEMP_MAX                  (80.0f)
#define DHT22_HUMIDITY_MIN              (0.0f)
#define DHT22_HUMIDITY_MAX              (100.0f)

// Seuils d'anomalie (plus tolérants)
#define TEMP_ANOMALY_THRESHOLD          (10.0f)    // Plus large vs Enterprise
#define HUMIDITY_ANOMALY_THRESHOLD      (25.0f)    // Plus large vs Enterprise
#define SENSOR_READ_MAX_FAILURES        (10)       // Plus tolérant

// ================================
// Configuration réseau Community
// ================================

#define WIFI_SSID_MAX_LEN               (32)
#define WIFI_PASSWORD_MAX_LEN           (64)
#define WIFI_CONNECTION_TIMEOUT_MS      (30000)
#define WIFI_MAX_RETRY                  (3)        // Moins de tentatives

// Pas de MQTT en Community Edition par défaut
#define COMMUNITY_NO_MQTT               (true)

// ================================
// Configuration de logging
// ================================

#define MAX_LOG_MESSAGE_SIZE            (256)
#define SECURITY_LOG_BUFFER_SIZE        (2048)     // Réduit vs Enterprise
#define LOG_ROTATION_SIZE_KB            (32)       // Réduit vs Enterprise

// ================================
// Configuration détection d'anomalies Community
// ================================

#define ANOMALY_HISTORY_SIZE            (50)       // Réduit vs Enterprise
#define ANOMALY_DETECTION_WINDOW        (5)        // Réduit vs Enterprise
#define ANOMALY_SCORE_THRESHOLD         (0.9f)     // Plus strict (moins sensible)
#define ANOMALY_LEARNING_PERIOD_MS      (600000)   // 10 minutes vs 5

// Pas de ML adaptatif en Community
#define COMMUNITY_THRESHOLD_ONLY        (true)
#define COMMUNITY_NO_ML                 (true)

// ================================
// Types d'événements de sécurité Community
// ================================

typedef enum {
    SECURITY_EVENT_NONE = 0,
    SECURITY_EVENT_INTEGRITY_FAILURE,
    SECURITY_EVENT_ANOMALY_DETECTED,
    SECURITY_EVENT_SENSOR_MALFUNCTION,
    SECURITY_EVENT_COMMUNICATION_FAILURE,
    SECURITY_EVENT_POWER_ANOMALY,
    // Pas d'événements avancés en Community
    SECURITY_EVENT_MAX
} security_event_type_t;

// ================================
// Niveaux de sévérité (identiques)
// ================================

typedef enum {
    SECURITY_SEVERITY_INFO = 1,
    SECURITY_SEVERITY_LOW,
    SECURITY_SEVERITY_MEDIUM,
    SECURITY_SEVERITY_HIGH,
    SECURITY_SEVERITY_CRITICAL
} security_severity_t;

// ================================
// États système Community
// ================================

typedef enum {
    SYSTEM_STATE_BOOTING = 0,
    SYSTEM_STATE_INITIALIZING,
    SYSTEM_STATE_NORMAL_OPERATION,
    SYSTEM_STATE_SECURITY_ALERT,
    SYSTEM_STATE_EMERGENCY,
    SYSTEM_STATE_SHUTDOWN
} system_state_t;

// ================================
// Configuration gestion d'énergie Community
// ================================

#define POWER_SAVE_MODE_ENABLED         (0)        // Désactivé par défaut
#define SLEEP_MODE_DURATION_MS          (300000)   // 5 minutes vs 1 minute

// Pas de gestion énergétique avancée
#define COMMUNITY_NO_POWER_MGMT         (true)

// ================================
// Macros utilitaires (identiques)
// ================================

#define ARRAY_SIZE(x)                   (sizeof(x) / sizeof((x)[0]))
#define MIN(a, b)                       ((a) < (b) ? (a) : (b))
#define MAX(a, b)                       ((a) > (b) ? (a) : (b))
#define ALIGN(x, a)                     (((x) + (a) - 1) & ~((a) - 1))

// Macros de vérification simplifiées
#define CHECK_ERROR(x) do { \
    esp_err_t __err_rc = (x); \
    if (__err_rc != ESP_OK) { \
        ESP_LOGE(TAG, "Erreur Community: %s (0x%x) à %s:%d", esp_err_to_name(__err_rc), __err_rc, __FILE__, __LINE__); \
        return __err_rc; \
    } \
} while(0)

#define CHECK_NULL(x) do { \
    if ((x) == NULL) { \
        ESP_LOGE(TAG, "Pointeur NULL Community à %s:%d", __FILE__, __LINE__); \
        return ESP_ERR_INVALID_ARG; \
    } \
} while(0)

// ================================
// Structure de configuration globale Community
// ================================

typedef struct {
    // Configuration sécurité de base
    uint8_t security_level;
    bool basic_crypto_enabled;              // Crypto de base seulement
    bool threshold_detection_enabled;       // Détection par seuils
    
    // Configuration réseau de base
    char wifi_ssid[WIFI_SSID_MAX_LEN];
    char wifi_password[WIFI_PASSWORD_MAX_LEN];
    
    // Configuration capteurs
    uint32_t sensor_read_interval;
    bool anomaly_detection_enabled;
    
    // État système
    system_state_t current_state;
    uint32_t boot_count;
    uint64_t uptime_seconds;
    
    // Métriques Community
    uint32_t integrity_checks_performed;
    uint32_t anomalies_detected;
    uint32_t sensor_readings_total;
    
} global_config_community_t;

// ================================
// Variables globales Community
// ================================

extern global_config_community_t g_config_community;

// ================================
// Niveaux de sécurité Community (simplifiés)
// ================================

#define SECURITY_LEVEL_LOW              (1)
#define SECURITY_LEVEL_MEDIUM           (2)
#define SECURITY_LEVEL_HIGH             (3)        // Pas de niveau CRITICAL en Community

#define CURRENT_SECURITY_LEVEL_COMMUNITY    SECURITY_LEVEL_MEDIUM

// ================================
// Fonctionnalités désactivées en Community
// ================================

// Ces fonctionnalités ne sont pas disponibles en Community Edition
#define FEATURE_REAL_TIME_INTEGRITY     (false)    // Seulement au boot
#define FEATURE_CONTINUOUS_ATTESTATION  (false)    // Pas d'attestation
#define FEATURE_ML_ANOMALY_DETECTION    (false)    // Seuils fixes seulement
#define FEATURE_HARDWARE_HSM            (false)    // Crypto software seulement
#define FEATURE_EFUSE_PROTECTION        (false)    // Pas de protection eFuse
#define FEATURE_SECURE_BOOT_V2          (false)    // Secure Boot basique seulement
#define FEATURE_FLASH_ENCRYPTION        (false)    // Pas de chiffrement flash
#define FEATURE_REMOTE_ATTESTATION      (false)    // Pas d'attestation distante
#define FEATURE_ADVANCED_MONITORING     (false)    // Monitoring basique
#define FEATURE_ENTERPRISE_TOOLS        (false)    // Pas d'outils avancés

// ================================
// Messages informatifs Community
// ================================

#define COMMUNITY_UPGRADE_MESSAGE       "\n💡 Pour accéder aux fonctionnalités avancées :\n" \
                                       "   • Vérification d'intégrité temps réel\n" \
                                       "   • Attestation continue autonome\n" \
                                       "   • Détection ML comportementale\n" \
                                       "   • Crypto HSM ESP32 intégré\n" \
                                       "   • Support professionnel\n" \
                                       "🚀 Contactez-nous pour SecureIoT-VIF Enterprise Edition !\n"

#ifdef __cplusplus
}
#endif

#endif /* APP_CONFIG_H */