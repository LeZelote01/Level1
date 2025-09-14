/**
 * @file app_config.h
 * @brief Configuration globale du framework SecureIoT-VIF v2.0 - ESP32 Crypto Intégré
 * 
 * Ce fichier contient toutes les constantes, macros et configurations
 * utilisées par le framework de sécurité IoT utilisant le crypto ESP32 intégré.
 * 
 * @author Framework SecureIoT-VIF
 * @version 2.0.0 - ESP32 Crypto Intégré
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
// Configuration générale
// ================================

#define SECURE_IOT_VIF_VERSION "2.0.0-ESP32-CRYPTO"
#define SECURE_IOT_VIF_NAME "SecureIoT-VIF-ESP32"

// ================================
// Configuration des tâches FreeRTOS
// ================================

// Tâche de monitoring de sécurité
#define SECURITY_MONITOR_STACK_SIZE      (8192)
#define SECURITY_MONITOR_PRIORITY        (10)
#define SECURITY_MONITOR_INTERVAL_MS     (5000)    // 5 secondes

// Tâche de gestion des capteurs
#define SENSOR_TASK_STACK_SIZE           (4096)
#define SENSOR_TASK_PRIORITY             (8)
#define SENSOR_READ_INTERVAL_MS          (2000)    // 2 secondes

// Tâche d'attestation continue
#define ATTESTATION_TASK_STACK_SIZE      (6144)
#define ATTESTATION_TASK_PRIORITY        (9)
#define ATTESTATION_INTERVAL_MS          (30000)   // 30 secondes

// ================================
// Configuration des timers
// ================================

#define INTEGRITY_CHECK_INTERVAL_US      (60000000) // 60 secondes en microsecondes
#define HEARTBEAT_INTERVAL_US            (10000000) // 10 secondes en microsecondes

// ================================
// Configuration des queues
// ================================

#define SECURITY_EVENT_QUEUE_SIZE        (20)
#define SENSOR_DATA_QUEUE_SIZE           (10)

// ================================
// Configuration GPIO et hardware
// ================================

// Configuration DHT22 - ESP32 Crypto Intégré
#define DHT22_GPIO_PIN                  (4)
#define DHT22_POWER_GPIO                (5)  // GPIO pour alimenter le capteur

// LED de statut
#define STATUS_LED_GPIO                 (2)  // LED interne ESP32

// Bouton de reset sécurisé
#define SECURE_RESET_GPIO               (0)  // Boot button

// ================================
// Configuration ESP32 Crypto Intégré
// ================================

// Configuration eFuse pour stockage des clés
#define ESP32_EFUSE_DEVICE_KEY_BLOCK     (0)     // Clé privée principale
#define ESP32_EFUSE_ATTESTATION_BLOCK    (1)     // Clé d'attestation
#define ESP32_EFUSE_ENCRYPTION_BLOCK     (2)     // Clé de chiffrement
#define ESP32_EFUSE_HMAC_BLOCK           (3)     // Clé HMAC

// Configuration Secure Boot
#define ESP32_SECURE_BOOT_V2_ENABLED     (true)
#define ESP32_FLASH_ENCRYPTION_ENABLED   (true)
#define ESP32_EFUSE_PROTECTION_ENABLED   (true)

// Configuration TRNG (True Random Number Generator)
#define ESP32_TRNG_ENTROPY_THRESHOLD     (512)   // Seuil minimum d'entropie
#define ESP32_RANDOM_GENERATION_TIMEOUT  (1000)  // Timeout génération aléatoire (ms)

// ================================
// Configuration de sécurité
// ================================

// Niveaux de sécurité
#define SECURITY_LEVEL_LOW              (1)
#define SECURITY_LEVEL_MEDIUM           (2)
#define SECURITY_LEVEL_HIGH             (3)
#define SECURITY_LEVEL_CRITICAL         (4)

#define CURRENT_SECURITY_LEVEL          SECURITY_LEVEL_HIGH

// Tailles des clés et algorithmes crypto ESP32
#define ECDSA_KEY_SIZE_BITS             (256)    // ECDSA P-256
#define AES_KEY_SIZE_BITS               (256)    // AES-256
#define RSA_KEY_SIZE_BITS               (2048)   // RSA-2048
#define HMAC_KEY_SIZE_BYTES             (32)     // HMAC-SHA256

// Tailles de hash et signatures
#define SHA256_DIGEST_SIZE              (32)
#define ECDSA_SIGNATURE_SIZE            (64)
#define RSA_SIGNATURE_SIZE              (256)

// ================================
// Configuration de l'intégrité
// ================================

#define FIRMWARE_SIGNATURE_SIZE         ECDSA_SIGNATURE_SIZE
#define FIRMWARE_HASH_SIZE              SHA256_DIGEST_SIZE
#define MAX_FIRMWARE_CHUNKS             (256)
#define FIRMWARE_CHUNK_SIZE             (4096)

// Intervalles de vérification
#define INTEGRITY_CHECK_BOOT_DELAY_MS   (3000)   // Réduit grâce à ESP32 crypto
#define INTEGRITY_CHECK_MAX_FAILURES    (3)

// ================================
// Configuration de l'attestation
// ================================

#define ATTESTATION_CHALLENGE_SIZE      (32)
#define ATTESTATION_RESPONSE_SIZE       (128)
#define ATTESTATION_MAX_RETRIES         (3)
#define ATTESTATION_TIMEOUT_MS          (5000)   // Réduit grâce à ESP32 crypto

// Types d'attestation
#define ATTESTATION_TYPE_STARTUP        (1)
#define ATTESTATION_TYPE_PERIODIC       (2)
#define ATTESTATION_TYPE_ON_DEMAND      (3)

// ================================
// Configuration des capteurs
// ================================

// Limites DHT22
#define DHT22_TEMP_MIN                  (-40.0f)
#define DHT22_TEMP_MAX                  (80.0f)
#define DHT22_HUMIDITY_MIN              (0.0f)
#define DHT22_HUMIDITY_MAX              (100.0f)

// Seuils d'anomalie
#define TEMP_ANOMALY_THRESHOLD          (5.0f)    // Écart en °C
#define HUMIDITY_ANOMALY_THRESHOLD      (15.0f)   // Écart en %
#define SENSOR_READ_MAX_FAILURES        (5)

// ================================
// Configuration réseau et communication
// ================================

#define WIFI_SSID_MAX_LEN               (32)
#define WIFI_PASSWORD_MAX_LEN           (64)
#define WIFI_CONNECTION_TIMEOUT_MS      (30000)
#define WIFI_MAX_RETRY                  (5)

// Configuration MQTT (pour attestation distante)
#define MQTT_BROKER_MAX_LEN             (256)
#define MQTT_TOPIC_MAX_LEN              (128)
#define MQTT_MESSAGE_MAX_LEN            (1024)
#define MQTT_CLIENT_ID_MAX_LEN          (64)

// ================================
// Configuration de logging
// ================================

#define MAX_LOG_MESSAGE_SIZE            (256)
#define SECURITY_LOG_BUFFER_SIZE        (4096)
#define LOG_ROTATION_SIZE_KB            (64)

// ================================
// Configuration de la détection d'anomalies
// ================================

#define ANOMALY_HISTORY_SIZE            (100)
#define ANOMALY_DETECTION_WINDOW        (10)
#define ANOMALY_SCORE_THRESHOLD         (0.8f)
#define ANOMALY_LEARNING_PERIOD_MS      (300000)  // 5 minutes

// ================================
// Types d'événements de sécurité
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
    SECURITY_EVENT_CRYPTO_ERROR,           // Nouveau: erreur crypto ESP32
    SECURITY_EVENT_EFUSE_CORRUPTION,       // Nouveau: corruption eFuse
    SECURITY_EVENT_SECURE_BOOT_FAILURE,    // Nouveau: échec secure boot
    SECURITY_EVENT_MAX
} security_event_type_t;

// ================================
// Niveaux de sévérité
// ================================

typedef enum {
    SECURITY_SEVERITY_INFO = 1,
    SECURITY_SEVERITY_LOW,
    SECURITY_SEVERITY_MEDIUM,
    SECURITY_SEVERITY_HIGH,
    SECURITY_SEVERITY_CRITICAL
} security_severity_t;

// ================================
// États système
// ================================

typedef enum {
    SYSTEM_STATE_BOOTING = 0,
    SYSTEM_STATE_INITIALIZING,
    SYSTEM_STATE_CRYPTO_SETUP,             // Nouveau: setup crypto ESP32
    SYSTEM_STATE_NORMAL_OPERATION,
    SYSTEM_STATE_SECURITY_ALERT,
    SYSTEM_STATE_EMERGENCY,
    SYSTEM_STATE_SHUTDOWN
} system_state_t;

// ================================
// Configuration de la gestion d'énergie
// ================================

#define POWER_SAVE_MODE_ENABLED         (1)
#define SLEEP_MODE_DURATION_MS          (60000)   // 1 minute
#define WAKEUP_STUB_SIZE_BYTES          (8192)

// Configuration économie d'énergie ESP32
#define ESP32_LIGHT_SLEEP_ENABLED       (true)
#define ESP32_CRYPTO_CLOCK_GATING       (true)    // Gating horloge crypto quand inutilisé
#define ESP32_POWER_MANAGEMENT_ENABLED  (true)

// ================================
// Macros utilitaires
// ================================

#define ARRAY_SIZE(x)                   (sizeof(x) / sizeof((x)[0]))
#define MIN(a, b)                       ((a) < (b) ? (a) : (b))
#define MAX(a, b)                       ((a) > (b) ? (a) : (b))
#define ALIGN(x, a)                     (((x) + (a) - 1) & ~((a) - 1))

// Macros de vérification
#define CHECK_ERROR(x) do { \
    esp_err_t __err_rc = (x); \
    if (__err_rc != ESP_OK) { \
        ESP_LOGE(TAG, "Erreur: %s (0x%x) à %s:%d", esp_err_to_name(__err_rc), __err_rc, __FILE__, __LINE__); \
        return __err_rc; \
    } \
} while(0)

#define CHECK_NULL(x) do { \
    if ((x) == NULL) { \
        ESP_LOGE(TAG, "Pointeur NULL à %s:%d", __FILE__, __LINE__); \
        return ESP_ERR_INVALID_ARG; \
    } \
} while(0)

#define CHECK_CRYPTO_ERROR(x) do { \
    esp32_crypto_result_t __crypto_rc = (x); \
    if (__crypto_rc != ESP32_CRYPTO_SUCCESS) { \
        ESP_LOGE(TAG, "Erreur crypto: %s à %s:%d", esp32_crypto_error_to_string(__crypto_rc), __FILE__, __LINE__); \
        return ESP_FAIL; \
    } \
} while(0)

// ================================
// Structure de configuration globale
// ================================

typedef struct {
    // Configuration sécurité
    uint8_t security_level;
    bool secure_boot_enabled;
    bool flash_encryption_enabled;
    bool efuse_protection_enabled;          // Nouveau: protection eFuse
    
    // Configuration crypto ESP32
    bool hardware_crypto_enabled;           // Nouveau: crypto matériel
    bool trng_enabled;                      // Nouveau: TRNG
    uint8_t efuse_key_blocks_used;          // Nouveau: blocs eFuse utilisés
    
    // Configuration réseau
    char wifi_ssid[WIFI_SSID_MAX_LEN];
    char wifi_password[WIFI_PASSWORD_MAX_LEN];
    
    // Configuration attestation
    uint32_t attestation_interval;
    bool remote_attestation_enabled;
    
    // Configuration capteurs
    uint32_t sensor_read_interval;
    bool anomaly_detection_enabled;
    
    // État système
    system_state_t current_state;
    uint32_t boot_count;
    uint64_t uptime_seconds;
    
} global_config_t;

// ================================
// Variables globales (extern)
// ================================

extern global_config_t g_config;

// ================================
// Compatibilité avec code existant
// ================================

// Aliases pour compatibilité (facilitent la transition)
#define se_manager_init()                    esp32_crypto_manager_init(NULL)
#define se_manager_deinit()                  esp32_crypto_manager_deinit()
#define se_get_device_info(info)             esp32_crypto_get_device_info(info)
#define se_health_check()                    esp32_crypto_health_check()
#define se_generate_key_pair(id, key)        esp32_crypto_generate_ecdsa_keypair(id, key)
#define se_get_public_key(id, key)           esp32_crypto_get_public_key(id, key)
#define se_sign_message(id, hash, sig)       esp32_crypto_ecdsa_sign(id, hash, sig)
#define se_verify_signature(key, hash, sig)  esp32_crypto_ecdsa_verify(key, hash, sig)
#define se_generate_random(buf, len)         esp32_crypto_generate_random(buf, len)
#define se_perform_attestation(ch, sz, att)  esp32_crypto_perform_attestation(ch, sz, att)
#define se_verify_integrity()                esp32_crypto_verify_integrity()
#define se_update_heartbeat(cnt)             esp32_crypto_update_heartbeat(cnt)
#define se_store_emergency_state()           esp32_crypto_store_emergency_state()

#ifdef __cplusplus
}
#endif

#endif /* APP_CONFIG_H */