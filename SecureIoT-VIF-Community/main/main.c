/**
 * @file main.c
 * @brief Point d'entrée principal du framework SecureIoT-VIF Community Edition
 * 
 * Version simplifiée avec fonctionnalités de base pour éducation et recherche.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_sleep.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "app_config.h"
#include "crypto_operations_basic.h"  // Version simplifiée
#include "integrity_checker.h"
#include "sensor_manager.h"
#include "anomaly_detector.h"
#include "incident_manager.h"

static const char *TAG = "SECURE_IOT_VIF_COMMUNITY";

// Handles des tâches principales
static TaskHandle_t security_monitor_task_handle = NULL;
static TaskHandle_t sensor_task_handle = NULL;

// Timers pour les vérifications périodiques
static esp_timer_handle_t integrity_check_timer = NULL;
static esp_timer_handle_t heartbeat_timer = NULL;

// Queues pour la communication inter-tâches
static QueueHandle_t security_event_queue = NULL;
static QueueHandle_t sensor_data_queue = NULL;

// Sémaphores pour la synchronisation
static SemaphoreHandle_t system_mutex = NULL;

/**
 * @brief Structure pour les événements de sécurité
 */
typedef struct {
    security_event_type_t type;
    uint32_t timestamp;
    uint8_t severity;
    char description[128];
    uint8_t data[64];
    size_t data_len;
} security_event_t;

/**
 * @brief Fonction de callback pour le timer de vérification d'intégrité (au démarrage)
 */
static void integrity_check_timer_callback(void* arg) {
    ESP_LOGI(TAG, "🔍 Vérification d'intégrité de base (Community Edition)");
    
    // Vérification simplifiée au démarrage uniquement
    integrity_status_t status = integrity_check_firmware_basic();
    if (status != INTEGRITY_OK) {
        ESP_LOGE(TAG, "❌ Échec vérification intégrité: %d", status);
        
        // Signaler l'événement de sécurité
        security_event_t event = {
            .type = SECURITY_EVENT_INTEGRITY_FAILURE,
            .timestamp = (uint32_t)(esp_timer_get_time() / 1000),
            .severity = SECURITY_SEVERITY_HIGH,
            .data_len = sizeof(integrity_status_t)
        };
        strncpy(event.description, "Échec vérification intégrité basique", sizeof(event.description)-1);
        memcpy(event.data, &status, sizeof(integrity_status_t));
        
        if (xQueueSend(security_event_queue, &event, 0) != pdPASS) {
            ESP_LOGE(TAG, "❌ Impossible d'envoyer événement de sécurité");
        }
    } else {
        ESP_LOGI(TAG, "✅ Vérification d'intégrité de base réussie");
    }
}

/**
 * @brief Fonction de callback pour le heartbeat système
 */
static void heartbeat_timer_callback(void* arg) {
    static uint32_t heartbeat_counter = 0;
    heartbeat_counter++;
    
    ESP_LOGD(TAG, "💓 Heartbeat système Community: %lu", heartbeat_counter);
    
    // Vérification de l'état des tâches critiques
    if (security_monitor_task_handle != NULL && 
        eTaskGetState(security_monitor_task_handle) == eDeleted) {
        ESP_LOGE(TAG, "💥 Tâche de monitoring terminée - redémarrage requis");
        esp_restart();
    }
}

/**
 * @brief Tâche de monitoring de sécurité (version simplifiée)
 */
static void security_monitor_task(void *pvParameters) {
    ESP_LOGI(TAG, "🛡️ Démarrage monitoring sécurité Community Edition");
    
    security_event_t event;
    TickType_t xLastWakeTime = xTaskGetTickCount();
    
    while (1) {
        // Traitement des événements de sécurité
        if (xQueueReceive(security_event_queue, &event, pdMS_TO_TICKS(100)) == pdPASS) {
            ESP_LOGW(TAG, "⚠️ Événement sécurité reçu: type=%d, sévérité=%d, desc=%s", 
                     event.type, event.severity, event.description);
            
            // Traitement basique selon le type d'événement
            switch (event.type) {
                case SECURITY_EVENT_INTEGRITY_FAILURE:
                    incident_handle_integrity_failure(&event);
                    break;
                    
                case SECURITY_EVENT_ANOMALY_DETECTED:
                    incident_handle_anomaly(&event);
                    break;
                    
                case SECURITY_EVENT_SENSOR_MALFUNCTION:
                    ESP_LOGW(TAG, "🌡️ Dysfonctionnement capteur détecté");
                    break;
                    
                default:
                    ESP_LOGW(TAG, "❓ Événement de sécurité non reconnu: %d", event.type);
                    break;
            }
        }
        
        vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(SECURITY_MONITOR_INTERVAL_MS));
    }
}

/**
 * @brief Tâche de gestion des capteurs
 */
static void sensor_task(void *pvParameters) {
    ESP_LOGI(TAG, "🌡️ Démarrage tâche gestion capteurs");
    
    sensor_data_t sensor_data;
    TickType_t xLastWakeTime = xTaskGetTickCount();
    
    while (1) {
        // Lecture des données capteurs
        esp_err_t ret = sensor_read_dht22(&sensor_data);
        if (ret == ESP_OK) {
            ESP_LOGD(TAG, "📊 Données capteur: T=%.1f°C, H=%.1f%%", 
                     sensor_data.temperature, sensor_data.humidity);
            
            // Détection d'anomalies par seuils fixes (Community Edition)
            anomaly_result_t anomaly = anomaly_detect_threshold_based(&sensor_data);
            if (anomaly.is_anomaly) {
                ESP_LOGW(TAG, "🚨 Anomalie détectée (seuils fixes): score=%.3f", anomaly.anomaly_score);
                
                // Signaler l'événement
                security_event_t event = {
                    .type = SECURITY_EVENT_ANOMALY_DETECTED,
                    .timestamp = (uint32_t)(esp_timer_get_time() / 1000),
                    .severity = SECURITY_SEVERITY_MEDIUM,
                    .data_len = sizeof(anomaly_result_t)
                };
                snprintf(event.description, sizeof(event.description), 
                         "Anomalie seuils fixes: score=%.3f", anomaly.anomaly_score);
                memcpy(event.data, &anomaly, sizeof(anomaly_result_t));
                
                xQueueSend(security_event_queue, &event, portMAX_DELAY);
            }
            
            // Envoyer les données à la queue pour traitement
            if (xQueueSend(sensor_data_queue, &sensor_data, 0) != pdPASS) {
                ESP_LOGW(TAG, "📦 Queue des données capteur pleine");
            }
        } else {
            ESP_LOGE(TAG, "❌ Erreur lecture capteur: %s", esp_err_to_name(ret));
        }
        
        vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
    }
}

/**
 * @brief Initialisation du système de sécurité (version Community)
 */
static esp_err_t init_security_system(void) {
    esp_err_t ret = ESP_OK;
    
    ESP_LOGI(TAG, "🔐 === Initialisation Système Community Edition ===");
    
    // Initialisation crypto de base (pas d'HSM avancé)
    ESP_LOGI(TAG, "🔑 Initialisation crypto de base...");
    ret = crypto_operations_basic_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation crypto de base: %s", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "✅ Crypto de base initialisé");
    
    // Vérification initiale d'intégrité (au démarrage seulement)
    ESP_LOGI(TAG, "🔍 Vérification intégrité initiale...");
    integrity_status_t integrity_status = integrity_check_firmware_basic();
    if (integrity_status != INTEGRITY_OK) {
        ESP_LOGE(TAG, "❌ Échec vérification intégrité initiale: %d", integrity_status);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "✅ Vérification intégrité initiale réussie");
    
    // Initialisation des capteurs
    ESP_LOGI(TAG, "🌡️ Initialisation gestionnaire de capteurs...");
    ret = sensor_manager_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation gestionnaire de capteurs: %s", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "✅ Gestionnaire de capteurs initialisé");
    
    // Initialisation du détecteur d'anomalies (seuils fixes)
    ESP_LOGI(TAG, "🤖 Initialisation détecteur d'anomalies de base...");
    ret = anomaly_detector_basic_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation détecteur d'anomalies: %s", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "✅ Détecteur d'anomalies de base initialisé");
    
    // Initialisation du gestionnaire d'incidents
    ESP_LOGI(TAG, "🚨 Initialisation gestionnaire d'incidents...");
    ret = incident_manager_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec initialisation gestionnaire d'incidents: %s", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "✅ Gestionnaire d'incidents initialisé");
    
    ESP_LOGI(TAG, "🎉 === Système Community Edition Initialisé ===");
    return ESP_OK;
}

/**
 * @brief Initialisation des tâches et timers
 */
static esp_err_t init_tasks_and_timers(void) {
    esp_err_t ret = ESP_OK;
    
    ESP_LOGI(TAG, "⚙️ Initialisation tâches et timers Community...");
    
    // Création des queues
    security_event_queue = xQueueCreate(SECURITY_EVENT_QUEUE_SIZE, sizeof(security_event_t));
    if (security_event_queue == NULL) {
        ESP_LOGE(TAG, "❌ Échec création queue événements de sécurité");
        return ESP_FAIL;
    }
    
    sensor_data_queue = xQueueCreate(SENSOR_DATA_QUEUE_SIZE, sizeof(sensor_data_t));
    if (sensor_data_queue == NULL) {
        ESP_LOGE(TAG, "❌ Échec création queue données capteur");
        return ESP_FAIL;
    }
    
    // Création des sémaphores
    system_mutex = xSemaphoreCreateMutex();
    if (system_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Échec création mutex système");
        return ESP_FAIL;
    }
    
    // Création des tâches
    BaseType_t task_ret = xTaskCreate(
        security_monitor_task,
        "security_monitor_community",
        SECURITY_MONITOR_STACK_SIZE,
        NULL,
        SECURITY_MONITOR_PRIORITY,
        &security_monitor_task_handle
    );
    if (task_ret != pdPASS) {
        ESP_LOGE(TAG, "❌ Échec création tâche monitoring Community");
        return ESP_FAIL;
    }
    
    task_ret = xTaskCreate(
        sensor_task,
        "sensor_task_community",
        SENSOR_TASK_STACK_SIZE,
        NULL,
        SENSOR_TASK_PRIORITY,
        &sensor_task_handle
    );
    if (task_ret != pdPASS) {
        ESP_LOGE(TAG, "❌ Échec création tâche capteur");
        return ESP_FAIL;
    }
    
    // Configuration des timers (vérification moins fréquente en Community)
    esp_timer_create_args_t integrity_timer_args = {
        .callback = &integrity_check_timer_callback,
        .arg = NULL,
        .name = "integrity_check_timer_community"
    };
    
    ret = esp_timer_create(&integrity_timer_args, &integrity_check_timer);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec création timer vérification intégrité: %s", esp_err_to_name(ret));
        return ret;
    }
    
    esp_timer_create_args_t heartbeat_timer_args = {
        .callback = &heartbeat_timer_callback,
        .arg = NULL,
        .name = "heartbeat_timer_community"
    };
    
    ret = esp_timer_create(&heartbeat_timer_args, &heartbeat_timer);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec création timer heartbeat: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Démarrage des timers (intervalles plus longs en Community)
    ret = esp_timer_start_periodic(integrity_check_timer, INTEGRITY_CHECK_INTERVAL_US_COMMUNITY);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec démarrage timer vérification intégrité: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ret = esp_timer_start_periodic(heartbeat_timer, HEARTBEAT_INTERVAL_US);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Échec démarrage timer heartbeat: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ESP_LOGI(TAG, "✅ Tâches et timers Community initialisés");
    return ESP_OK;
}

/**
 * @brief Point d'entrée principal de l'application Community
 */
void app_main(void) {
    ESP_LOGI(TAG, "🚀 === Démarrage SecureIoT-VIF Community Edition ===");
    
    // Initialisation de la mémoire NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Initialisation du stack réseau par défaut
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // Affichage d'informations système
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    ESP_LOGI(TAG, "🔧 Chip ESP32 avec %d cœurs, WiFi%s%s, révision silicium %d",
             chip_info.cores,
             (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
             (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "",
             chip_info.revision);
    
    ESP_LOGI(TAG, "💾 Mémoire flash: %dMB %s", 
             spi_flash_get_chip_size() / (1024 * 1024),
             (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "intégrée" : "externe");
    
    // Afficher les capacités Community Edition
    ESP_LOGI(TAG, "🎓 SecureIoT-VIF Community Edition:");
    ESP_LOGI(TAG, "  ✅ Crypto de base pour éducation et recherche");
    ESP_LOGI(TAG, "  ✅ Vérification d'intégrité au démarrage");
    ESP_LOGI(TAG, "  ✅ Détection d'anomalies par seuils fixes");
    ESP_LOGI(TAG, "  ✅ Interface capteurs DHT22 complète");
    ESP_LOGI(TAG, "  🎯 Idéal pour apprentissage et prototypage!");
    
    // Initialisation du système de sécurité Community
    ret = init_security_system();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "💥 Échec initialisation système Community - arrêt");
        esp_restart();
    }
    
    // Initialisation des tâches et timers
    ret = init_tasks_and_timers();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "💥 Échec initialisation tâches et timers - arrêt");
        esp_restart();
    }
    
    ESP_LOGI(TAG, "🎉 === SecureIoT-VIF Community Edition Opérationnel ===");
    ESP_LOGI(TAG, "🎓 Framework éducatif et de recherche actif");
    ESP_LOGI(TAG, "💡 Idéal pour apprendre la sécurité IoT!");
    
    // La boucle principale est gérée par les tâches FreeRTOS
}

/**
 * @brief Handler d'urgence pour les exceptions non gérées
 */
void app_main_panic_handler(void) {
    ESP_LOGE(TAG, "💥 PANIQUE SYSTÈME Community - Redémarrage d'urgence");
    
    // Délai pour permettre l'affichage
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    // Redémarrage forcé
    esp_restart();
}