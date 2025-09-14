/**
 * @file dht22_driver.h
 * @brief Header pour le driver DHT22 - Community Edition
 * 
 * Interface complète identique à Enterprise pour le driver DHT22.
 * Basé sur le fichier original du projet.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#ifndef DHT22_DRIVER_H
#define DHT22_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "app_config.h"

// ================================
// Constantes DHT22
// ================================

// Limites physiques du capteur DHT22
#define DHT22_TEMP_MIN                  (-40.0f)
#define DHT22_TEMP_MAX                  (80.0f)
#define DHT22_HUMIDITY_MIN              (0.0f)
#define DHT22_HUMIDITY_MAX              (100.0f)

// Timings DHT22 (en microsecondes)
#define DHT22_START_SIGNAL_DURATION     (1000)     // 1ms LOW
#define DHT22_HOST_PULL_UP_DURATION     (30)       // 30µs HIGH
#define DHT22_RESPONSE_WAIT_TIMEOUT     (100)      // 100µs max
#define DHT22_DATA_BIT_TIMEOUT          (80)       // 80µs max

// Durées des bits DHT22
#define DHT22_BIT_0_HIGH_DURATION       (26)       // ~26-28µs pour bit 0
#define DHT22_BIT_1_HIGH_DURATION       (70)       // ~70µs pour bit 1
#define DHT22_BIT_THRESHOLD             (40)       // Seuil de décision

// ================================
// Types et structures
// ================================

/**
 * @brief Statistiques du driver DHT22
 */
typedef struct {
    uint32_t total_reads;           // Lectures totales
    uint32_t successful_reads;      // Lectures réussies
    uint32_t failed_reads;          // Lectures échouées
    uint32_t checksum_errors;       // Erreurs de checksum
    uint32_t out_of_range_reads;    // Lectures hors plage
    uint64_t last_read_time;        // Dernier timestamp
    uint64_t init_time;             // Timestamp d'initialisation
    uint32_t total_read_time_ms;    // Temps total de lecture
    float min_temperature;          // Température minimale lue
    float max_temperature;          // Température maximale lue
    float min_humidity;             // Humidité minimale lue
    float max_humidity;             // Humidité maximale lue
} dht22_stats_t;

// ================================
// Fonctions d'initialisation
// ================================

/**
 * @brief Initialise le driver DHT22
 * 
 * Configure les GPIOs et prépare le capteur pour la lecture.
 * 
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t dht22_driver_init(void);

/**
 * @brief Deinitialise le driver DHT22
 * 
 * @return ESP_OK si succès
 */
esp_err_t dht22_driver_deinit(void);

// ================================
// Fonctions de lecture
// ================================

/**
 * @brief Lit les données du capteur DHT22
 * 
 * Effectue la séquence complète de communication avec le DHT22:
 * 1. Signal de démarrage
 * 2. Attente de la réponse
 * 3. Lecture des 40 bits de données
 * 4. Vérification du checksum
 * 5. Conversion des valeurs
 * 
 * @param temperature Pointeur vers la température (°C)
 * @param humidity Pointeur vers l'humidité (%)
 * @return ESP_OK si succès, code d'erreur sinon
 */
esp_err_t dht22_read_data(float *temperature, float *humidity);

// ================================
// Fonctions de statistiques
// ================================

/**
 * @brief Obtient les statistiques du driver DHT22
 * 
 * @param stats Pointeur vers la structure de statistiques
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG sinon
 */
esp_err_t dht22_get_stats(dht22_stats_t *stats);

/**
 * @brief Affiche les statistiques du driver DHT22
 */
void dht22_print_stats(void);

/**
 * @brief Réinitialise les statistiques du driver DHT22
 * 
 * @return ESP_OK si succès, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t dht22_reset_stats(void);

// ================================
// Fonctions utilitaires
// ================================

/**
 * @brief Test de fonctionnement du driver DHT22
 * 
 * @return ESP_OK si tous les tests passent, ESP_FAIL sinon
 */
esp_err_t dht22_self_test(void);

/**
 * @brief Affiche les informations du driver DHT22
 */
void dht22_print_info(void);

// ================================
// Macros utilitaires
// ================================

/**
 * @brief Vérifie si une valeur de température est valide
 */
#define DHT22_IS_VALID_TEMPERATURE(temp) \
    ((temp) >= DHT22_TEMP_MIN && (temp) <= DHT22_TEMP_MAX)

/**
 * @brief Vérifie si une valeur d'humidité est valide
 */
#define DHT22_IS_VALID_HUMIDITY(hum) \
    ((hum) >= DHT22_HUMIDITY_MIN && (hum) <= DHT22_HUMIDITY_MAX)

/**
 * @brief Calcule le checksum DHT22
 */
#define DHT22_CALCULATE_CHECKSUM(data) \
    ((data)[0] + (data)[1] + (data)[2] + (data)[3])

#ifdef __cplusplus
}
#endif

#endif /* DHT22_DRIVER_H */