/**
 * @file sensor_manager.h
 * @brief Header pour le gestionnaire de capteurs - Community Edition
 * 
 * Interface complète identique à Enterprise pour les capteurs.
 * Basé sur le fichier original du projet.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#ifndef SENSOR_MANAGER_H
#define SENSOR_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "app_config.h"

// ================================
// Types et structures
// ================================

/**
 * @brief Structure pour les données d'un capteur
 */
typedef struct {
    float temperature;              // Température en °C
    float humidity;                 // Humidité relative en %
    uint64_t timestamp;             // Timestamp en millisecondes
    uint32_t read_duration_ms;      // Durée de lecture en ms
    uint8_t quality_score;          // Score de qualité 0-100
} sensor_data_t;

/**
 * @brief Statistiques du gestionnaire de capteurs
 */
typedef struct {
    uint32_t total_readings;        // Lectures totales
    uint32_t successful_readings;   // Lectures réussies
    uint32_t failed_readings;       // Lectures échouées
    uint32_t invalid_readings;      // Lectures invalides
    uint64_t last_reading_time;     // Dernier timestamp
    uint64_t last_error_time;       // Dernier timestamp d'erreur
    uint64_t start_time;            // Timestamp de démarrage
    uint32_t total_read_time_ms;    // Temps total de lecture
    float min_temperature;          // Température minimale
    float max_temperature;          // Température maximale
    float avg_temperature;          // Température moyenne
    float min_humidity;             // Humidité minimale
    float max_humidity;             // Humidité maximale
    float avg_humidity;             // Humidité moyenne
} sensor_stats_t;

// ================================
// Fonctions d'initialisation
// ================================

/**
 * @brief Initialise le gestionnaire de capteurs
 * 
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t sensor_manager_init(void);

/**
 * @brief Deinitialise le gestionnaire de capteurs
 * 
 * @return ESP_OK si succès
 */
esp_err_t sensor_manager_deinit(void);

// ================================
// Fonctions de lecture des capteurs
// ================================

/**
 * @brief Lit les données du capteur DHT22
 * 
 * @param data Pointeur vers la structure de données
 * @return ESP_OK si succès, code d'erreur sinon
 */
esp_err_t sensor_read_dht22(sensor_data_t *data);

// ================================
// Fonctions utilitaires
// ================================

/**
 * @brief Calcule un score de qualité pour les données capteur
 * 
 * @param data Pointeur vers les données capteur
 * @return Score de qualité de 0 à 100
 */
uint8_t sensor_calculate_quality(const sensor_data_t *data);

/**
 * @brief Obtient les statistiques du gestionnaire de capteurs
 * 
 * @param stats Pointeur vers la structure de statistiques
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG sinon
 */
esp_err_t sensor_get_stats(sensor_stats_t *stats);

/**
 * @brief Obtient la dernière lecture de capteur
 * 
 * @param data Pointeur vers la structure de données
 * @return ESP_OK si succès, ESP_ERR_NOT_FOUND si aucune lecture
 */
esp_err_t sensor_get_last_reading(sensor_data_t *data);

/**
 * @brief Affiche les statistiques du gestionnaire de capteurs
 */
void sensor_print_stats(void);

/**
 * @brief Réinitialise les statistiques du gestionnaire
 * 
 * @return ESP_OK si succès, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t sensor_reset_stats(void);

/**
 * @brief Test de fonctionnement du gestionnaire de capteurs
 * 
 * @return ESP_OK si tous les tests passent, ESP_FAIL sinon
 */
esp_err_t sensor_manager_self_test(void);

/**
 * @brief Affiche les informations du gestionnaire de capteurs
 */
void sensor_manager_print_info(void);

// ================================
// Macros utilitaires
// ================================

#define SENSOR_IS_VALID_TEMP(temp) \
    ((temp) >= DHT22_TEMP_MIN && (temp) <= DHT22_TEMP_MAX)

#define SENSOR_IS_VALID_HUMIDITY(hum) \
    ((hum) >= DHT22_HUMIDITY_MIN && (hum) <= DHT22_HUMIDITY_MAX)

#define SENSOR_IS_VALID_DATA(data) \
    (SENSOR_IS_VALID_TEMP((data)->temperature) && \
     SENSOR_IS_VALID_HUMIDITY((data)->humidity))

#ifdef __cplusplus
}
#endif

#endif /* SENSOR_MANAGER_H */