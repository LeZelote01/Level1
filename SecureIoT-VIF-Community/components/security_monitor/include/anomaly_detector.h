/**
 * @file anomaly_detector.h
 * @brief Header pour le détecteur d'anomalies Community Edition
 * 
 * Interface simplifiée pour la détection d'anomalies par seuils fixes.
 * Version éducative sans ML adaptatif.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "sensor_manager.h"

// ================================
// Constantes Community
// ================================

#define ANOMALY_HISTORY_SIZE_COMMUNITY      (30)        // Réduit vs Enterprise
#define ANOMALY_DETECTION_WINDOW_COMMUNITY  (5)         // Réduit vs Enterprise
#define ANOMALY_SCORE_THRESHOLD_COMMUNITY   (0.3f)      // Plus tolérant

// ================================
// Types et énumérations
// ================================

/**
 * @brief Codes d'erreur du détecteur d'anomalies
 */
typedef enum {
    ANOMALY_SUCCESS = 0,
    ANOMALY_ERROR_NOT_INITIALIZED,
    ANOMALY_ERROR_INVALID_DATA,
    ANOMALY_ERROR_INSUFFICIENT_DATA,
    ANOMALY_ERROR_THRESHOLD_INVALID,
    ANOMALY_MAX
} anomaly_error_t;

/**
 * @brief Structure des seuils de détection Community
 */
typedef struct {
    float temp_min;                 // Température minimale acceptable
    float temp_max;                 // Température maximale acceptable
    float humidity_min;             // Humidité minimale acceptable
    float humidity_max;             // Humidité maximale acceptable
    float temp_change_max;          // Changement max température entre lectures
    float humidity_change_max;      // Changement max humidité entre lectures
} anomaly_thresholds_t;

/**
 * @brief Résultat de détection d'anomalie Community
 */
typedef struct {
    bool is_anomaly;                // Anomalie détectée ?
    float anomaly_score;            // Score d'anomalie 0.0-1.0
    uint64_t timestamp;             // Timestamp de l'analyse
    float temperature;              // Température analysée
    float humidity;                 // Humidité analysée
    anomaly_error_t error_code;     // Code d'erreur
    
    // Détails des anomalies (Community)
    bool temp_anomaly;              // Anomalie température ?
    bool humidity_anomaly;          // Anomalie humidité ?
    bool change_anomaly;            // Changement rapide ?
} anomaly_result_t;

/**
 * @brief Statistiques du détecteur Community
 */
typedef struct {
    uint32_t total_analyses;        // Analyses totales
    uint32_t normal_analyses;       // Analyses normales
    uint32_t anomalies_detected;    // Anomalies détectées
    uint64_t last_anomaly_time;     // Dernière anomalie (timestamp)
    uint64_t init_time;             // Timestamp d'initialisation
} anomaly_stats_community_t;

// ================================
// Fonctions d'initialisation
// ================================

/**
 * @brief Initialise le détecteur d'anomalies Community
 * 
 * Version simplifiée utilisant uniquement des seuils fixes.
 * 
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t anomaly_detector_basic_init(void);

/**
 * @brief Deinitialise le détecteur d'anomalies
 * 
 * @return ESP_OK si succès
 */
esp_err_t anomaly_detector_basic_deinit(void);

// ================================
// Fonctions de détection Community
// ================================

/**
 * @brief Détection d'anomalies par seuils fixes (Community)
 * 
 * Méthode simplifiée pour l'apprentissage:
 * - Vérification contre seuils absolus
 * - Détection de changements rapides
 * - Pas d'apprentissage automatique
 * 
 * @param data Données capteur à analyser
 * @return anomaly_result_t Résultat de l'analyse
 */
anomaly_result_t anomaly_detect_threshold_based(const sensor_data_t *data);

// ================================
// Fonctions de configuration Community
// ================================

/**
 * @brief Configure les seuils de détection Community
 * 
 * Permet de personnaliser les seuils pour l'apprentissage.
 * 
 * @param thresholds Nouveaux seuils à appliquer
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG si seuils invalides
 */
esp_err_t anomaly_set_thresholds_community(const anomaly_thresholds_t *thresholds);

/**
 * @brief Obtient les seuils actuels
 * 
 * @param thresholds Pointeur vers la structure de seuils
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG sinon
 */
esp_err_t anomaly_get_thresholds_community(anomaly_thresholds_t *thresholds);

// ================================
// Fonctions de statistiques Community
// ================================

/**
 * @brief Obtient les statistiques du détecteur Community
 * 
 * @param stats Pointeur vers la structure de statistiques
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG sinon
 */
esp_err_t anomaly_get_stats_community(anomaly_stats_community_t *stats);

/**
 * @brief Affiche les statistiques du détecteur Community
 */
void anomaly_print_stats_community(void);

/**
 * @brief Réinitialise les statistiques du détecteur
 * 
 * @return ESP_OK si succès, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t anomaly_reset_stats_community(void);

// ================================
// Fonctions utilitaires Community
// ================================

/**
 * @brief Test de fonctionnement du détecteur Community
 * 
 * @return ESP_OK si tous les tests passent, ESP_FAIL sinon
 */
esp_err_t anomaly_detector_self_test(void);

/**
 * @brief Affiche les informations du détecteur Community
 */
void anomaly_detector_print_info(void);

/**
 * @brief Convertit un code d'erreur en chaîne
 * 
 * @param error Code d'erreur anomaly_error_t
 * @return Chaîne décrivant l'erreur
 */
const char* anomaly_error_to_string(anomaly_error_t error);

// ================================
// Macros utilitaires Community
// ================================

/**
 * @brief Vérifie si un score d'anomalie dépasse le seuil
 */
#define ANOMALY_IS_DETECTED_COMMUNITY(score) \
    ((score) >= ANOMALY_SCORE_THRESHOLD_COMMUNITY)

/**
 * @brief Calcule le pourcentage d'anomalies
 */
#define ANOMALY_CALC_RATE_COMMUNITY(detected, total) \
    (((total) > 0) ? ((float)(detected) / (total) * 100.0f) : 0.0f)

// ================================
// Seuils par défaut Community
// ================================

#define ANOMALY_DEFAULT_TEMP_MIN_COMMUNITY      (5.0f)      // Plus large qu'Enterprise
#define ANOMALY_DEFAULT_TEMP_MAX_COMMUNITY      (45.0f)     // Plus large qu'Enterprise
#define ANOMALY_DEFAULT_HUMIDITY_MIN_COMMUNITY  (10.0f)     // Plus large qu'Enterprise
#define ANOMALY_DEFAULT_HUMIDITY_MAX_COMMUNITY  (90.0f)     // Plus large qu'Enterprise
#define ANOMALY_DEFAULT_TEMP_CHANGE_COMMUNITY   (10.0f)     // Plus tolérant
#define ANOMALY_DEFAULT_HUMIDITY_CHANGE_COMMUNITY (20.0f)   // Plus tolérant

// ================================
// Messages informatifs Community
// ================================

#define ANOMALY_COMMUNITY_FEATURES \
    "🎓 Fonctionnalités Community:\n" \
    "• Détection par seuils fixes\n" \
    "• Configuration seuils personnalisés\n" \
    "• Détection changements rapides\n" \
    "• Statistiques détaillées\n" \
    "• Historique simple\n"

#define ANOMALY_COMMUNITY_LIMITATIONS \
    "⚠️  Limitations Community:\n" \
    "• Pas d'apprentissage automatique\n" \
    "• Pas d'adaptation comportementale\n" \
    "• Seuils fixes uniquement\n" \
    "• Historique limité (30 vs 100)\n" \
    "• Usage éducatif uniquement\n"

#define ANOMALY_UPGRADE_TO_ENTERPRISE \
    "🚀 Upgrade vers Enterprise pour:\n" \
    "• Machine Learning adaptatif\n" \
    "• Adaptation comportementale automatique\n" \
    "• Algorithmes avancés (Z-score, etc.)\n" \
    "• Historique étendu et analyse temporelle\n" \
    "• Performance optimisée pour production\n"

#ifdef __cplusplus
}
#endif

#endif /* ANOMALY_DETECTOR_H */