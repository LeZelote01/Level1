/**
 * @file incident_manager.h
 * @brief Header pour le gestionnaire d'incidents Community Edition
 * 
 * Interface simplifiée pour la gestion des incidents de sécurité.
 * Version éducative sans actions automatiques critiques.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#ifndef INCIDENT_MANAGER_H
#define INCIDENT_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

// ================================
// Types et structures Community
// ================================

/**
 * @brief Statistiques des incidents Community
 */
typedef struct {
    uint32_t total_incidents;       // Incidents totaux
    uint32_t integrity_failures;   // Échecs vérification intégrité
    uint32_t anomalies_handled;     // Anomalies gérées
    uint32_t security_violations;   // Violations de sécurité
    uint32_t other_incidents;       // Autres incidents
    uint64_t last_incident_time;    // Dernier incident (timestamp)
    uint64_t init_time;             // Timestamp d'initialisation
} incident_stats_t;

// ================================
// Fonctions d'initialisation
// ================================

/**
 * @brief Initialise le gestionnaire d'incidents Community
 * 
 * Version simplifiée pour l'apprentissage de la gestion d'incidents.
 * 
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t incident_manager_init(void);

/**
 * @brief Deinitialise le gestionnaire d'incidents
 * 
 * @return ESP_OK si succès
 */
esp_err_t incident_manager_deinit(void);

// ================================
// Fonctions de gestion d'incidents Community
// ================================

/**
 * @brief Gestion d'un échec de vérification d'intégrité
 * 
 * Version Community: logging et statistiques uniquement.
 * 
 * @param event_data Données de l'événement (peut être NULL)
 * @return ESP_OK si traité, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t incident_handle_integrity_failure(const void *event_data);

/**
 * @brief Gestion d'une anomalie détectée
 * 
 * Version Community: analyse basique et logging.
 * 
 * @param event_data Données de l'événement (peut être NULL)
 * @return ESP_OK si traité, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t incident_handle_anomaly(const void *event_data);

/**
 * @brief Gestion d'un échec d'attestation
 * 
 * Note: L'attestation n'est pas disponible en Community Edition.
 * 
 * @param event_data Données de l'événement (peut être NULL)
 * @return ESP_OK (information seulement)
 */
esp_err_t incident_handle_attestation_failure(const void *event_data);

/**
 * @brief Gestion d'un accès non autorisé
 * 
 * Version Community: logging et alerte console.
 * 
 * @param event_data Données de l'événement (peut être NULL)
 * @return ESP_OK si traité, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t incident_handle_unauthorized_access(const void *event_data);

// ================================
// Fonctions de statistiques Community
// ================================

/**
 * @brief Obtient les statistiques des incidents
 * 
 * @param stats Pointeur vers la structure de statistiques
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG sinon
 */
esp_err_t incident_get_stats(incident_stats_t *stats);

/**
 * @brief Affiche les statistiques des incidents
 */
void incident_print_stats(void);

/**
 * @brief Réinitialise les statistiques des incidents
 * 
 * @return ESP_OK si succès, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t incident_reset_stats(void);

// ================================
// Fonctions utilitaires Community
// ================================

/**
 * @brief Test de fonctionnement du gestionnaire Community
 * 
 * @return ESP_OK si tous les tests passent, ESP_FAIL sinon
 */
esp_err_t incident_manager_self_test(void);

/**
 * @brief Affiche les informations du gestionnaire Community
 */
void incident_manager_print_info(void);

// ================================
// Macros utilitaires Community
// ================================

/**
 * @brief Calcule le taux d'incidents par heure
 */
#define INCIDENT_CALC_RATE_PER_HOUR_COMMUNITY(incidents, uptime_ms) \
    (((uptime_ms) > 0) ? ((float)(incidents) * 3600000.0f / (uptime_ms)) : 0.0f)

// ================================
// Messages informatifs Community
// ================================

#define INCIDENT_COMMUNITY_FEATURES \
    "🎓 Fonctionnalités Community:\n" \
    "• Gestion incidents de base\n" \
    "• Logging détaillé\n" \
    "• Statistiques complètes\n" \
    "• Notifications console\n" \
    "• Idéal pour apprentissage\n"

#define INCIDENT_COMMUNITY_LIMITATIONS \
    "⚠️  Limitations Community:\n" \
    "• Pas d'actions automatiques\n" \
    "• Pas de redémarrage auto\n" \
    "• Pas d'escalade d'incidents\n" \
    "• Pas de notifications externes\n" \
    "• Usage éducatif uniquement\n"

#define INCIDENT_UPGRADE_TO_ENTERPRISE \
    "🚀 Upgrade vers Enterprise pour:\n" \
    "• Actions automatiques de récupération\n" \
    "• Redémarrage et isolation automatiques\n" \
    "• Escalade d'incidents configurable\n" \
    "• Notifications multiples (email, SMS, etc.)\n" \
    "• Intégration systèmes de monitoring\n"

#ifdef __cplusplus
}
#endif

#endif /* INCIDENT_MANAGER_H */