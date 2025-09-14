/**
 * @file remote_verifier.h
 * @brief Vérifieur distant Enterprise pour attestation SecureIoT-VIF
 * 
 * Version Enterprise avec TLS obligatoire, authentification avancée,
 * retry intelligent et monitoring des communications.
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef REMOTE_VERIFIER_H
#define REMOTE_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

// ================================
// Constantes Enterprise
// ================================

#define REMOTE_VERIFIER_URL_MAX_LEN         (512)   // URLs plus longues
#define REMOTE_VERIFIER_API_KEY_MAX_LEN     (128)   // Clés API plus longues
#define REMOTE_VERIFIER_ENDPOINT_MAX_LEN    (256)   // Endpoints détaillés
#define REMOTE_VERIFIER_CERT_MAX_LEN        (2048)  // Certificats complets

// ================================
// Structures Enterprise
// ================================

/**
 * @brief Configuration du vérifieur distant Enterprise
 */
typedef struct {
    char server_url[REMOTE_VERIFIER_URL_MAX_LEN];
    uint16_t server_port;
    char api_endpoint[REMOTE_VERIFIER_ENDPOINT_MAX_LEN];
    char api_key[REMOTE_VERIFIER_API_KEY_MAX_LEN];
    uint32_t timeout_ms;
    bool tls_enabled;                   // Obligatoire en Enterprise
    bool certificate_validation;        // Validation certificats
    uint32_t retry_attempts;            // Nombre de tentatives
    uint32_t retry_delay_ms;            // Délai entre tentatives
    bool compression_enabled;           // Compression gzip
    bool keep_alive_enabled;            // Connexions persistantes
    char custom_ca_cert[REMOTE_VERIFIER_CERT_MAX_LEN]; // Certificat CA personnalisé
} remote_verifier_config_enterprise_t;

/**
 * @brief Statistiques du vérifieur distant Enterprise
 */
typedef struct {
    uint32_t total_requests;
    uint32_t successful_requests;
    uint32_t failed_requests;
    uint32_t retry_attempts;
    float success_rate;
    float avg_response_time_ms;
    uint32_t uptime_seconds;
} remote_verifier_stats_enterprise_t;

/**
 * @brief Configuration de base pour compatibilité
 */
typedef struct {
    char server_url[256];
    uint16_t server_port;
    char api_key[64];
    uint32_t timeout_ms;
    bool tls_enabled;
} remote_verifier_config_t;

// ================================
// API Enterprise
// ================================

/**
 * @brief Initialisation du vérifieur distant Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t remote_verifier_init_enterprise(void);

/**
 * @brief Dé-initialisation du vérifieur Enterprise
 * @return ESP_OK en cas de succès
 */
esp_err_t remote_verifier_deinit_enterprise(void);

/**
 * @brief Envoi d'attestation avec retry intelligent Enterprise
 * @param attestation_data Données d'attestation à envoyer
 * @param data_len Taille des données
 * @return ESP_OK en cas de succès
 */
esp_err_t remote_verifier_send_attestation_enterprise(const uint8_t* attestation_data, size_t data_len);

/**
 * @brief Configuration du vérifieur distant Enterprise
 * @param config Configuration Enterprise complète
 * @return ESP_OK en cas de succès
 */
esp_err_t remote_verifier_configure_enterprise(const remote_verifier_config_enterprise_t* config);

/**
 * @brief Obtention des statistiques du vérifieur Enterprise
 * @return Statistiques complètes
 */
remote_verifier_stats_enterprise_t remote_verifier_get_stats_enterprise(void);

/**
 * @brief Test de connectivité du vérifieur Enterprise
 * @return ESP_OK si la connectivité est OK
 */
esp_err_t remote_verifier_test_connectivity_enterprise(void);

// ================================
// API Compatibilité (versions standard)
// ================================

/**
 * @brief Initialisation (compatibilité)
 */
esp_err_t remote_verifier_init(void);

/**
 * @brief Dé-initialisation (compatibilité)
 */
esp_err_t remote_verifier_deinit(void);

/**
 * @brief Envoi d'attestation (compatibilité)
 */
esp_err_t remote_verifier_send_attestation(const uint8_t* attestation_data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_VERIFIER_H */