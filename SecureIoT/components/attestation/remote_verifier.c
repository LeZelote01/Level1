/**
 * @file remote_verifier.c
 * @brief Implémentation du vérifieur distant
 */

#include "remote_verifier.h"
#include "esp_log.h"

static const char *TAG = "REMOTE_VERIFIER";
static bool g_verifier_initialized = false;

esp_err_t remote_verifier_init(void) {
    if (g_verifier_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Initialisation vérifieur distant");
    g_verifier_initialized = true;
    return ESP_OK;
}

esp_err_t remote_verifier_deinit(void) {
    if (!g_verifier_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Dé-initialisation vérifieur distant");
    g_verifier_initialized = false;
    return ESP_OK;
}

esp_err_t remote_verifier_send_attestation(const uint8_t* attestation_data, size_t data_len) {
    if (!g_verifier_initialized || !attestation_data) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGD(TAG, "Envoi attestation distante (%zu bytes)", data_len);
    // Simulation d'envoi - dans une vraie implémentation, utiliserait HTTP/HTTPS
    return ESP_OK;
}