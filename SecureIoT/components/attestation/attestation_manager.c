/**
 * @file attestation_manager.c
 * @brief Implémentation du gestionnaire d'attestation continue
 */

#include "attestation_manager.h"
#include "remote_verifier.h"
#include "se_manager.h"
#include "integrity_checker.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>

static const char *TAG = "ATTESTATION_MGR";
static bool g_attestation_initialized = false;
static uint32_t g_sequence_counter = 0;

esp_err_t attestation_manager_init(void) {
    if (g_attestation_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Initialisation gestionnaire d'attestation");
    
    // Initialisation du vérifieur distant
    esp_err_t ret = remote_verifier_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Échec initialisation vérifieur distant: %s", esp_err_to_name(ret));
        return ret;
    }
    
    g_attestation_initialized = true;
    g_sequence_counter = 0;
    
    ESP_LOGI(TAG, "Gestionnaire d'attestation initialisé");
    return ESP_OK;
}

esp_err_t attestation_manager_deinit(void) {
    if (!g_attestation_initialized) return ESP_OK;
    
    ESP_LOGI(TAG, "Dé-initialisation gestionnaire d'attestation");
    remote_verifier_deinit();
    g_attestation_initialized = false;
    
    return ESP_OK;
}

attestation_result_t attestation_perform_continuous(void) {
    attestation_result_t result = {0};
    
    if (!g_attestation_initialized) {
        result.status = ATTESTATION_ERROR_COMMUNICATION;
        return result;
    }
    
    ESP_LOGD(TAG, "Exécution attestation continue #%lu", g_sequence_counter);
    
    // Génération d'un challenge auto-signé
    uint8_t challenge[ATTESTATION_CHALLENGE_SIZE];
    se_result_t se_ret = se_generate_random(challenge, sizeof(challenge));
    if (se_ret != SE_SUCCESS) {
        result.status = ATTESTATION_ERROR_COMMUNICATION;
        return result;
    }
    
    // Réponse au challenge
    esp_err_t ret = attestation_respond_to_challenge(challenge, sizeof(challenge), &result);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Échec réponse challenge attestation");
        result.status = ATTESTATION_ERROR_SIGNATURE_FAILED;
        return result;
    }
    
    // Vérification de l'intégrité pendant l'attestation
    integrity_status_t integrity_status = integrity_check_firmware();
    if (integrity_status != INTEGRITY_OK) {
        ESP_LOGW(TAG, "Intégrité compromise pendant attestation: %s", 
                 integrity_status_to_string(integrity_status));
        result.status = ATTESTATION_ERROR_SIGNATURE_FAILED;
        return result;
    }
    
    result.sequence_number = ++g_sequence_counter;
    result.status = ATTESTATION_SUCCESS;
    result.is_valid = true;
    
    ESP_LOGD(TAG, "Attestation continue réussie #%lu", g_sequence_counter);
    return result;
}

esp_err_t attestation_respond_to_challenge(const uint8_t* challenge, size_t challenge_size, attestation_result_t* result) {
    if (!challenge || !result || challenge_size != ATTESTATION_CHALLENGE_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGD(TAG, "Réponse au challenge d'attestation");
    
    // Copie du challenge
    memcpy(result->challenge, challenge, ATTESTATION_CHALLENGE_SIZE);
    
    // Génération de la réponse avec l'élément sécurisé
    se_attestation_t se_attestation;
    se_result_t se_ret = se_perform_attestation(challenge, challenge_size, &se_attestation);
    if (se_ret != SE_SUCCESS) {
        ESP_LOGE(TAG, "Échec attestation SE: %s", se_error_to_string(se_ret));
        return ESP_FAIL;
    }
    
    // Construction de la réponse
    memcpy(result->response, se_attestation.response, MIN(ATTESTATION_RESPONSE_SIZE, SE_SIGNATURE_SIZE));
    memcpy(result->device_certificate, se_attestation.device_cert, MIN(ATTESTATION_CERT_SIZE, SE_CERTIFICATE_SIZE));
    
    result->timestamp = se_attestation.timestamp;
    result->is_valid = se_attestation.is_valid;
    result->status = se_attestation.is_valid ? ATTESTATION_SUCCESS : ATTESTATION_ERROR_SIGNATURE_FAILED;
    
    ESP_LOGD(TAG, "Réponse challenge générée: %s", result->is_valid ? "Valide" : "Invalide");
    return ESP_OK;
}

esp_err_t attestation_generate_self_attestation(attestation_result_t* result) {
    if (!result) return ESP_ERR_INVALID_ARG;
    
    ESP_LOGD(TAG, "Génération auto-attestation");
    
    // Génération d'un challenge local
    uint8_t self_challenge[ATTESTATION_CHALLENGE_SIZE];
    se_result_t se_ret = se_generate_random(self_challenge, sizeof(self_challenge));
    if (se_ret != SE_SUCCESS) {
        return ESP_FAIL;
    }
    
    // Ajout de l'état système au challenge
    struct timeval tv;
    gettimeofday(&tv, NULL);
    memcpy(&self_challenge[28], &tv.tv_sec, 4); // 4 derniers bytes = timestamp
    
    return attestation_respond_to_challenge(self_challenge, sizeof(self_challenge), result);
}