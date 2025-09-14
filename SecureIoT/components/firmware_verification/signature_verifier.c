/**
 * @file signature_verifier.c
 * @brief Implémentation du vérificateur de signatures
 */

#include "signature_verifier.h"
#include "se_manager.h"
#include "esp_log.h"

static const char *TAG = "SIG_VERIFIER";

esp_err_t signature_verify_firmware(const integrity_metadata_t* metadata, signature_verification_result_t* result) {
    if (!metadata || !result) return ESP_ERR_INVALID_ARG;
    
    uint64_t start_time = esp_timer_get_time();
    
    // Simulation de vérification de signature
    se_result_t se_ret = se_verify_signature(
        metadata->global_signature, 
        metadata->global_hash, 
        metadata->global_signature
    );
    
    result->is_valid = (se_ret == SE_SUCCESS);
    memcpy(result->signature, metadata->global_signature, 64);
    result->verification_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    
    ESP_LOGD(TAG, "Vérification signature firmware: %s", result->is_valid ? "OK" : "ÉCHEC");
    return ESP_OK;
}

esp_err_t signature_verify_chunk(const integrity_chunk_info_t* chunk, signature_verification_result_t* result) {
    if (!chunk || !result) return ESP_ERR_INVALID_ARG;
    
    uint64_t start_time = esp_timer_get_time();
    
    // Simulation de vérification de signature chunk
    se_result_t se_ret = se_verify_signature(
        chunk->signature, 
        chunk->hash, 
        chunk->signature
    );
    
    result->is_valid = (se_ret == SE_SUCCESS);
    memcpy(result->signature, chunk->signature, 64);
    result->verification_time_ms = (uint32_t)((esp_timer_get_time() - start_time) / 1000);
    
    ESP_LOGD(TAG, "Vérification signature chunk %lu: %s", chunk->chunk_id, result->is_valid ? "OK" : "ÉCHEC");
    return ESP_OK;
}