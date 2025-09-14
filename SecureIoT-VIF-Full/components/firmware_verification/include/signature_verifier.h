/**
 * @file signature_verifier.h
 * @brief Vérificateur de signatures pour SecureIoT-VIF
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#ifndef SIGNATURE_VERIFIER_H
#define SIGNATURE_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "integrity_checker.h"

typedef struct {
    bool is_valid;
    uint8_t signature[64];
    uint32_t verification_time_ms;
} signature_verification_result_t;

esp_err_t signature_verify_firmware(const integrity_metadata_t* metadata, signature_verification_result_t* result);
esp_err_t signature_verify_chunk(const integrity_chunk_info_t* chunk, signature_verification_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_VERIFIER_H */