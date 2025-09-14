/**
 * @file attestation_manager.h
 * @brief Gestionnaire d'attestation continue pour SecureIoT-VIF
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
 * @date 2025
 */

#ifndef ATTESTATION_MANAGER_H
#define ATTESTATION_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define ATTESTATION_CHALLENGE_SIZE  (32)
#define ATTESTATION_RESPONSE_SIZE   (128)
#define ATTESTATION_CERT_SIZE       (512)

typedef enum {
    ATTESTATION_SUCCESS = 0,
    ATTESTATION_ERROR_INVALID_CHALLENGE = -1,
    ATTESTATION_ERROR_SIGNATURE_FAILED = -2,
    ATTESTATION_ERROR_CERTIFICATE_INVALID = -3,
    ATTESTATION_ERROR_TIMEOUT = -4,
    ATTESTATION_ERROR_COMMUNICATION = -5
} attestation_status_t;

typedef struct {
    attestation_status_t status;
    uint8_t challenge[ATTESTATION_CHALLENGE_SIZE];
    uint8_t response[ATTESTATION_RESPONSE_SIZE];
    uint8_t device_certificate[ATTESTATION_CERT_SIZE];
    uint32_t timestamp;
    bool is_valid;
    uint32_t sequence_number;
} attestation_result_t;

esp_err_t attestation_manager_init(void);
esp_err_t attestation_manager_deinit(void);
attestation_result_t attestation_perform_continuous(void);
esp_err_t attestation_respond_to_challenge(const uint8_t* challenge, size_t challenge_size, attestation_result_t* result);
esp_err_t attestation_generate_self_attestation(attestation_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* ATTESTATION_MANAGER_H */