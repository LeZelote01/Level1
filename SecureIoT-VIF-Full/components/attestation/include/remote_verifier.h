/**
 * @file remote_verifier.h
 * @brief Vérifieur distant pour attestation SecureIoT-VIF
 */

#ifndef REMOTE_VERIFIER_H
#define REMOTE_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef struct {
    char server_url[256];
    uint16_t server_port;
    char api_key[64];
    uint32_t timeout_ms;
    bool tls_enabled;
} remote_verifier_config_t;

esp_err_t remote_verifier_init(void);
esp_err_t remote_verifier_deinit(void);
esp_err_t remote_verifier_send_attestation(const uint8_t* attestation_data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_VERIFIER_H */