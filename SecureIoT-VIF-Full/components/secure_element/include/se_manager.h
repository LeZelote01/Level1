/**
 * @file se_manager.h
 * @brief Aliases de compatibilité pour SecureIoT-VIF ESP32 Crypto Intégré
 * 
 * Ce fichier fournit des aliases pour maintenir la compatibilité API
 * avec le crypto ESP32 intégré uniquement.
 * 
 * @author Framework SecureIoT-VIF
 * @version 2.0.0 - ESP32 Crypto Intégré
 * @date 2025
 */

#ifndef SE_MANAGER_H
#define SE_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

// Inclure l'interface ESP32 crypto intégré
#include "esp32_crypto_manager.h"

// ================================
// Aliases de Types
// ================================

typedef esp32_crypto_result_t se_result_t;
typedef esp32_crypto_info_t se_device_info_t;
typedef esp32_key_info_t se_key_info_t;
typedef esp32_signature_t se_signature_t;
typedef esp32_attestation_t se_attestation_t;

// États
#define SE_SUCCESS                  ESP32_CRYPTO_SUCCESS
#define SE_ERROR_INVALID_PARAM      ESP32_CRYPTO_ERROR_INVALID_PARAM
#define SE_ERROR_NOT_INITIALIZED    ESP32_CRYPTO_ERROR_NOT_INITIALIZED
#define SE_ERROR_VERIFICATION_FAILED ESP32_CRYPTO_ERROR_VERIFICATION_FAILED
#define SE_ERROR_EXECUTION_FAILED   ESP32_CRYPTO_ERROR_EXECUTION_FAILED
#define SE_ERROR_MEMORY             ESP32_CRYPTO_ERROR_MEMORY

// Constantes
#define SE_SERIAL_NUMBER_SIZE       ESP32_SERIAL_NUMBER_SIZE
#define SE_PUBLIC_KEY_SIZE          ESP32_PUBLIC_KEY_SIZE
#define SE_PRIVATE_KEY_SIZE         ESP32_PRIVATE_KEY_SIZE
#define SE_SIGNATURE_SIZE           ESP32_SIGNATURE_SIZE
#define SE_CERTIFICATE_SIZE         ESP32_CERTIFICATE_SIZE
#define SE_RANDOM_BYTES_SIZE        ESP32_RANDOM_BYTES_SIZE

// Slots
#define SE_SLOT_DEVICE_PRIVATE_KEY   ESP32_EFUSE_KEY_BLOCK_0
#define SE_SLOT_ATTESTATION_KEY      ESP32_EFUSE_KEY_BLOCK_1
#define SE_SLOT_ENCRYPTION_KEY       ESP32_EFUSE_KEY_BLOCK_2
#define SE_SLOT_ROOT_CA_PUBLIC_KEY   ESP32_EFUSE_KEY_BLOCK_3

// ================================
// Aliases de Fonctions
// ================================

// Gestion générale
#define se_manager_init()                    esp32_crypto_manager_init(NULL)
#define se_manager_deinit()                  esp32_crypto_manager_deinit()
#define se_get_device_info(info)             esp32_crypto_get_device_info(info)
#define se_health_check()                    esp32_crypto_health_check()

// Gestion des clés
#define se_generate_key_pair(id, key)        esp32_crypto_generate_ecdsa_keypair(id, key)
#define se_get_public_key(id, key)           esp32_crypto_get_public_key(id, key)
#define se_get_key_info(id, info)            esp32_crypto_get_key_info(id, info)

// Opérations cryptographiques
#define se_sign_message(id, hash, sig)       esp32_crypto_ecdsa_sign(id, hash, sig)
#define se_verify_signature(key, hash, sig)  esp32_crypto_ecdsa_verify(key, hash, sig)
#define se_generate_random(buf, len)         esp32_crypto_generate_random(buf, len)

// Attestation et vérification
#define se_perform_attestation(ch, sz, att)  esp32_crypto_perform_attestation(ch, sz, att)
#define se_verify_integrity()                esp32_crypto_verify_integrity()

// Gestion d'état
#define se_update_heartbeat(cnt)             esp32_crypto_update_heartbeat(cnt)
#define se_store_emergency_state()           esp32_crypto_store_emergency_state()

// Utilitaires
#define se_error_to_string(error)            esp32_crypto_error_to_string(error)
#define se_print_device_info()               esp32_crypto_print_device_info()
#define se_self_test()                       esp32_crypto_self_test()
#define se_get_statistics(ops, err, time)    esp32_crypto_get_statistics(ops, err, time)

#ifdef __cplusplus
}
#endif

#endif /* SE_MANAGER_H */