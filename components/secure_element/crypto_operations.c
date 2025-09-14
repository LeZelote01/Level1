/**
 * @file crypto_operations.c
 * @brief Implémentation des opérations cryptographiques pour SecureIoT-VIF
 * 
 * Ce module implémente les opérations cryptographiques de haut niveau
 * en utilisant les capacités crypto intégrées de l'ESP32.
 * 
 * @author Framework SecureIoT-VIF
 * @version 2.0.0 - ESP32 Crypto Intégré
 * @date 2025
 */

#include "crypto_operations.h"
#include "se_manager.h"

#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbedtls/md5.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "CRYPTO_OPS";

static bool g_crypto_initialized = false;

// ================================
// Fonctions utilitaires internes
// ================================

/**
 * @brief Mappeur d'algorithmes de hachage vers mbedTLS
 */
static mbedtls_md_type_t map_hash_algorithm(crypto_hash_algorithm_t algorithm) {
    switch (algorithm) {
        case CRYPTO_HASH_SHA256: return MBEDTLS_MD_SHA256;
        case CRYPTO_HASH_SHA1: return MBEDTLS_MD_SHA1;
        case CRYPTO_HASH_MD5: return MBEDTLS_MD_MD5;
        default: return MBEDTLS_MD_NONE;
    }
}

/**
 * @brief Convertit un code d'erreur mbedTLS en résultat crypto
 */
static crypto_result_t mbedtls_to_crypto_result(int mbedtls_ret) {
    if (mbedtls_ret == 0) {
        return CRYPTO_SUCCESS;
    }
    
    switch (mbedtls_ret) {
        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
            return CRYPTO_ERROR_INVALID_PARAM;
        case MBEDTLS_ERR_AES_BAD_INPUT_DATA:
            return CRYPTO_ERROR_OPERATION_FAILED;
        default:
            return CRYPTO_ERROR_OPERATION_FAILED;
    }
}

// ================================
// Fonctions publiques - Initialisation
// ================================

crypto_result_t crypto_init(void) {
    if (g_crypto_initialized) {
        return CRYPTO_SUCCESS;
    }
    
    ESP_LOGI(TAG, "Initialisation du sous-système cryptographique");
    
    // Test des capacités matérielles
    uint8_t test_random[32];
    esp_fill_random(test_random, sizeof(test_random));
    
    // Vérification que le générateur aléatoire fonctionne
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(test_random); i++) {
        if (test_random[i] != 0) {
            all_zero = false;
            break;
        }
    }
    
    if (all_zero) {
        ESP_LOGE(TAG, "Générateur aléatoire ESP32 défaillant");
        return CRYPTO_ERROR_OPERATION_FAILED;
    }
    
    g_crypto_initialized = true;
    ESP_LOGI(TAG, "Sous-système cryptographique initialisé");
    return CRYPTO_SUCCESS;
}

void crypto_deinit(void) {
    if (g_crypto_initialized) {
        ESP_LOGI(TAG, "Dé-initialisation du sous-système cryptographique");
        g_crypto_initialized = false;
    }
}

// ================================
// Fonctions publiques - Hachage
// ================================

crypto_result_t crypto_hash_init(crypto_hash_ctx_t* ctx, crypto_hash_algorithm_t algorithm) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(crypto_hash_ctx_t));
    ctx->algorithm = algorithm;
    
    switch (algorithm) {
        case CRYPTO_HASH_SHA256: {
            ctx->internal_ctx = malloc(sizeof(mbedtls_sha256_context));
            if (ctx->internal_ctx == NULL) {
                return CRYPTO_ERROR_MEMORY;
            }
            mbedtls_sha256_init((mbedtls_sha256_context*)ctx->internal_ctx);
            int ret = mbedtls_sha256_starts_ret((mbedtls_sha256_context*)ctx->internal_ctx, 0);
            if (ret != 0) {
                free(ctx->internal_ctx);
                return mbedtls_to_crypto_result(ret);
            }
            ctx->digest_size = 32;
            break;
        }
        case CRYPTO_HASH_SHA1: {
            ctx->internal_ctx = malloc(sizeof(mbedtls_sha1_context));
            if (ctx->internal_ctx == NULL) {
                return CRYPTO_ERROR_MEMORY;
            }
            mbedtls_sha1_init((mbedtls_sha1_context*)ctx->internal_ctx);
            int ret = mbedtls_sha1_starts_ret((mbedtls_sha1_context*)ctx->internal_ctx);
            if (ret != 0) {
                free(ctx->internal_ctx);
                return mbedtls_to_crypto_result(ret);
            }
            ctx->digest_size = 20;
            break;
        }
        case CRYPTO_HASH_MD5: {
            ctx->internal_ctx = malloc(sizeof(mbedtls_md5_context));
            if (ctx->internal_ctx == NULL) {
                return CRYPTO_ERROR_MEMORY;
            }
            mbedtls_md5_init((mbedtls_md5_context*)ctx->internal_ctx);
            int ret = mbedtls_md5_starts_ret((mbedtls_md5_context*)ctx->internal_ctx);
            if (ret != 0) {
                free(ctx->internal_ctx);
                return mbedtls_to_crypto_result(ret);
            }
            ctx->digest_size = 16;
            break;
        }
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_hash_update(crypto_hash_ctx_t* ctx, const uint8_t* data, size_t data_len) {
    if (ctx == NULL || data == NULL || ctx->internal_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (ctx->is_finalized) {
        return CRYPTO_ERROR_OPERATION_FAILED;
    }
    
    int ret = 0;
    switch (ctx->algorithm) {
        case CRYPTO_HASH_SHA256:
            ret = mbedtls_sha256_update_ret((mbedtls_sha256_context*)ctx->internal_ctx, data, data_len);
            break;
        case CRYPTO_HASH_SHA1:
            ret = mbedtls_sha1_update_ret((mbedtls_sha1_context*)ctx->internal_ctx, data, data_len);
            break;
        case CRYPTO_HASH_MD5:
            ret = mbedtls_md5_update_ret((mbedtls_md5_context*)ctx->internal_ctx, data, data_len);
            break;
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    return mbedtls_to_crypto_result(ret);
}

crypto_result_t crypto_hash_final(crypto_hash_ctx_t* ctx, uint8_t* digest, size_t* digest_len) {
    if (ctx == NULL || digest == NULL || digest_len == NULL || ctx->internal_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (*digest_len < ctx->digest_size) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    
    if (ctx->is_finalized) {
        memcpy(digest, ctx->digest, ctx->digest_size);
        *digest_len = ctx->digest_size;
        return CRYPTO_SUCCESS;
    }
    
    int ret = 0;
    switch (ctx->algorithm) {
        case CRYPTO_HASH_SHA256:
            ret = mbedtls_sha256_finish_ret((mbedtls_sha256_context*)ctx->internal_ctx, ctx->digest);
            mbedtls_sha256_free((mbedtls_sha256_context*)ctx->internal_ctx);
            break;
        case CRYPTO_HASH_SHA1:
            ret = mbedtls_sha1_finish_ret((mbedtls_sha1_context*)ctx->internal_ctx, ctx->digest);
            mbedtls_sha1_free((mbedtls_sha1_context*)ctx->internal_ctx);
            break;
        case CRYPTO_HASH_MD5:
            ret = mbedtls_md5_finish_ret((mbedtls_md5_context*)ctx->internal_ctx, ctx->digest);
            mbedtls_md5_free((mbedtls_md5_context*)ctx->internal_ctx);
            break;
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    if (ret == 0) {
        memcpy(digest, ctx->digest, ctx->digest_size);
        *digest_len = ctx->digest_size;
        ctx->is_finalized = true;
        
        free(ctx->internal_ctx);
        ctx->internal_ctx = NULL;
    }
    
    return mbedtls_to_crypto_result(ret);
}

crypto_result_t crypto_hash_compute(crypto_hash_algorithm_t algorithm, 
                                    const uint8_t* data, size_t data_len,
                                    uint8_t* digest, size_t* digest_len) {
    crypto_hash_ctx_t ctx;
    
    crypto_result_t result = crypto_hash_init(&ctx, algorithm);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    result = crypto_hash_update(&ctx, data, data_len);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    return crypto_hash_final(&ctx, digest, digest_len);
}

// ================================
// Fonctions publiques - Chiffrement symétrique
// ================================

crypto_result_t crypto_cipher_init(crypto_cipher_ctx_t* ctx, 
                                   crypto_cipher_algorithm_t algorithm,
                                   const uint8_t* key, size_t key_len,
                                   const uint8_t* iv, bool is_encrypt) {
    if (ctx == NULL || key == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(crypto_cipher_ctx_t));
    ctx->algorithm = algorithm;
    ctx->is_encrypt = is_encrypt;
    
    // Vérification de la longueur de clé
    size_t expected_key_len = 0;
    switch (algorithm) {
        case CRYPTO_CIPHER_AES_256_CBC:
        case CRYPTO_CIPHER_AES_256_GCM:
            expected_key_len = 32;
            break;
        case CRYPTO_CIPHER_AES_128_CBC:
        case CRYPTO_CIPHER_AES_128_GCM:
            expected_key_len = 16;
            break;
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    if (key_len != expected_key_len) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memcpy(ctx->key, key, key_len);
    if (iv != NULL) {
        memcpy(ctx->iv, iv, CRYPTO_AES_IV_SIZE);
    }
    
    // Initialisation du contexte mbedTLS
    switch (algorithm) {
        case CRYPTO_CIPHER_AES_256_CBC:
        case CRYPTO_CIPHER_AES_128_CBC: {
            ctx->internal_ctx = malloc(sizeof(mbedtls_aes_context));
            if (ctx->internal_ctx == NULL) {
                return CRYPTO_ERROR_MEMORY;
            }
            
            mbedtls_aes_init((mbedtls_aes_context*)ctx->internal_ctx);
            int ret;
            if (is_encrypt) {
                ret = mbedtls_aes_setkey_enc((mbedtls_aes_context*)ctx->internal_ctx, key, key_len * 8);
            } else {
                ret = mbedtls_aes_setkey_dec((mbedtls_aes_context*)ctx->internal_ctx, key, key_len * 8);
            }
            
            if (ret != 0) {
                mbedtls_aes_free((mbedtls_aes_context*)ctx->internal_ctx);
                free(ctx->internal_ctx);
                return mbedtls_to_crypto_result(ret);
            }
            break;
        }
        case CRYPTO_CIPHER_AES_256_GCM:
        case CRYPTO_CIPHER_AES_128_GCM: {
            ctx->internal_ctx = malloc(sizeof(mbedtls_gcm_context));
            if (ctx->internal_ctx == NULL) {
                return CRYPTO_ERROR_MEMORY;
            }
            
            mbedtls_gcm_init((mbedtls_gcm_context*)ctx->internal_ctx);
            int ret = mbedtls_gcm_setkey((mbedtls_gcm_context*)ctx->internal_ctx, 
                                         MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
            
            if (ret != 0) {
                mbedtls_gcm_free((mbedtls_gcm_context*)ctx->internal_ctx);
                free(ctx->internal_ctx);
                return mbedtls_to_crypto_result(ret);
            }
            break;
        }
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    ctx->is_initialized = true;
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_cipher_update(crypto_cipher_ctx_t* ctx,
                                     const uint8_t* input, size_t input_len,
                                     uint8_t* output, size_t* output_len) {
    if (ctx == NULL || input == NULL || output == NULL || output_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->is_initialized) {
        return CRYPTO_ERROR_OPERATION_FAILED;
    }
    
    int ret = 0;
    switch (ctx->algorithm) {
        case CRYPTO_CIPHER_AES_256_CBC:
        case CRYPTO_CIPHER_AES_128_CBC: {
            // CBC nécessite un traitement par blocs complets
            if (input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
                return CRYPTO_ERROR_INVALID_PARAM;
            }
            
            if (*output_len < input_len) {
                return CRYPTO_ERROR_BUFFER_TOO_SMALL;
            }
            
            uint8_t iv_copy[CRYPTO_AES_IV_SIZE];
            memcpy(iv_copy, ctx->iv, CRYPTO_AES_IV_SIZE);
            
            ret = mbedtls_aes_crypt_cbc((mbedtls_aes_context*)ctx->internal_ctx,
                                        ctx->is_encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                        input_len, iv_copy, input, output);
            
            // Mise à jour de l'IV pour les opérations chaînées
            memcpy(ctx->iv, iv_copy, CRYPTO_AES_IV_SIZE);
            *output_len = input_len;
            break;
        }
        case CRYPTO_CIPHER_AES_256_GCM:
        case CRYPTO_CIPHER_AES_128_GCM: {
            // GCM - mode de chiffrement authentifié
            if (*output_len < input_len) {
                return CRYPTO_ERROR_BUFFER_TOO_SMALL;
            }
            
            // Pour GCM, nous utilisons une implémentation simplifiée
            // Dans une vraie implémentation, il faudrait gérer les AAD et tags
            ret = mbedtls_gcm_crypt_and_tag((mbedtls_gcm_context*)ctx->internal_ctx,
                                            ctx->is_encrypt ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                                            input_len, ctx->iv, CRYPTO_AES_IV_SIZE,
                                            NULL, 0, input, output, 16, NULL);
            *output_len = input_len;
            break;
        }
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    return mbedtls_to_crypto_result(ret);
}

crypto_result_t crypto_cipher_final(crypto_cipher_ctx_t* ctx, uint8_t* output, size_t* output_len) {
    if (ctx == NULL || output_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Pour la plupart des modes, il n'y a pas de données finales
    *output_len = 0;
    return CRYPTO_SUCCESS;
}

void crypto_cipher_cleanup(crypto_cipher_ctx_t* ctx) {
    if (ctx == NULL || ctx->internal_ctx == NULL) {
        return;
    }
    
    switch (ctx->algorithm) {
        case CRYPTO_CIPHER_AES_256_CBC:
        case CRYPTO_CIPHER_AES_128_CBC:
            mbedtls_aes_free((mbedtls_aes_context*)ctx->internal_ctx);
            break;
        case CRYPTO_CIPHER_AES_256_GCM:
        case CRYPTO_CIPHER_AES_128_GCM:
            mbedtls_gcm_free((mbedtls_gcm_context*)ctx->internal_ctx);
            break;
    }
    
    free(ctx->internal_ctx);
    crypto_secure_memzero(ctx, sizeof(crypto_cipher_ctx_t));
}

// ================================
// Fonctions publiques - Dérivation de clés
// ================================

crypto_result_t crypto_kdf_derive_key(const crypto_kdf_params_t* params, 
                                      uint8_t* output, size_t output_len) {
    if (params == NULL || output == NULL || params->password == NULL || params->salt == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    int ret = 0;
    switch (params->algorithm) {
        case CRYPTO_KDF_PBKDF2: {
            const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            if (info == NULL) {
                return CRYPTO_ERROR_OPERATION_FAILED;
            }
            
            ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                                params->password, params->password_len,
                                                params->salt, params->salt_len,
                                                params->iterations,
                                                output_len, output);
            break;
        }
        case CRYPTO_KDF_HKDF: {
            const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            if (info == NULL) {
                return CRYPTO_ERROR_OPERATION_FAILED;
            }
            
            ret = mbedtls_hkdf(info, params->salt, params->salt_len, 
                               params->password, params->password_len,
                               NULL, 0, output, output_len);
            break;
        }
        case CRYPTO_KDF_SCRYPT:
            // mbedTLS ne supporte pas scrypt nativement
            return CRYPTO_ERROR_NOT_SUPPORTED;
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    return mbedtls_to_crypto_result(ret);
}

crypto_result_t crypto_generate_salt(uint8_t* salt, size_t salt_len) {
    if (salt == NULL || salt_len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    esp_fill_random(salt, salt_len);
    return CRYPTO_SUCCESS;
}

// ================================
// Fonctions publiques - ECC avec crypto ESP32
// ================================

crypto_result_t crypto_ecc_generate_keypair_se(uint8_t slot_id, crypto_ecc_keypair_t* keypair) {
    if (keypair == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memset(keypair, 0, sizeof(crypto_ecc_keypair_t));
    
    se_result_t se_ret = se_generate_key_pair(slot_id, keypair->public_key);
    if (se_ret != SE_SUCCESS) {
        ESP_LOGE(TAG, "Échec génération paire de clés SE: %s", se_error_to_string(se_ret));
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    keypair->has_public = true;
    keypair->has_private = true; // La clé privée reste dans le SE
    keypair->curve_id = 0x01; // P-256
    
    ESP_LOGD(TAG, "Paire de clés ECC générée dans slot %d", slot_id);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_ecc_sign_se(uint8_t slot_id, const uint8_t* data, size_t data_len,
                                   crypto_ecc_signature_t* signature) {
    if (data == NULL || signature == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memset(signature, 0, sizeof(crypto_ecc_signature_t));
    
    // Calcul du hash des données
    uint8_t hash[CRYPTO_SHA256_DIGEST_SIZE];
    size_t hash_len = sizeof(hash);
    
    crypto_result_t result = crypto_hash_compute(CRYPTO_HASH_SHA256, data, data_len, hash, &hash_len);
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec calcul hash pour signature");
        return result;
    }
    
    // Signature avec l'élément sécurisé
    se_result_t se_ret = se_sign_message(slot_id, hash, signature->signature);
    if (se_ret != SE_SUCCESS) {
        ESP_LOGE(TAG, "Échec signature SE: %s", se_error_to_string(se_ret));
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    // Extraction des composantes R et S (format ECDSA standard)
    memcpy(signature->r, signature->signature, 32);
    memcpy(signature->s, signature->signature + 32, 32);
    signature->is_valid = true;
    
    ESP_LOGD(TAG, "Signature ECC générée avec slot %d", slot_id);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_ecc_verify(const uint8_t* public_key, 
                                  const uint8_t* data, size_t data_len,
                                  const crypto_ecc_signature_t* signature) {
    if (public_key == NULL || data == NULL || signature == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (!signature->is_valid) {
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    // Calcul du hash des données
    uint8_t hash[CRYPTO_SHA256_DIGEST_SIZE];
    size_t hash_len = sizeof(hash);
    
    crypto_result_t result = crypto_hash_compute(CRYPTO_HASH_SHA256, data, data_len, hash, &hash_len);
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec calcul hash pour vérification");
        return result;
    }
    
    // Vérification avec l'élément sécurisé
    se_result_t se_ret = se_verify_signature(public_key, hash, signature->signature);
    if (se_ret != SE_SUCCESS) {
        ESP_LOGD(TAG, "Vérification signature échouée: %s", se_error_to_string(se_ret));
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    ESP_LOGD(TAG, "Signature ECC vérifiée avec succès");
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_ecdh_se(uint8_t private_key_slot, const uint8_t* remote_public_key,
                               uint8_t* shared_secret) {
    if (remote_public_key == NULL || shared_secret == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    se_result_t se_ret = se_ecdh_key_exchange(private_key_slot, remote_public_key, shared_secret);
    if (se_ret != SE_SUCCESS) {
        ESP_LOGE(TAG, "Échec échange ECDH: %s", se_error_to_string(se_ret));
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    ESP_LOGD(TAG, "Échange ECDH réussi avec slot %d", private_key_slot);
    return CRYPTO_SUCCESS;
}

// ================================
// Fonctions publiques - HMAC
// ================================

crypto_result_t crypto_hmac_se(uint8_t key_slot, const uint8_t* data, size_t data_len,
                               uint8_t* hmac, size_t* hmac_len) {
    if (data == NULL || hmac == NULL || hmac_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (*hmac_len < 32) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    
    se_result_t se_ret = se_calculate_hmac(key_slot, data, data_len, hmac);
    if (se_ret != SE_SUCCESS) {
        ESP_LOGE(TAG, "Échec calcul HMAC SE: %s", se_error_to_string(se_ret));
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    *hmac_len = 32; // SHA-256 HMAC
    ESP_LOGD(TAG, "HMAC calculé avec slot %d", key_slot);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_hmac_verify_se(uint8_t key_slot, const uint8_t* data, size_t data_len,
                                      const uint8_t* expected_hmac, size_t hmac_len) {
    if (data == NULL || expected_hmac == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    uint8_t computed_hmac[32];
    size_t computed_hmac_len = sizeof(computed_hmac);
    
    crypto_result_t result = crypto_hmac_se(key_slot, data, data_len, computed_hmac, &computed_hmac_len);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    if (hmac_len != computed_hmac_len) {
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    if (crypto_secure_memcmp(computed_hmac, expected_hmac, hmac_len) != 0) {
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    ESP_LOGD(TAG, "HMAC vérifié avec succès");
    return CRYPTO_SUCCESS;
}

// ================================
// Fonctions publiques - Génération aléatoire ESP32
// ================================

crypto_result_t crypto_random_se(uint8_t* buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Utiliser le TRNG intégré ESP32 pour génération par chunks optimaux
    size_t remaining = length;
    uint8_t* ptr = buffer;
    
    while (remaining > 0) {
        size_t chunk_size = (remaining > 32) ? 32 : remaining;
        
        se_result_t se_ret = se_generate_random(ptr, chunk_size);
        if (se_ret != SE_SUCCESS) {
            ESP_LOGE(TAG, "Échec génération aléatoire SE: %s", se_error_to_string(se_ret));
            return CRYPTO_ERROR_SE_COMMUNICATION;
        }
        
        ptr += chunk_size;
        remaining -= chunk_size;
    }
    
    ESP_LOGD(TAG, "%zu bytes aléatoires générés avec SE", length);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_generate_nonce(uint8_t* nonce, size_t nonce_len) {
    if (nonce == NULL || nonce_len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Combinaison de l'aléatoire SE et ESP32 pour plus de robustesse
    uint8_t se_random[16];
    uint8_t esp_random[16];
    
    crypto_result_t result = crypto_random_se(se_random, sizeof(se_random));
    if (result != CRYPTO_SUCCESS) {
        // Fallback sur l'aléatoire ESP32 uniquement
        ESP_LOGW(TAG, "Utilisation aléatoire ESP32 uniquement pour nonce");
        esp_fill_random(nonce, nonce_len);
        return CRYPTO_SUCCESS;
    }
    
    esp_fill_random(esp_random, sizeof(esp_random));
    
    // XOR des deux sources pour le nonce final
    size_t copy_len = (nonce_len > 16) ? 16 : nonce_len;
    for (size_t i = 0; i < copy_len; i++) {
        nonce[i] = se_random[i] ^ esp_random[i];
    }
    
    // Si le nonce demandé est plus long, compléter avec l'aléatoire ESP32
    if (nonce_len > 16) {
        esp_fill_random(nonce + 16, nonce_len - 16);
    }
    
    ESP_LOGD(TAG, "Nonce de %zu bytes généré", nonce_len);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_generate_symmetric_key(uint8_t* key, size_t key_len) {
    return crypto_random_se(key, key_len);
}

// ================================
// Fonctions publiques - Intégrité firmware
// ================================

crypto_result_t crypto_compute_firmware_mac(const uint8_t* firmware_data, size_t firmware_size,
                                            uint8_t key_slot, uint8_t* mac, size_t* mac_len) {
    if (firmware_data == NULL || mac == NULL || mac_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Calcul MAC intégrité firmware (%zu bytes)", firmware_size);
    
    return crypto_hmac_se(key_slot, firmware_data, firmware_size, mac, mac_len);
}

crypto_result_t crypto_verify_firmware_integrity(const uint8_t* firmware_data, size_t firmware_size,
                                                 uint8_t key_slot, const uint8_t* expected_mac, 
                                                 size_t mac_len) {
    if (firmware_data == NULL || expected_mac == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Vérification intégrité firmware (%zu bytes)", firmware_size);
    
    return crypto_hmac_verify_se(key_slot, firmware_data, firmware_size, expected_mac, mac_len);
}

// ================================
// Fonctions publiques - Utilitaires
// ================================

const char* crypto_result_to_string(crypto_result_t result) {
    switch (result) {
        case CRYPTO_SUCCESS: return "Succès";
        case CRYPTO_ERROR_INVALID_PARAM: return "Paramètre invalide";
        case CRYPTO_ERROR_BUFFER_TOO_SMALL: return "Buffer trop petit";
        case CRYPTO_ERROR_OPERATION_FAILED: return "Opération échouée";
        case CRYPTO_ERROR_NOT_SUPPORTED: return "Non supporté";
        case CRYPTO_ERROR_VERIFICATION_FAILED: return "Vérification échouée";
        case CRYPTO_ERROR_MEMORY: return "Erreur mémoire";
        case CRYPTO_ERROR_SE_COMMUNICATION: return "Erreur communication SE";
        default: return "Erreur inconnue";
    }
}

void crypto_secure_memzero(void* buffer, size_t size) {
    if (buffer != NULL && size > 0) {
        mbedtls_platform_zeroize(buffer, size);
    }
}

int crypto_secure_memcmp(const void* a, const void* b, size_t len) {
    if (a == NULL || b == NULL) {
        return -1;
    }
    
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t result = 0;
    
    // Comparaison en temps constant
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result;
}

crypto_result_t crypto_performance_test(void) {
    ESP_LOGI(TAG, "Démarrage test de performance cryptographique");
    
    const size_t test_data_size = 1024;
    uint8_t test_data[1024];
    uint8_t output_buffer[1024];
    
    // Remplissage avec des données de test
    esp_fill_random(test_data, sizeof(test_data));
    
    // Test de hachage SHA-256
    uint64_t start_time = esp_timer_get_time();
    uint8_t hash[32];
    size_t hash_len = sizeof(hash);
    
    crypto_result_t result = crypto_hash_compute(CRYPTO_HASH_SHA256, test_data, test_data_size, hash, &hash_len);
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test hachage");
        return result;
    }
    
    uint64_t hash_time = esp_timer_get_time() - start_time;
    ESP_LOGI(TAG, "SHA-256 (%zu bytes): %llu µs", test_data_size, hash_time);
    
    // Test de chiffrement AES
    uint8_t aes_key[32];
    uint8_t aes_iv[16];
    crypto_generate_symmetric_key(aes_key, sizeof(aes_key));
    crypto_generate_nonce(aes_iv, sizeof(aes_iv));
    
    crypto_cipher_ctx_t cipher_ctx;
    start_time = esp_timer_get_time();
    
    result = crypto_cipher_init(&cipher_ctx, CRYPTO_CIPHER_AES_256_CBC, aes_key, sizeof(aes_key), aes_iv, true);
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec init chiffrement");
        return result;
    }
    
    size_t output_len = sizeof(output_buffer);
    result = crypto_cipher_update(&cipher_ctx, test_data, test_data_size, output_buffer, &output_len);
    crypto_cipher_cleanup(&cipher_ctx);
    
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test chiffrement");
        return result;
    }
    
    uint64_t cipher_time = esp_timer_get_time() - start_time;
    ESP_LOGI(TAG, "AES-256-CBC (%zu bytes): %llu µs", test_data_size, cipher_time);
    
    // Test de génération aléatoire SE
    uint8_t random_data[32];
    start_time = esp_timer_get_time();
    
    result = crypto_random_se(random_data, sizeof(random_data));
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGW(TAG, "SE non disponible pour test aléatoire");
    } else {
        uint64_t random_time = esp_timer_get_time() - start_time;
        ESP_LOGI(TAG, "Génération aléatoire SE (32 bytes): %llu µs", random_time);
    }
    
    ESP_LOGI(TAG, "Test de performance terminé avec succès");
    return CRYPTO_SUCCESS;
}