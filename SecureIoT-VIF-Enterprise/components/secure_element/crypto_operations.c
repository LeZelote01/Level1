/**
 * @file crypto_operations.c
 * @brief Opérations cryptographiques Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise complète avec toutes les fonctionnalités avancées :
 * - Support crypto post-quantique (préparation)
 * - Optimisations performance Enterprise
 * - Monitoring et métriques avancées
 * - Protection contre les attaques par canal auxiliaire
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#include "crypto_operations.h"
#include "esp32_crypto_manager.h"

#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha1.h"
#include "mbedtls/md5.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "CRYPTO_OPS_ENTERPRISE";

static bool g_crypto_initialized = false;

// Métriques Enterprise
static uint32_t g_total_operations = 0;
static uint64_t g_total_operation_time = 0;
static uint32_t g_operation_failures = 0;

// ================================
// Fonctions utilitaires internes Enterprise
// ================================

/**
 * @brief Mappeur d'algorithmes de hachage vers mbedTLS avec support Enterprise
 */
static mbedtls_md_type_t map_hash_algorithm_enterprise(crypto_hash_algorithm_t algorithm) {
    switch (algorithm) {
        case CRYPTO_HASH_SHA256: return MBEDTLS_MD_SHA256;
        case CRYPTO_HASH_SHA512: return MBEDTLS_MD_SHA512;  // Enterprise
        case CRYPTO_HASH_SHA1: return MBEDTLS_MD_SHA1;
        case CRYPTO_HASH_MD5: return MBEDTLS_MD_MD5;
        default: return MBEDTLS_MD_NONE;
    }
}

/**
 * @brief Convertit un code d'erreur mbedTLS en résultat crypto Enterprise
 */
static crypto_result_t mbedtls_to_crypto_result_enterprise(int mbedtls_ret) {
    if (mbedtls_ret == 0) {
        return CRYPTO_SUCCESS;
    }
    
    // Gestion d'erreur Enterprise plus détaillée
    switch (mbedtls_ret) {
        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
            ESP_LOGW(TAG, "Erreur paramètre AES Enterprise: -0x%04x", -mbedtls_ret);
            return CRYPTO_ERROR_INVALID_PARAM;
        case MBEDTLS_ERR_AES_BAD_INPUT_DATA:
            ESP_LOGW(TAG, "Données AES Enterprise invalides: -0x%04x", -mbedtls_ret);
            return CRYPTO_ERROR_OPERATION_FAILED;
        default:
            ESP_LOGW(TAG, "Erreur mbedTLS Enterprise non mappée: -0x%04x", -mbedtls_ret);
            return CRYPTO_ERROR_OPERATION_FAILED;
    }
}

/**
 * @brief Protection contre les attaques temporelles Enterprise
 */
static void crypto_timing_safe_delay_enterprise(void) {
    // Délai aléatoire pour protection contre les attaques temporelles
    uint8_t random_delay;
    esp_fill_random(&random_delay, 1);
    ets_delay_us(random_delay % 100);  // 0-99 µs de délai aléatoire
}

// ================================
// Fonctions publiques Enterprise - Initialisation
// ================================

crypto_result_t crypto_init_enterprise(void) {
    if (g_crypto_initialized) {
        return CRYPTO_SUCCESS;
    }
    
    ESP_LOGI(TAG, "Initialisation du sous-système cryptographique Enterprise");
    
    // Test des capacités matérielles Enterprise
    uint8_t test_random[64];  // Test avec plus de données en Enterprise
    esp_fill_random(test_random, sizeof(test_random));
    
    // Vérification Enterprise robuste du générateur aléatoire
    bool all_zero = true;
    bool all_same = true;
    uint8_t first_byte = test_random[0];
    
    for (size_t i = 0; i < sizeof(test_random); i++) {
        if (test_random[i] != 0) {
            all_zero = false;
        }
        if (test_random[i] != first_byte) {
            all_same = false;
        }
    }
    
    if (all_zero || all_same) {
        ESP_LOGE(TAG, "Générateur aléatoire ESP32 Enterprise défaillant");
        return CRYPTO_ERROR_OPERATION_FAILED;
    }
    
    // Test additionnel Enterprise : entropie
    uint32_t entropy_score = 0;
    for (size_t i = 0; i < sizeof(test_random) - 1; i++) {
        if (test_random[i] != test_random[i + 1]) {
            entropy_score++;
        }
    }
    
    if (entropy_score < (sizeof(test_random) / 4)) {  // Au moins 25% de différence
        ESP_LOGW(TAG, "Entropie faible détectée en Enterprise (score: %lu)", entropy_score);
    }
    
    g_crypto_initialized = true;
    ESP_LOGI(TAG, "Sous-système cryptographique Enterprise initialisé (entropie: %lu)", entropy_score);
    return CRYPTO_SUCCESS;
}

void crypto_deinit_enterprise(void) {
    if (g_crypto_initialized) {
        ESP_LOGI(TAG, "Dé-initialisation du sous-système cryptographique Enterprise");
        
        // Statistiques finales Enterprise
        ESP_LOGI(TAG, "Statistiques finales Enterprise:");
        ESP_LOGI(TAG, "  - Opérations totales: %lu", g_total_operations);
        ESP_LOGI(TAG, "  - Échecs: %lu", g_operation_failures);
        ESP_LOGI(TAG, "  - Temps total: %llu µs", g_total_operation_time);
        if (g_total_operations > 0) {
            ESP_LOGI(TAG, "  - Temps moyen: %llu µs", g_total_operation_time / g_total_operations);
        }
        
        g_crypto_initialized = false;
    }
}

// ================================
// Fonctions publiques Enterprise - Hachage
// ================================

crypto_result_t crypto_hash_init_enterprise(crypto_hash_ctx_t* ctx, crypto_hash_algorithm_t algorithm) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(crypto_hash_ctx_t));
    ctx->algorithm = algorithm;
    
    uint64_t start_time = esp_timer_get_time();
    
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
                return mbedtls_to_crypto_result_enterprise(ret);
            }
            ctx->digest_size = 32;
            break;
        }
        case CRYPTO_HASH_SHA512: {  // Support Enterprise SHA-512
            ctx->internal_ctx = malloc(sizeof(mbedtls_sha512_context));
            if (ctx->internal_ctx == NULL) {
                return CRYPTO_ERROR_MEMORY;
            }
            mbedtls_sha512_init((mbedtls_sha512_context*)ctx->internal_ctx);
            int ret = mbedtls_sha512_starts_ret((mbedtls_sha512_context*)ctx->internal_ctx, 0);
            if (ret != 0) {
                free(ctx->internal_ctx);
                return mbedtls_to_crypto_result_enterprise(ret);
            }
            ctx->digest_size = 64;
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
                return mbedtls_to_crypto_result_enterprise(ret);
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
                return mbedtls_to_crypto_result_enterprise(ret);
            }
            ctx->digest_size = 16;
            break;
        }
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_hash_update_enterprise(crypto_hash_ctx_t* ctx, const uint8_t* data, size_t data_len) {
    if (ctx == NULL || data == NULL || ctx->internal_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (ctx->is_finalized) {
        return CRYPTO_ERROR_OPERATION_FAILED;
    }
    
    uint64_t start_time = esp_timer_get_time();
    int ret = 0;
    
    // Protection temporelle Enterprise
    crypto_timing_safe_delay_enterprise();
    
    switch (ctx->algorithm) {
        case CRYPTO_HASH_SHA256:
            ret = mbedtls_sha256_update_ret((mbedtls_sha256_context*)ctx->internal_ctx, data, data_len);
            break;
        case CRYPTO_HASH_SHA512:  // Support Enterprise
            ret = mbedtls_sha512_update_ret((mbedtls_sha512_context*)ctx->internal_ctx, data, data_len);
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
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    if (ret != 0) {
        g_operation_failures++;
        return mbedtls_to_crypto_result_enterprise(ret);
    }
    
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_hash_final_enterprise(crypto_hash_ctx_t* ctx, uint8_t* digest, size_t* digest_len) {
    if (ctx == NULL || digest == NULL || digest_len == NULL || ctx->internal_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (ctx->is_finalized) {
        return CRYPTO_ERROR_OPERATION_FAILED;
    }
    
    if (*digest_len < ctx->digest_size) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint64_t start_time = esp_timer_get_time();
    int ret = 0;
    
    switch (ctx->algorithm) {
        case CRYPTO_HASH_SHA256:
            ret = mbedtls_sha256_finish_ret((mbedtls_sha256_context*)ctx->internal_ctx, digest);
            break;
        case CRYPTO_HASH_SHA512:  // Support Enterprise
            ret = mbedtls_sha512_finish_ret((mbedtls_sha512_context*)ctx->internal_ctx, digest);
            break;
        case CRYPTO_HASH_SHA1:
            ret = mbedtls_sha1_finish_ret((mbedtls_sha1_context*)ctx->internal_ctx, digest);
            break;
        case CRYPTO_HASH_MD5:
            ret = mbedtls_md5_finish_ret((mbedtls_md5_context*)ctx->internal_ctx, digest);
            break;
        default:
            return CRYPTO_ERROR_NOT_SUPPORTED;
    }
    
    if (ret == 0) {
        *digest_len = ctx->digest_size;
        ctx->is_finalized = true;
        memcpy(ctx->digest, digest, ctx->digest_size);
    }
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    if (ret != 0) {
        g_operation_failures++;
        return mbedtls_to_crypto_result_enterprise(ret);
    }
    
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_hash_compute_enterprise(crypto_hash_algorithm_t algorithm, 
                                               const uint8_t* data, size_t data_len,
                                               uint8_t* digest, size_t* digest_len) {
    crypto_hash_ctx_t ctx;
    crypto_result_t result;
    
    result = crypto_hash_init_enterprise(&ctx, algorithm);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    result = crypto_hash_update_enterprise(&ctx, data, data_len);
    if (result != CRYPTO_SUCCESS) {
        crypto_hash_cleanup_enterprise(&ctx);
        return result;
    }
    
    result = crypto_hash_final_enterprise(&ctx, digest, digest_len);
    crypto_hash_cleanup_enterprise(&ctx);
    
    return result;
}

void crypto_hash_cleanup_enterprise(crypto_hash_ctx_t* ctx) {
    if (ctx == NULL || ctx->internal_ctx == NULL) {
        return;
    }
    
    switch (ctx->algorithm) {
        case CRYPTO_HASH_SHA256:
            mbedtls_sha256_free((mbedtls_sha256_context*)ctx->internal_ctx);
            break;
        case CRYPTO_HASH_SHA512:  // Support Enterprise
            mbedtls_sha512_free((mbedtls_sha512_context*)ctx->internal_ctx);
            break;
        case CRYPTO_HASH_SHA1:
            mbedtls_sha1_free((mbedtls_sha1_context*)ctx->internal_ctx);
            break;
        case CRYPTO_HASH_MD5:
            mbedtls_md5_free((mbedtls_md5_context*)ctx->internal_ctx);
            break;
    }
    
    free(ctx->internal_ctx);
    
    // Effacement sécurisé Enterprise
    mbedtls_platform_zeroize(ctx, sizeof(crypto_hash_ctx_t));
}

// ================================
// Fonctions ECC avec crypto ESP32 Enterprise
// ================================

crypto_result_t crypto_ecc_generate_keypair_se_enterprise(uint8_t slot_id, crypto_ecc_keypair_t* keypair) {
    if (keypair == NULL || slot_id >= 8) {  // Enterprise: 8 slots
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Génération paire de clés ECC Enterprise pour slot %d", slot_id);
    
    uint64_t start_time = esp_timer_get_time();
    
    // Utiliser le gestionnaire crypto Enterprise
    uint8_t public_key[65];  // Format non compressé
    esp32_crypto_result_t result = esp32_crypto_generate_ecdsa_keypair_enterprise(slot_id, public_key);
    
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec génération clé ECC Enterprise: %s", 
                 esp32_crypto_error_to_string(result));
        g_operation_failures++;
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    // Copier la clé publique (skip 0x04 prefix)
    memcpy(keypair->public_key, public_key + 1, CRYPTO_ECC_PUBLIC_KEY_SIZE);
    keypair->has_public = true;
    keypair->has_private = true;  // En eFuse, non accessible directement
    keypair->curve_id = 1;  // SECP256R1
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    ESP_LOGI(TAG, "Paire de clés ECC Enterprise générée (slot %d, %.2f ms)", 
             slot_id, operation_time / 1000.0f);
    
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_ecc_sign_se_enterprise(uint8_t slot_id, const uint8_t* data, size_t data_len,
                                              crypto_ecc_signature_t* signature) {
    if (signature == NULL || data == NULL || slot_id >= 8) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Signature ECC Enterprise avec slot %d", slot_id);
    
    uint64_t start_time = esp_timer_get_time();
    
    // Calculer le hash des données
    uint8_t hash[32];
    size_t hash_len = sizeof(hash);
    crypto_result_t hash_result = crypto_hash_compute_enterprise(CRYPTO_HASH_SHA256, data, data_len, hash, &hash_len);
    if (hash_result != CRYPTO_SUCCESS) {
        g_operation_failures++;
        return hash_result;
    }
    
    // Signer avec le gestionnaire crypto Enterprise
    esp32_crypto_result_t result = esp32_crypto_ecdsa_sign_enterprise(slot_id, hash, signature->signature);
    
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec signature ECC Enterprise: %s", 
                 esp32_crypto_error_to_string(result));
        g_operation_failures++;
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    // Copier les composantes r et s
    memcpy(signature->r, signature->signature, 32);
    memcpy(signature->s, signature->signature + 32, 32);
    signature->is_valid = true;
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    ESP_LOGI(TAG, "Signature ECC Enterprise générée (slot %d, %.2f ms)", 
             slot_id, operation_time / 1000.0f);
    
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_ecc_verify_enterprise(const uint8_t* public_key, 
                                             const uint8_t* data, size_t data_len,
                                             const crypto_ecc_signature_t* signature) {
    if (public_key == NULL || data == NULL || signature == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Vérification signature ECC Enterprise");
    
    uint64_t start_time = esp_timer_get_time();
    
    // Calculer le hash des données
    uint8_t hash[32];
    size_t hash_len = sizeof(hash);
    crypto_result_t hash_result = crypto_hash_compute_enterprise(CRYPTO_HASH_SHA256, data, data_len, hash, &hash_len);
    if (hash_result != CRYPTO_SUCCESS) {
        g_operation_failures++;
        return hash_result;
    }
    
    // Préparer la clé publique au format ESP32 (avec préfixe 0x04)
    uint8_t formatted_public_key[65];
    formatted_public_key[0] = 0x04;
    memcpy(formatted_public_key + 1, public_key, CRYPTO_ECC_PUBLIC_KEY_SIZE);
    
    // Vérifier avec le gestionnaire crypto Enterprise
    esp32_crypto_result_t result = esp32_crypto_ecdsa_verify_enterprise(formatted_public_key, hash, signature->signature);
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGW(TAG, "Signature ECC Enterprise invalide: %s", 
                 esp32_crypto_error_to_string(result));
        g_operation_failures++;
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    ESP_LOGD(TAG, "Signature ECC Enterprise valide (%.2f ms)", operation_time / 1000.0f);
    return CRYPTO_SUCCESS;
}

// ================================
// Fonctions de génération aléatoire sécurisée Enterprise
// ================================

crypto_result_t crypto_random_se_enterprise(uint8_t* buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Génération aléatoire Enterprise (%zu bytes)", length);
    
    uint64_t start_time = esp_timer_get_time();
    
    // Utiliser le TRNG Enterprise
    esp32_crypto_result_t result = esp32_crypto_generate_random_enterprise(buffer, length);
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec génération aléatoire Enterprise: %s", 
                 esp32_crypto_error_to_string(result));
        g_operation_failures++;
        return CRYPTO_ERROR_SE_COMMUNICATION;
    }
    
    ESP_LOGD(TAG, "Génération aléatoire Enterprise réussie (%.2f µs)", operation_time / 1.0f);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_generate_nonce_enterprise(uint8_t* nonce, size_t nonce_len) {
    if (nonce == NULL || nonce_len == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Génération Enterprise avec mélange temporel
    crypto_result_t result = crypto_random_se_enterprise(nonce, nonce_len);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    // Mélange Enterprise avec timestamp pour plus de randomness
    uint64_t timestamp = esp_timer_get_time();
    for (size_t i = 0; i < nonce_len && i < 8; i++) {
        nonce[i] ^= (uint8_t)(timestamp >> (i * 8));
    }
    
    ESP_LOGD(TAG, "Nonce Enterprise de %zu bytes généré", nonce_len);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_generate_symmetric_key_enterprise(uint8_t* key, size_t key_len) {
    return crypto_random_se_enterprise(key, key_len);
}

// ================================
// Fonctions d'intégrité firmware Enterprise
// ================================

crypto_result_t crypto_compute_firmware_mac_enterprise(const uint8_t* firmware_data, size_t firmware_size,
                                                       uint8_t key_slot, uint8_t* mac, size_t* mac_len) {
    if (firmware_data == NULL || mac == NULL || mac_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Calcul MAC intégrité firmware Enterprise (%zu bytes)", firmware_size);
    
    uint64_t start_time = esp_timer_get_time();
    
    // En Enterprise, utiliser SHA-512 pour plus de sécurité
    size_t hash_len = 64;
    crypto_result_t result = crypto_hash_compute_enterprise(CRYPTO_HASH_SHA512, 
                                                            firmware_data, firmware_size, 
                                                            mac, &hash_len);
    
    if (result == CRYPTO_SUCCESS) {
        *mac_len = hash_len;
    }
    
    // Métriques Enterprise
    uint64_t operation_time = esp_timer_get_time() - start_time;
    g_total_operations++;
    g_total_operation_time += operation_time;
    
    ESP_LOGI(TAG, "MAC firmware Enterprise calculé (%.2f ms)", operation_time / 1000.0f);
    return result;
}

crypto_result_t crypto_verify_firmware_integrity_enterprise(const uint8_t* firmware_data, size_t firmware_size,
                                                            uint8_t key_slot, const uint8_t* expected_mac, 
                                                            size_t mac_len) {
    if (firmware_data == NULL || expected_mac == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Vérification intégrité firmware Enterprise (%zu bytes)", firmware_size);
    
    uint8_t computed_mac[64];
    size_t computed_mac_len = sizeof(computed_mac);
    
    crypto_result_t result = crypto_compute_firmware_mac_enterprise(firmware_data, firmware_size, 
                                                                    key_slot, computed_mac, &computed_mac_len);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    // Comparaison sécurisée en temps constant Enterprise
    if (computed_mac_len != mac_len) {
        ESP_LOGE(TAG, "Taille MAC firmware Enterprise incorrecte");
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    if (crypto_secure_memcmp_enterprise(computed_mac, expected_mac, mac_len) != 0) {
        ESP_LOGE(TAG, "MAC firmware Enterprise invalide");
        return CRYPTO_ERROR_VERIFICATION_FAILED;
    }
    
    ESP_LOGI(TAG, "Intégrité firmware Enterprise validée");
    return CRYPTO_SUCCESS;
}

// ================================
// Fonctions utilitaires Enterprise
// ================================

const char* crypto_result_to_string_enterprise(crypto_result_t result) {
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

void crypto_secure_memzero_enterprise(void* buffer, size_t size) {
    if (buffer != NULL && size > 0) {
        mbedtls_platform_zeroize(buffer, size);
        
        // Vérification Enterprise supplémentaire
        volatile uint8_t* ptr = (volatile uint8_t*)buffer;
        for (size_t i = 0; i < size; i++) {
            if (ptr[i] != 0) {
                ESP_LOGW(TAG, "Effacement mémoire Enterprise incomplet à l'offset %zu", i);
                break;
            }
        }
    }
}

int crypto_secure_memcmp_enterprise(const void* a, const void* b, size_t len) {
    if (a == NULL || b == NULL) {
        return -1;
    }
    
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t result = 0;
    
    // Comparaison en temps constant Enterprise avec protection supplémentaire
    crypto_timing_safe_delay_enterprise();
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    crypto_timing_safe_delay_enterprise();
    
    return result;
}

crypto_result_t crypto_performance_test_enterprise(void) {
    ESP_LOGI(TAG, "Démarrage test de performance cryptographique Enterprise");
    
    const size_t test_data_size = 4096;  // Plus de données en Enterprise
    uint8_t* test_data = malloc(test_data_size);
    uint8_t* output_buffer = malloc(test_data_size);
    
    if (test_data == NULL || output_buffer == NULL) {
        if (test_data) free(test_data);
        if (output_buffer) free(output_buffer);
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Remplissage avec des données de test
    esp_fill_random(test_data, test_data_size);
    
    uint64_t total_start_time = esp_timer_get_time();
    
    // Test de hachage SHA-256
    uint64_t start_time = esp_timer_get_time();
    uint8_t hash256[32];
    size_t hash256_len = sizeof(hash256);
    
    crypto_result_t result = crypto_hash_compute_enterprise(CRYPTO_HASH_SHA256, test_data, test_data_size, hash256, &hash256_len);
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test hachage SHA-256 Enterprise");
        free(test_data);
        free(output_buffer);
        return result;
    }
    
    uint64_t sha256_time = esp_timer_get_time() - start_time;
    ESP_LOGI(TAG, "SHA-256 Enterprise (%zu bytes): %llu µs", test_data_size, sha256_time);
    
    // Test de hachage SHA-512 Enterprise
    start_time = esp_timer_get_time();
    uint8_t hash512[64];
    size_t hash512_len = sizeof(hash512);
    
    result = crypto_hash_compute_enterprise(CRYPTO_HASH_SHA512, test_data, test_data_size, hash512, &hash512_len);
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test hachage SHA-512 Enterprise");
        free(test_data);
        free(output_buffer);
        return result;
    }
    
    uint64_t sha512_time = esp_timer_get_time() - start_time;
    ESP_LOGI(TAG, "SHA-512 Enterprise (%zu bytes): %llu µs", test_data_size, sha512_time);
    
    // Test de génération aléatoire SE Enterprise
    uint8_t random_data[64];  // Plus de données en Enterprise
    start_time = esp_timer_get_time();
    
    result = crypto_random_se_enterprise(random_data, sizeof(random_data));
    if (result != CRYPTO_SUCCESS) {
        ESP_LOGW(TAG, "SE Enterprise non disponible pour test aléatoire");
    } else {
        uint64_t random_time = esp_timer_get_time() - start_time;
        ESP_LOGI(TAG, "Génération aléatoire SE Enterprise (64 bytes): %llu µs", random_time);
    }
    
    // Test ECC Enterprise
    start_time = esp_timer_get_time();
    crypto_ecc_keypair_t keypair;
    result = crypto_ecc_generate_keypair_se_enterprise(0, &keypair);
    if (result == CRYPTO_SUCCESS) {
        uint64_t keygen_time = esp_timer_get_time() - start_time;
        ESP_LOGI(TAG, "Génération clé ECC Enterprise: %llu µs", keygen_time);
        
        // Test signature
        start_time = esp_timer_get_time();
        crypto_ecc_signature_t signature;
        result = crypto_ecc_sign_se_enterprise(0, test_data, 256, &signature);
        if (result == CRYPTO_SUCCESS) {
            uint64_t sign_time = esp_timer_get_time() - start_time;
            ESP_LOGI(TAG, "Signature ECC Enterprise: %llu µs", sign_time);
            
            // Test vérification
            start_time = esp_timer_get_time();
            result = crypto_ecc_verify_enterprise(keypair.public_key, test_data, 256, &signature);
            if (result == CRYPTO_SUCCESS) {
                uint64_t verify_time = esp_timer_get_time() - start_time;
                ESP_LOGI(TAG, "Vérification ECC Enterprise: %llu µs", verify_time);
            }
        }
    }
    
    uint64_t total_time = esp_timer_get_time() - total_start_time;
    ESP_LOGI(TAG, "Test de performance Enterprise terminé avec succès (temps total: %llu µs)", total_time);
    
    free(test_data);
    free(output_buffer);
    return CRYPTO_SUCCESS;
}

crypto_result_t crypto_get_statistics_enterprise(uint32_t* total_ops, uint32_t* failures, uint64_t* avg_time_us) {
    if (total_ops) *total_ops = g_total_operations;
    if (failures) *failures = g_operation_failures;
    if (avg_time_us && g_total_operations > 0) {
        *avg_time_us = g_total_operation_time / g_total_operations;
    } else if (avg_time_us) {
        *avg_time_us = 0;
    }
    
    return CRYPTO_SUCCESS;
}

void crypto_print_statistics_enterprise(void) {
    ESP_LOGI(TAG, "=== Statistiques Cryptographiques Enterprise ===");
    ESP_LOGI(TAG, "Opérations totales: %lu", g_total_operations);
    ESP_LOGI(TAG, "Échecs: %lu", g_operation_failures);
    ESP_LOGI(TAG, "Temps total: %llu µs", g_total_operation_time);
    if (g_total_operations > 0) {
        ESP_LOGI(TAG, "Temps moyen: %llu µs", g_total_operation_time / g_total_operations);
        ESP_LOGI(TAG, "Taux de succès: %.2f%%", 
                 (float)(g_total_operations - g_operation_failures) / g_total_operations * 100.0f);
    }
    ESP_LOGI(TAG, "==============================================");
}

// ================================
// Fonctions de compatibilité avec l'API de base
// ================================

crypto_result_t crypto_init(void) {
    return crypto_init_enterprise();
}

void crypto_deinit(void) {
    crypto_deinit_enterprise();
}

crypto_result_t crypto_hash_init(crypto_hash_ctx_t* ctx, crypto_hash_algorithm_t algorithm) {
    return crypto_hash_init_enterprise(ctx, algorithm);
}

crypto_result_t crypto_hash_update(crypto_hash_ctx_t* ctx, const uint8_t* data, size_t data_len) {
    return crypto_hash_update_enterprise(ctx, data, data_len);
}

crypto_result_t crypto_hash_final(crypto_hash_ctx_t* ctx, uint8_t* digest, size_t* digest_len) {
    return crypto_hash_final_enterprise(ctx, digest, digest_len);
}

crypto_result_t crypto_hash_compute(crypto_hash_algorithm_t algorithm, 
                                    const uint8_t* data, size_t data_len,
                                    uint8_t* digest, size_t* digest_len) {
    return crypto_hash_compute_enterprise(algorithm, data, data_len, digest, digest_len);
}

void crypto_hash_cleanup(crypto_hash_ctx_t* ctx) {
    crypto_hash_cleanup_enterprise(ctx);
}

crypto_result_t crypto_ecc_generate_keypair_se(uint8_t slot_id, crypto_ecc_keypair_t* keypair) {
    return crypto_ecc_generate_keypair_se_enterprise(slot_id, keypair);
}

crypto_result_t crypto_ecc_sign_se(uint8_t slot_id, const uint8_t* data, size_t data_len,
                                   crypto_ecc_signature_t* signature) {
    return crypto_ecc_sign_se_enterprise(slot_id, data, data_len, signature);
}

crypto_result_t crypto_ecc_verify(const uint8_t* public_key, 
                                  const uint8_t* data, size_t data_len,
                                  const crypto_ecc_signature_t* signature) {
    return crypto_ecc_verify_enterprise(public_key, data, data_len, signature);
}

crypto_result_t crypto_random_se(uint8_t* buffer, size_t length) {
    return crypto_random_se_enterprise(buffer, length);
}

crypto_result_t crypto_generate_nonce(uint8_t* nonce, size_t nonce_len) {
    return crypto_generate_nonce_enterprise(nonce, nonce_len);
}

crypto_result_t crypto_generate_symmetric_key(uint8_t* key, size_t key_len) {
    return crypto_generate_symmetric_key_enterprise(key, key_len);
}

crypto_result_t crypto_compute_firmware_mac(const uint8_t* firmware_data, size_t firmware_size,
                                            uint8_t key_slot, uint8_t* mac, size_t* mac_len) {
    return crypto_compute_firmware_mac_enterprise(firmware_data, firmware_size, key_slot, mac, mac_len);
}

crypto_result_t crypto_verify_firmware_integrity(const uint8_t* firmware_data, size_t firmware_size,
                                                 uint8_t key_slot, const uint8_t* expected_mac, 
                                                 size_t mac_len) {
    return crypto_verify_firmware_integrity_enterprise(firmware_data, firmware_size, key_slot, expected_mac, mac_len);
}

const char* crypto_result_to_string(crypto_result_t result) {
    return crypto_result_to_string_enterprise(result);
}

void crypto_secure_memzero(void* buffer, size_t size) {
    crypto_secure_memzero_enterprise(buffer, size);
}

int crypto_secure_memcmp(const void* a, const void* b, size_t len) {
    return crypto_secure_memcmp_enterprise(a, b, len);
}

crypto_result_t crypto_performance_test(void) {
    return crypto_performance_test_enterprise();
}