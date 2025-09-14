/**
 * @file crypto_operations_basic.c
 * @brief Opérations cryptographiques de base pour SecureIoT-VIF Community Edition
 * 
 * Version simplifiée utilisant uniquement le crypto software, sans HSM ni eFuse.
 * Idéale pour l'apprentissage et le prototypage.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "crypto_operations_basic.h"

static const char *TAG = "CRYPTO_BASIC_COMMUNITY";

// Contextes crypto globaux (software uniquement)
static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;
static mbedtls_ecdsa_context ecdsa_ctx;
static bool crypto_initialized = false;

/**
 * @brief Initialise le système cryptographique de base
 */
esp_err_t crypto_operations_basic_init(void) {
    esp_err_t ret = ESP_OK;
    
    if (crypto_initialized) {
        ESP_LOGW(TAG, "Crypto de base déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "🔐 Initialisation crypto de base Community Edition");
    
    // Initialisation entropy (software uniquement)
    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    mbedtls_ecdsa_init(&ecdsa_ctx);
    
    // Seed du générateur aléatoire
    const char *pers = "secureiot_vif_community";
    int mbedtls_ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, 
                                           &entropy_ctx, (const unsigned char *)pers, strlen(pers));
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec seed générateur aléatoire: -0x%04x", -mbedtls_ret);
        return ESP_FAIL;
    }
    
    crypto_initialized = true;
    ESP_LOGI(TAG, "✅ Crypto de base Community initialisé");
    ESP_LOGI(TAG, "💡 Version éducative - Crypto software seulement");
    
    return ret;
}

/**
 * @brief Deinitialise le système cryptographique
 */
esp_err_t crypto_operations_basic_deinit(void) {
    if (!crypto_initialized) {
        return ESP_OK;
    }
    
    mbedtls_ecdsa_free(&ecdsa_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
    mbedtls_entropy_free(&entropy_ctx);
    
    crypto_initialized = false;
    ESP_LOGI(TAG, "🔓 Crypto de base Community déinitialisé");
    
    return ESP_OK;
}

/**
 * @brief Génère des données aléatoires (software uniquement)
 */
esp_err_t crypto_basic_generate_random(uint8_t *buffer, size_t length) {
    if (!crypto_initialized) {
        ESP_LOGE(TAG, "❌ Crypto non initialisé");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (buffer == NULL || length == 0) {
        ESP_LOGE(TAG, "❌ Paramètres invalides pour génération aléatoire");
        return ESP_ERR_INVALID_ARG;
    }
    
    int mbedtls_ret = mbedtls_ctr_drbg_random(&ctr_drbg_ctx, buffer, length);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec génération aléatoire: -0x%04x", -mbedtls_ret);
        return ESP_FAIL;
    }
    
    ESP_LOGD(TAG, "🎲 Généré %d bytes aléatoires (software)", length);
    return ESP_OK;
}

/**
 * @brief Calcule un hash SHA-256 (software)
 */
esp_err_t crypto_basic_sha256(const uint8_t *input, size_t input_len, uint8_t *output) {
    if (input == NULL || output == NULL || input_len == 0) {
        ESP_LOGE(TAG, "❌ Paramètres invalides pour SHA-256");
        return ESP_ERR_INVALID_ARG;
    }
    
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    
    int mbedtls_ret = mbedtls_sha256_starts_ret(&sha256_ctx, 0); // SHA-256
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec initialisation SHA-256: -0x%04x", -mbedtls_ret);
        mbedtls_sha256_free(&sha256_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_ret = mbedtls_sha256_update_ret(&sha256_ctx, input, input_len);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec update SHA-256: -0x%04x", -mbedtls_ret);
        mbedtls_sha256_free(&sha256_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_ret = mbedtls_sha256_finish_ret(&sha256_ctx, output);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec finalisation SHA-256: -0x%04x", -mbedtls_ret);
        mbedtls_sha256_free(&sha256_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_sha256_free(&sha256_ctx);
    ESP_LOGD(TAG, "🔒 SHA-256 calculé (software): %d bytes", input_len);
    
    return ESP_OK;
}

/**
 * @brief Chiffre des données avec AES-128-GCM (version simplifiée)
 */
esp_err_t crypto_basic_aes_encrypt(const uint8_t *key, const uint8_t *iv, 
                                  const uint8_t *input, size_t input_len,
                                  uint8_t *output, uint8_t *tag) {
    if (key == NULL || iv == NULL || input == NULL || output == NULL || tag == NULL) {
        ESP_LOGE(TAG, "❌ Paramètres invalides pour AES encrypt");
        return ESP_ERR_INVALID_ARG;
    }
    
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    
    int mbedtls_ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128); // AES-128
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec configuration clé AES: -0x%04x", -mbedtls_ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, input_len,
                                           iv, 12, NULL, 0, input, output, 16, tag);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec chiffrement AES-GCM: -0x%04x", -mbedtls_ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_gcm_free(&gcm_ctx);
    ESP_LOGD(TAG, "🔐 AES-128-GCM encrypt réussi: %d bytes", input_len);
    
    return ESP_OK;
}

/**
 * @brief Déchiffre des données avec AES-128-GCM
 */
esp_err_t crypto_basic_aes_decrypt(const uint8_t *key, const uint8_t *iv,
                                  const uint8_t *input, size_t input_len,
                                  const uint8_t *tag, uint8_t *output) {
    if (key == NULL || iv == NULL || input == NULL || tag == NULL || output == NULL) {
        ESP_LOGE(TAG, "❌ Paramètres invalides pour AES decrypt");
        return ESP_ERR_INVALID_ARG;
    }
    
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    
    int mbedtls_ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128); // AES-128
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec configuration clé AES: -0x%04x", -mbedtls_ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, input_len, iv, 12, NULL, 0,
                                          tag, 16, input, output);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec déchiffrement AES-GCM: -0x%04x", -mbedtls_ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ESP_FAIL;
    }
    
    mbedtls_gcm_free(&gcm_ctx);
    ESP_LOGD(TAG, "🔓 AES-128-GCM decrypt réussi: %d bytes", input_len);
    
    return ESP_OK;
}

/**
 * @brief Génère une paire de clés ECDSA P-256 (software)
 */
esp_err_t crypto_basic_generate_ecdsa_keypair(crypto_basic_keypair_t *keypair) {
    if (!crypto_initialized) {
        ESP_LOGE(TAG, "❌ Crypto non initialisé");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (keypair == NULL) {
        ESP_LOGE(TAG, "❌ Paramètre keypair invalide");
        return ESP_ERR_INVALID_ARG;
    }
    
    mbedtls_ecdsa_context ecdsa_temp;
    mbedtls_ecdsa_init(&ecdsa_temp);
    
    // Générer paire de clés ECDSA P-256
    int mbedtls_ret = mbedtls_ecdsa_genkey(&ecdsa_temp, MBEDTLS_ECP_DP_SECP256R1,
                                          mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec génération clés ECDSA: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_temp);
        return ESP_FAIL;
    }
    
    // Exporter la clé publique
    size_t pub_len = 0;
    mbedtls_ret = mbedtls_ecp_point_write_binary(&ecdsa_temp.grp, &ecdsa_temp.Q,
                                                MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_len,
                                                keypair->public_key, sizeof(keypair->public_key));
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec export clé publique: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_temp);
        return ESP_FAIL;
    }
    keypair->public_key_len = pub_len;
    
    // Exporter la clé privée (attention: stockage en RAM non sécurisé)
    mbedtls_ret = mbedtls_mpi_write_binary(&ecdsa_temp.d, keypair->private_key, 32);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec export clé privée: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_temp);
        return ESP_FAIL;
    }
    keypair->private_key_len = 32;
    
    mbedtls_ecdsa_free(&ecdsa_temp);
    ESP_LOGI(TAG, "🔑 Paire de clés ECDSA P-256 générée (software)");
    ESP_LOGW(TAG, "⚠️  Clé privée stockée en RAM (non sécurisé - Community Edition)");
    
    return ESP_OK;
}

/**
 * @brief Signe un hash avec ECDSA (software)
 */
esp_err_t crypto_basic_ecdsa_sign(const crypto_basic_keypair_t *keypair,
                                 const uint8_t *hash, size_t hash_len,
                                 uint8_t *signature, size_t *signature_len) {
    if (!crypto_initialized) {
        ESP_LOGE(TAG, "❌ Crypto non initialisé");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (keypair == NULL || hash == NULL || signature == NULL || signature_len == NULL) {
        ESP_LOGE(TAG, "❌ Paramètres invalides pour signature ECDSA");
        return ESP_ERR_INVALID_ARG;
    }
    
    mbedtls_ecdsa_context ecdsa_sign;
    mbedtls_ecdsa_init(&ecdsa_sign);
    
    // Charger la clé privée
    int mbedtls_ret = mbedtls_ecp_group_load(&ecdsa_sign.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec chargement groupe ECP: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_sign);
        return ESP_FAIL;
    }
    
    mbedtls_ret = mbedtls_mpi_read_binary(&ecdsa_sign.d, keypair->private_key, keypair->private_key_len);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec chargement clé privée: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_sign);
        return ESP_FAIL;
    }
    
    // Effectuer la signature
    mbedtls_ret = mbedtls_ecdsa_write_signature(&ecdsa_sign, MBEDTLS_MD_SHA256,
                                               hash, hash_len, signature, signature_len,
                                               mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec signature ECDSA: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_sign);
        return ESP_FAIL;
    }
    
    mbedtls_ecdsa_free(&ecdsa_sign);
    ESP_LOGD(TAG, "✍️ Signature ECDSA créée: %d bytes", *signature_len);
    
    return ESP_OK;
}

/**
 * @brief Vérifie une signature ECDSA (software)
 */
esp_err_t crypto_basic_ecdsa_verify(const crypto_basic_keypair_t *keypair,
                                   const uint8_t *hash, size_t hash_len,
                                   const uint8_t *signature, size_t signature_len) {
    if (!crypto_initialized) {
        ESP_LOGE(TAG, "❌ Crypto non initialisé");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (keypair == NULL || hash == NULL || signature == NULL) {
        ESP_LOGE(TAG, "❌ Paramètres invalides pour vérification ECDSA");
        return ESP_ERR_INVALID_ARG;
    }
    
    mbedtls_ecdsa_context ecdsa_verify;
    mbedtls_ecdsa_init(&ecdsa_verify);
    
    // Charger la clé publique
    int mbedtls_ret = mbedtls_ecp_group_load(&ecdsa_verify.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec chargement groupe ECP: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_verify);
        return ESP_FAIL;
    }
    
    mbedtls_ret = mbedtls_ecp_point_read_binary(&ecdsa_verify.grp, &ecdsa_verify.Q,
                                               keypair->public_key, keypair->public_key_len);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec chargement clé publique: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_verify);
        return ESP_FAIL;
    }
    
    // Vérifier la signature
    mbedtls_ret = mbedtls_ecdsa_read_signature(&ecdsa_verify, hash, hash_len,
                                              signature, signature_len);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "❌ Échec vérification signature ECDSA: -0x%04x", -mbedtls_ret);
        mbedtls_ecdsa_free(&ecdsa_verify);
        return ESP_FAIL;
    }
    
    mbedtls_ecdsa_free(&ecdsa_verify);
    ESP_LOGD(TAG, "✅ Signature ECDSA vérifiée avec succès");
    
    return ESP_OK;
}

/**
 * @brief Auto-test du système cryptographique de base
 */
esp_err_t crypto_basic_self_test(void) {
    ESP_LOGI(TAG, "🧪 Auto-test crypto de base Community Edition...");
    
    esp_err_t ret = ESP_OK;
    uint8_t test_data[] = "SecureIoT-VIF Community Test";
    uint8_t hash[32];
    uint8_t random_data[16];
    crypto_basic_keypair_t test_keypair;
    uint8_t signature[72]; // Taille max signature ECDSA DER
    size_t signature_len = sizeof(signature);
    
    // Test 1: Génération aléatoire
    ret = crypto_basic_generate_random(random_data, sizeof(random_data));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Auto-test: Échec génération aléatoire");
        return ret;
    }
    ESP_LOGI(TAG, "✅ Test génération aléatoire: OK");
    
    // Test 2: Hash SHA-256
    ret = crypto_basic_sha256(test_data, sizeof(test_data)-1, hash);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Auto-test: Échec SHA-256");
        return ret;
    }
    ESP_LOGI(TAG, "✅ Test SHA-256: OK");
    
    // Test 3: Génération paire de clés ECDSA
    ret = crypto_basic_generate_ecdsa_keypair(&test_keypair);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Auto-test: Échec génération clés ECDSA");
        return ret;
    }
    ESP_LOGI(TAG, "✅ Test génération clés ECDSA: OK");
    
    // Test 4: Signature ECDSA
    ret = crypto_basic_ecdsa_sign(&test_keypair, hash, sizeof(hash), signature, &signature_len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Auto-test: Échec signature ECDSA");
        return ret;
    }
    ESP_LOGI(TAG, "✅ Test signature ECDSA: OK");
    
    // Test 5: Vérification signature ECDSA
    ret = crypto_basic_ecdsa_verify(&test_keypair, hash, sizeof(hash), signature, signature_len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "❌ Auto-test: Échec vérification ECDSA");
        return ret;
    }
    ESP_LOGI(TAG, "✅ Test vérification ECDSA: OK");
    
    ESP_LOGI(TAG, "🎉 Auto-test crypto de base réussi - Community Edition opérationnelle");
    ESP_LOGI(TAG, "💡 Toutes opérations en software - Idéal pour apprentissage");
    
    return ESP_OK;
}

/**
 * @brief Affiche les informations du système crypto Community
 */
void crypto_basic_print_info(void) {
    ESP_LOGI(TAG, "📋 === Informations Crypto Community Edition ===");
    ESP_LOGI(TAG, "Édition: Community (Éducative & Recherche)");
    ESP_LOGI(TAG, "Type: Software uniquement (mbedTLS)");
    ESP_LOGI(TAG, "Algorithmes supportés:");
    ESP_LOGI(TAG, "  🔒 Hash: SHA-256");
    ESP_LOGI(TAG, "  🔐 Chiffrement: AES-128-GCM");
    ESP_LOGI(TAG, "  ✍️  Signature: ECDSA P-256");
    ESP_LOGI(TAG, "  🎲 Aléatoire: Software entropy");
    ESP_LOGI(TAG, "Limitations Community:");
    ESP_LOGI(TAG, "  ❌ Pas de HSM hardware");
    ESP_LOGI(TAG, "  ❌ Pas de stockage eFuse");
    ESP_LOGI(TAG, "  ❌ Pas d'accélération hardware");
    ESP_LOGI(TAG, "  ❌ Clés stockées en RAM");
    ESP_LOGI(TAG, "🎓 Idéal pour apprentissage et prototypage!");
    ESP_LOGI(TAG, "===========================================");
}