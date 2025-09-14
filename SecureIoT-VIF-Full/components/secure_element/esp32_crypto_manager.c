/**
 * @file esp32_crypto_manager.c
 * @brief Implémentation du gestionnaire cryptographique ESP32 intégré
 * 
 * @author Framework SecureIoT-VIF
 * @version 2.0.0 - ESP32 Crypto Intégré
 * @date 2025
 */

#include "esp32_crypto_manager.h"
#include "app_config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_secure_boot.h"
#include "esp_flash_encrypt.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

static const char *TAG = "ESP32_CRYPTO";

// ================================
// Variables globales statiques
// ================================

static bool g_crypto_initialized = false;
static esp32_crypto_config_t g_crypto_config;
static esp32_crypto_info_t g_crypto_info;
static uint32_t g_operation_counter = 0;
static uint32_t g_error_counter = 0;

// Contextes crypto mbedTLS
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static bool g_entropy_initialized = false;

// Clés stockées en mémoire (publiques uniquement)
static esp32_key_info_t g_key_slots[4];
static bool g_keys_initialized = false;

// ================================
// Fonctions utilitaires privées
// ================================

/**
 * @brief Initialise le générateur d'entropie
 */
static esp_err_t init_entropy_context(void) {
    if (g_entropy_initialized) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Initialisation contexte entropie...");
    
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    
    const char *personalization = "SecureIoT-VIF-ESP32";
    int ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char *)personalization,
                                    strlen(personalization));
    
    if (ret != 0) {
        ESP_LOGE(TAG, "Échec initialisation DRBG: -0x%04x", -ret);
        return ESP_FAIL;
    }
    
    g_entropy_initialized = true;
    ESP_LOGI(TAG, "Contexte entropie initialisé avec succès");
    return ESP_OK;
}

/**
 * @brief Nettoie le contexte d'entropie
 */
static void cleanup_entropy_context(void) {
    if (g_entropy_initialized) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
        g_entropy_initialized = false;
        ESP_LOGI(TAG, "Contexte entropie nettoyé");
    }
}

/**
 * @brief Initialise les informations du dispositif
 */
static esp_err_t init_device_info(void) {
    ESP_LOGI(TAG, "Initialisation informations dispositif...");
    
    // Obtenir l'ID unique (MAC address)
    esp_err_t ret = esp_read_mac(g_crypto_info.device_id, ESP_MAC_WIFI_STA);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Échec lecture MAC: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Obtenir la révision du chip
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    g_crypto_info.chip_revision = chip_info.revision;
    
    // Vérifier l'état du Secure Boot
    g_crypto_info.secure_boot_enabled = esp_secure_boot_enabled();
    
    // Vérifier l'état du chiffrement flash
    g_crypto_info.flash_encryption_enabled = esp_flash_encryption_enabled();
    
    // Initialiser les compteurs
    g_crypto_info.error_count = 0;
    g_crypto_info.operation_count = 0;
    g_crypto_info.last_operation_time = esp_timer_get_time();
    g_crypto_info.available_entropy = ESP32_TRNG_ENTROPY_THRESHOLD;
    g_crypto_info.state = ESP32_CRYPTO_STATE_CONFIGURED;
    
    ESP_LOGI(TAG, "Device ID: %02X:%02X:%02X:%02X:%02X:%02X",
             g_crypto_info.device_id[0], g_crypto_info.device_id[1], g_crypto_info.device_id[2],
             g_crypto_info.device_id[3], g_crypto_info.device_id[4], g_crypto_info.device_id[5]);
    ESP_LOGI(TAG, "Chip Revision: %d", g_crypto_info.chip_revision);
    ESP_LOGI(TAG, "Secure Boot: %s", g_crypto_info.secure_boot_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "Flash Encryption: %s", g_crypto_info.flash_encryption_enabled ? "Activé" : "Désactivé");
    
    return ESP_OK;
}

/**
 * @brief Initialise les slots de clés
 */
static esp_err_t init_key_slots(void) {
    ESP_LOGI(TAG, "Initialisation slots de clés...");
    
    for (int i = 0; i < 4; i++) {
        g_key_slots[i].key_id = i;
        g_key_slots[i].key_type = 0; // Non défini
        g_key_slots[i].key_size = 0;
        g_key_slots[i].is_in_efuse = false;
        g_key_slots[i].is_protected = false;
        g_key_slots[i].usage_count = 0;
        g_key_slots[i].efuse_block = i;
        memset(g_key_slots[i].key_data, 0, sizeof(g_key_slots[i].key_data));
    }
    
    g_keys_initialized = true;
    ESP_LOGI(TAG, "Slots de clés initialisés");
    return ESP_OK;
}

// ================================
// Fonctions publiques
// ================================

esp_err_t esp32_crypto_manager_init(const esp32_crypto_config_t* config) {
    if (g_crypto_initialized) {
        ESP_LOGW(TAG, "Gestionnaire crypto déjà initialisé");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "=== Initialisation Gestionnaire Crypto ESP32 ===");
    
    // Configuration par défaut si NULL
    if (config == NULL) {
        g_crypto_config.enable_secure_boot = ESP32_SECURE_BOOT_V2_ENABLED;
        g_crypto_config.enable_flash_encryption = ESP32_FLASH_ENCRYPTION_ENABLED;
        g_crypto_config.enable_hardware_random = true;
        g_crypto_config.enable_efuse_protection = ESP32_EFUSE_PROTECTION_ENABLED;
        g_crypto_config.entropy_source = 1;
        g_crypto_config.rsa_key_size = RSA_KEY_SIZE_BITS;
        g_crypto_config.enable_debug_mode = false;
        g_crypto_config.max_retries = 3;
    } else {
        memcpy(&g_crypto_config, config, sizeof(esp32_crypto_config_t));
    }
    
    ESP_LOGI(TAG, "Configuration:");
    ESP_LOGI(TAG, "  - Secure Boot: %s", g_crypto_config.enable_secure_boot ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "  - Flash Encryption: %s", g_crypto_config.enable_flash_encryption ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "  - Hardware Random: %s", g_crypto_config.enable_hardware_random ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "  - RSA Key Size: %d bits", g_crypto_config.rsa_key_size);
    
    // Initialiser NVS pour stockage sécurisé
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Initialiser le contexte d'entropie
    ret = init_entropy_context();
    if (ret != ESP_OK) {
        return ret;
    }
    
    // Initialiser les informations du dispositif
    ret = init_device_info();
    if (ret != ESP_OK) {
        cleanup_entropy_context();
        return ret;
    }
    
    // Initialiser les slots de clés
    ret = init_key_slots();
    if (ret != ESP_OK) {
        cleanup_entropy_context();
        return ret;
    }
    
    g_crypto_initialized = true;
    g_crypto_info.state = ESP32_CRYPTO_STATE_CONFIGURED;
    
    ESP_LOGI(TAG, "=== Gestionnaire Crypto ESP32 Initialisé avec Succès ===");
    return ESP_OK;
}

esp_err_t esp32_crypto_manager_deinit(void) {
    if (!g_crypto_initialized) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Dé-initialisation gestionnaire crypto ESP32...");
    
    // Nettoyer les contextes crypto
    cleanup_entropy_context();
    
    // Réinitialiser les états
    g_crypto_initialized = false;
    g_keys_initialized = false;
    g_crypto_info.state = ESP32_CRYPTO_STATE_UNINITIALIZED;
    
    ESP_LOGI(TAG, "Gestionnaire crypto ESP32 dé-initialisé");
    return ESP_OK;
}

esp32_crypto_result_t esp32_crypto_get_device_info(esp32_crypto_info_t* info) {
    if (!g_crypto_initialized || info == NULL) {
        return ESP32_CRYPTO_ERROR_NOT_INITIALIZED;
    }
    
    memcpy(info, &g_crypto_info, sizeof(esp32_crypto_info_t));
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_health_check(void) {
    if (!g_crypto_initialized) {
        return ESP32_CRYPTO_ERROR_NOT_INITIALIZED;
    }
    
    ESP_LOGD(TAG, "Vérification santé crypto ESP32...");
    
    // Test du générateur aléatoire
    uint8_t test_random[16];
    esp32_crypto_result_t result = esp32_crypto_generate_random(test_random, sizeof(test_random));
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test générateur aléatoire");
        g_crypto_info.error_count++;
        return ESP32_CRYPTO_ERROR_ENTROPY_FAILED;
    }
    
    // Test de hash SHA-256
    uint8_t test_data[] = "SecureIoT-VIF Test";
    uint8_t test_hash[32];
    result = esp32_crypto_sha256(test_data, strlen((char*)test_data), test_hash);
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec test SHA-256");
        g_crypto_info.error_count++;
        return ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
    }
    
    ESP_LOGI(TAG, "Vérification santé crypto réussie");
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_generate_ecdsa_keypair(uint8_t key_id, uint8_t* public_key) {
    if (!g_crypto_initialized || !g_entropy_initialized || key_id >= 4 || public_key == NULL) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Génération paire de clés ECDSA pour slot %d...", key_id);
    
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    
    esp32_crypto_result_t result = ESP32_CRYPTO_SUCCESS;
    
    do {
        // Initialiser la courbe P-256
        int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec chargement courbe P-256: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_KEY_GENERATION;
            break;
        }
        
        // Générer la clé privée
        ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &g_ctr_drbg);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec génération paire de clés: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_KEY_GENERATION;
            break;
        }
        
        // Exporter la clé publique (format non compressé)
        size_t olen;
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen, public_key, ESP32_PUBLIC_KEY_SIZE);
        if (ret != 0 || olen != 65) { // 1 + 32 + 32 bytes
            ESP_LOGE(TAG, "Échec export clé publique: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_KEY_GENERATION;
            break;
        }
        
        // Stocker les métadonnées de la clé (clé publique uniquement)
        g_key_slots[key_id].key_type = 1; // ECDSA
        g_key_slots[key_id].key_size = ESP32_PUBLIC_KEY_SIZE;
        memcpy(g_key_slots[key_id].key_data, public_key + 1, 64); // Skip first byte (0x04)
        g_key_slots[key_id].is_in_efuse = true; // Simulé
        g_key_slots[key_id].is_protected = true;
        g_key_slots[key_id].usage_count = 0;
        
        ESP_LOGI(TAG, "Paire de clés ECDSA générée pour slot %d", key_id);
        g_crypto_info.operation_count++;
        g_operation_counter++;
        
    } while (0);
    
    // Nettoyer (important: la clé privée ne doit pas rester en mémoire)
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    
    g_crypto_info.last_operation_time = esp_timer_get_time();
    return result;
}

esp32_crypto_result_t esp32_crypto_get_public_key(uint8_t key_id, uint8_t* public_key) {
    if (!g_crypto_initialized || key_id >= 4 || public_key == NULL) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (!g_key_slots[key_id].is_in_efuse || g_key_slots[key_id].key_type != 1) {
        ESP_LOGE(TAG, "Clé %d non disponible ou mauvais type", key_id);
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Format: 0x04 (uncompressed) + X (32 bytes) + Y (32 bytes)
    public_key[0] = 0x04;
    memcpy(public_key + 1, g_key_slots[key_id].key_data, 64);
    
    ESP_LOGD(TAG, "Clé publique récupérée pour slot %d", key_id);
    g_crypto_info.operation_count++;
    g_crypto_info.last_operation_time = esp_timer_get_time();
    
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_generate_random(uint8_t* random_bytes, size_t length) {
    if (!g_crypto_initialized || random_bytes == NULL || length == 0 || length > 1024) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Génération %zu bytes aléatoires...", length);
    
    if (g_crypto_config.enable_hardware_random) {
        // Utiliser le TRNG matériel ESP32
        esp_fill_random(random_bytes, length);
    } else {
        // Utiliser mbedTLS DRBG
        if (!g_entropy_initialized) {
            return ESP32_CRYPTO_ERROR_ENTROPY_FAILED;
        }
        
        int ret = mbedtls_ctr_drbg_random(&g_ctr_drbg, random_bytes, length);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec génération aléatoire: -0x%04x", -ret);
            g_crypto_info.error_count++;
            return ESP32_CRYPTO_ERROR_ENTROPY_FAILED;
        }
    }
    
    g_crypto_info.operation_count++;
    g_crypto_info.last_operation_time = esp_timer_get_time();
    
    ESP_LOGD(TAG, "Génération aléatoire réussie");
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_sha256(const uint8_t* data, size_t data_length, uint8_t* hash) {
    if (!g_crypto_initialized || data == NULL || hash == NULL || data_length == 0) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Calcul SHA-256 sur %zu bytes...", data_length);
    
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    
    esp32_crypto_result_t result = ESP32_CRYPTO_SUCCESS;
    
    do {
        int ret = mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256 (not SHA-224)
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec initialisation SHA-256: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        ret = mbedtls_sha256_update(&ctx, data, data_length);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec update SHA-256: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        ret = mbedtls_sha256_finish(&ctx, hash);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec finalisation SHA-256: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        ESP_LOGD(TAG, "SHA-256 calculé avec succès");
        g_crypto_info.operation_count++;
        
    } while (0);
    
    mbedtls_sha256_free(&ctx);
    g_crypto_info.last_operation_time = esp_timer_get_time();
    
    return result;
}

esp32_crypto_result_t esp32_crypto_ecdsa_sign(uint8_t key_id, const uint8_t* message_hash, uint8_t* signature) {
    if (!g_crypto_initialized || key_id >= 4 || message_hash == NULL || signature == NULL) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (!g_key_slots[key_id].is_in_efuse || g_key_slots[key_id].key_type != 1) {
        ESP_LOGE(TAG, "Clé %d non disponible pour signature", key_id);
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Signature ECDSA avec clé slot %d...", key_id);
    
    // Pour la simulation, nous générons une signature "factice" mais cohérente
    // En production, ceci utiliserait la clé privée stockée en eFuse
    
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_mpi r, s;
    
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    
    esp32_crypto_result_t result = ESP32_CRYPTO_SUCCESS;
    
    do {
        // Charger la courbe P-256
        int ret = mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        // Générer une clé temporaire pour la démo (en production: utiliser eFuse)
        ret = mbedtls_ecp_gen_keypair(&ecdsa_ctx.grp, &ecdsa_ctx.d, &ecdsa_ctx.Q,
                                      mbedtls_ctr_drbg_random, &g_ctr_drbg);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        // Signer le hash
        ret = mbedtls_ecdsa_sign(&ecdsa_ctx.grp, &r, &s, &ecdsa_ctx.d, message_hash, 32,
                                 mbedtls_ctr_drbg_random, &g_ctr_drbg);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec signature ECDSA: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        // Encoder la signature (r || s)
        ret = mbedtls_mpi_write_binary(&r, signature, 32);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        ret = mbedtls_mpi_write_binary(&s, signature + 32, 32);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        g_key_slots[key_id].usage_count++;
        g_crypto_info.operation_count++;
        ESP_LOGI(TAG, "Signature ECDSA générée avec succès");
        
    } while (0);
    
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    g_crypto_info.last_operation_time = esp_timer_get_time();
    return result;
}

esp32_crypto_result_t esp32_crypto_ecdsa_verify(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature) {
    if (!g_crypto_initialized || public_key == NULL || message_hash == NULL || signature == NULL) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGD(TAG, "Vérification signature ECDSA...");
    
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_mpi r, s;
    
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    
    esp32_crypto_result_t result = ESP32_CRYPTO_SUCCESS;
    
    do {
        // Charger la courbe P-256
        int ret = mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
            break;
        }
        
        // Charger la clé publique
        ret = mbedtls_ecp_point_read_binary(&ecdsa_ctx.grp, &ecdsa_ctx.Q, public_key, 65);
        if (ret != 0) {
            ESP_LOGE(TAG, "Échec chargement clé publique: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_INVALID_PARAM;
            break;
        }
        
        // Charger la signature (r || s)
        ret = mbedtls_mpi_read_binary(&r, signature, 32);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_INVALID_PARAM;
            break;
        }
        
        ret = mbedtls_mpi_read_binary(&s, signature + 32, 32);
        if (ret != 0) {
            result = ESP32_CRYPTO_ERROR_INVALID_PARAM;
            break;
        }
        
        // Vérifier la signature
        ret = mbedtls_ecdsa_verify(&ecdsa_ctx.grp, message_hash, 32, &ecdsa_ctx.Q, &r, &s);
        if (ret != 0) {
            ESP_LOGW(TAG, "Signature ECDSA invalide: -0x%04x", -ret);
            result = ESP32_CRYPTO_ERROR_VERIFICATION_FAILED;
            break;
        }
        
        ESP_LOGD(TAG, "Signature ECDSA valide");
        g_crypto_info.operation_count++;
        
    } while (0);
    
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    g_crypto_info.last_operation_time = esp_timer_get_time();
    return result;
}

esp32_crypto_result_t esp32_crypto_perform_attestation(const uint8_t* challenge, size_t challenge_size, 
                                                        esp32_attestation_t* attestation) {
    if (!g_crypto_initialized || challenge == NULL || attestation == NULL || challenge_size != 32) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    ESP_LOGI(TAG, "Exécution attestation ESP32...");
    
    memset(attestation, 0, sizeof(esp32_attestation_t));
    
    // Copier le challenge
    memcpy(attestation->challenge, challenge, challenge_size);
    
    // Ajouter l'ID du dispositif
    memcpy(attestation->device_id, g_crypto_info.device_id, ESP32_SERIAL_NUMBER_SIZE);
    
    // Ajouter timestamp et boot count
    attestation->timestamp = (uint32_t)(esp_timer_get_time() / 1000000); // Secondes
    attestation->boot_count = g_crypto_info.operation_count; // Approximation
    
    // Créer le message à signer (challenge + device_id + timestamp)
    uint8_t message_to_sign[32 + 6 + 4];
    memcpy(message_to_sign, challenge, 32);
    memcpy(message_to_sign + 32, g_crypto_info.device_id, 6);
    memcpy(message_to_sign + 38, &attestation->timestamp, 4);
    
    // Calculer le hash du message
    uint8_t message_hash[32];
    esp32_crypto_result_t result = esp32_crypto_sha256(message_to_sign, sizeof(message_to_sign), message_hash);
    if (result != ESP32_CRYPTO_SUCCESS) {
        return result;
    }
    
    // Signer avec la clé d'attestation (slot 1)
    result = esp32_crypto_ecdsa_sign(1, message_hash, attestation->response);
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "Échec signature attestation");
        return result;
    }
    
    // Générer un certificat auto-signé simple (pour la démo)
    snprintf((char*)attestation->device_cert, ESP32_CERTIFICATE_SIZE,
             "-----BEGIN CERTIFICATE-----\n"
             "SecureIoT-VIF ESP32 Device Certificate\n"
             "Device ID: %02X:%02X:%02X:%02X:%02X:%02X\n"
             "Timestamp: %u\n"
             "Secure Boot: %s\n"
             "Flash Encryption: %s\n"
             "-----END CERTIFICATE-----\n",
             g_crypto_info.device_id[0], g_crypto_info.device_id[1], g_crypto_info.device_id[2],
             g_crypto_info.device_id[3], g_crypto_info.device_id[4], g_crypto_info.device_id[5],
             attestation->timestamp,
             g_crypto_info.secure_boot_enabled ? "Enabled" : "Disabled",
             g_crypto_info.flash_encryption_enabled ? "Enabled" : "Disabled");
    
    attestation->is_valid = true;
    g_crypto_info.operation_count++;
    
    ESP_LOGI(TAG, "Attestation ESP32 générée avec succès");
    return ESP32_CRYPTO_SUCCESS;
}

// ================================
// Fonctions utilitaires
// ================================

const char* esp32_crypto_error_to_string(esp32_crypto_result_t error) {
    switch (error) {
        case ESP32_CRYPTO_SUCCESS: return "Succès";
        case ESP32_CRYPTO_ERROR_INVALID_PARAM: return "Paramètre invalide";
        case ESP32_CRYPTO_ERROR_NOT_INITIALIZED: return "Non initialisé";
        case ESP32_CRYPTO_ERROR_MEMORY: return "Erreur mémoire";
        case ESP32_CRYPTO_ERROR_EFUSE_PROGRAMMING: return "Erreur programmation eFuse";
        case ESP32_CRYPTO_ERROR_VERIFICATION_FAILED: return "Vérification échouée";
        case ESP32_CRYPTO_ERROR_EXECUTION_FAILED: return "Exécution échouée";
        case ESP32_CRYPTO_ERROR_ENTROPY_FAILED: return "Erreur entropie";
        case ESP32_CRYPTO_ERROR_KEY_GENERATION: return "Erreur génération clé";
        case ESP32_CRYPTO_ERROR_FLASH_ENCRYPTION: return "Erreur chiffrement flash";
        case ESP32_CRYPTO_ERROR_SECURE_BOOT: return "Erreur secure boot";
        default: return "Erreur inconnue";
    }
}

void esp32_crypto_print_device_info(void) {
    if (!g_crypto_initialized) {
        ESP_LOGW(TAG, "Gestionnaire crypto non initialisé");
        return;
    }
    
    ESP_LOGI(TAG, "=== Informations Crypto ESP32 ===");
    ESP_LOGI(TAG, "Device ID: %02X:%02X:%02X:%02X:%02X:%02X",
             g_crypto_info.device_id[0], g_crypto_info.device_id[1], g_crypto_info.device_id[2],
             g_crypto_info.device_id[3], g_crypto_info.device_id[4], g_crypto_info.device_id[5]);
    ESP_LOGI(TAG, "Chip Revision: %d", g_crypto_info.chip_revision);
    ESP_LOGI(TAG, "Secure Boot: %s", g_crypto_info.secure_boot_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "Flash Encryption: %s", g_crypto_info.flash_encryption_enabled ? "Activé" : "Désactivé");
    ESP_LOGI(TAG, "État: %d", g_crypto_info.state);
    ESP_LOGI(TAG, "Opérations: %d", g_crypto_info.operation_count);
    ESP_LOGI(TAG, "Erreurs: %d", g_crypto_info.error_count);
    ESP_LOGI(TAG, "==============================");
}

esp32_crypto_result_t esp32_crypto_self_test(void) {
    if (!g_crypto_initialized) {
        return ESP32_CRYPTO_ERROR_NOT_INITIALIZED;
    }
    
    ESP_LOGI(TAG, "=== Démarrage Auto-test Crypto ESP32 ===");
    
    // Test 1: Génération aléatoire
    ESP_LOGI(TAG, "Test 1: Génération aléatoire...");
    uint8_t random1[32], random2[32];
    esp32_crypto_result_t result = esp32_crypto_generate_random(random1, sizeof(random1));
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Test génération aléatoire échoué");
        return result;
    }
    
    result = esp32_crypto_generate_random(random2, sizeof(random2));
    if (result != ESP32_CRYPTO_SUCCESS || memcmp(random1, random2, 32) == 0) {
        ESP_LOGE(TAG, "❌ Test génération aléatoire échoué (identiques)");
        return ESP32_CRYPTO_ERROR_ENTROPY_FAILED;
    }
    ESP_LOGI(TAG, "✅ Test génération aléatoire réussi");
    
    // Test 2: Hash SHA-256
    ESP_LOGI(TAG, "Test 2: Hash SHA-256...");
    uint8_t test_data[] = "SecureIoT-VIF ESP32 Test";
    uint8_t hash1[32], hash2[32];
    
    result = esp32_crypto_sha256(test_data, strlen((char*)test_data), hash1);
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Test SHA-256 échoué");
        return result;
    }
    
    result = esp32_crypto_sha256(test_data, strlen((char*)test_data), hash2);
    if (result != ESP32_CRYPTO_SUCCESS || memcmp(hash1, hash2, 32) != 0) {
        ESP_LOGE(TAG, "❌ Test SHA-256 échoué (incohérent)");
        return ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
    }
    ESP_LOGI(TAG, "✅ Test SHA-256 réussi");
    
    // Test 3: Génération de clé ECDSA
    ESP_LOGI(TAG, "Test 3: Génération clé ECDSA...");
    uint8_t public_key[65];
    result = esp32_crypto_generate_ecdsa_keypair(0, public_key);
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Test génération clé ECDSA échoué");
        return result;
    }
    ESP_LOGI(TAG, "✅ Test génération clé ECDSA réussi");
    
    // Test 4: Signature et vérification
    ESP_LOGI(TAG, "Test 4: Signature et vérification ECDSA...");
    uint8_t signature[64];
    result = esp32_crypto_ecdsa_sign(0, hash1, signature);
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Test signature ECDSA échoué");
        return result;
    }
    
    result = esp32_crypto_ecdsa_verify(public_key, hash1, signature);
    if (result != ESP32_CRYPTO_SUCCESS) {
        ESP_LOGE(TAG, "❌ Test vérification ECDSA échoué");
        return result;
    }
    ESP_LOGI(TAG, "✅ Test signature/vérification ECDSA réussi");
    
    // Test 5: Attestation complète
    ESP_LOGI(TAG, "Test 5: Attestation complète...");
    uint8_t challenge[32];
    esp32_crypto_generate_random(challenge, sizeof(challenge));
    
    esp32_attestation_t attestation;
    result = esp32_crypto_perform_attestation(challenge, sizeof(challenge), &attestation);
    if (result != ESP32_CRYPTO_SUCCESS || !attestation.is_valid) {
        ESP_LOGE(TAG, "❌ Test attestation échoué");
        return result;
    }
    ESP_LOGI(TAG, "✅ Test attestation réussi");
    
    ESP_LOGI(TAG, "=== 🎉 Auto-test Crypto ESP32 RÉUSSI ===");
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_get_statistics(uint32_t* operations_count, uint32_t* error_count, 
                                                   uint64_t* last_operation_time) {
    if (!g_crypto_initialized) {
        return ESP32_CRYPTO_ERROR_NOT_INITIALIZED;
    }
    
    if (operations_count) *operations_count = g_crypto_info.operation_count;
    if (error_count) *error_count = g_crypto_info.error_count;
    if (last_operation_time) *last_operation_time = g_crypto_info.last_operation_time;
    
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_get_device_id(uint8_t* device_id) {
    if (!g_crypto_initialized || device_id == NULL) {
        return ESP32_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memcpy(device_id, g_crypto_info.device_id, ESP32_SERIAL_NUMBER_SIZE);
    return ESP32_CRYPTO_SUCCESS;
}

// Fonctions de compatibilité supplémentaires
esp32_crypto_result_t esp32_crypto_verify_integrity(void) {
    return esp32_crypto_health_check();
}

esp32_crypto_result_t esp32_crypto_update_heartbeat(uint32_t counter) {
    ESP_LOGD(TAG, "Heartbeat update: %u", counter);
    g_crypto_info.last_operation_time = esp_timer_get_time();
    return ESP32_CRYPTO_SUCCESS;
}

esp32_crypto_result_t esp32_crypto_store_emergency_state(void) {
    ESP_LOGI(TAG, "Stockage état d'urgence...");
    
    nvs_handle_t nvs_handle;
    esp_err_t ret = nvs_open("emergency", NVS_READWRITE, &nvs_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Erreur ouverture NVS: %s", esp_err_to_name(ret));
        return ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
    }
    
    uint32_t emergency_data = g_crypto_info.operation_count;
    ret = nvs_set_u32(nvs_handle, "state", emergency_data);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Erreur écriture NVS: %s", esp_err_to_name(ret));
        nvs_close(nvs_handle);
        return ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
    }
    
    ret = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Erreur commit NVS: %s", esp_err_to_name(ret));
        return ESP32_CRYPTO_ERROR_EXECUTION_FAILED;
    }
    
    ESP_LOGI(TAG, "État d'urgence stocké avec succès");
    return ESP32_CRYPTO_SUCCESS;
}