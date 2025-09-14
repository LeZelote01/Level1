/**
 * @file crypto_operations.h
 * @brief Opérations cryptographiques avancées Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise complète avec toutes les fonctionnalités avancées :
 * - Support SHA-512 Enterprise
 * - Protection contre les attaques par canal auxiliaire
 * - Métriques et monitoring avancés
 * - Support crypto post-quantique (préparation)
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 - Enterprise Edition
 * @date 2025
 */

#ifndef CRYPTO_OPERATIONS_H
#define CRYPTO_OPERATIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

// ================================
// Constantes cryptographiques Enterprise
// ================================

#define CRYPTO_SHA256_DIGEST_SIZE       (32)
#define CRYPTO_SHA512_DIGEST_SIZE       (64)    // Enterprise
#define CRYPTO_AES_KEY_SIZE             (32)    // AES-256
#define CRYPTO_AES_IV_SIZE              (16)
#define CRYPTO_AES_BLOCK_SIZE           (16)
#define CRYPTO_HMAC_KEY_SIZE            (32)
#define CRYPTO_NONCE_SIZE               (16)
#define CRYPTO_SALT_SIZE                (16)
#define CRYPTO_DERIVED_KEY_SIZE         (32)

// Tailles pour les algorithmes ECC Enterprise
#define CRYPTO_ECC_PRIVATE_KEY_SIZE     (32)
#define CRYPTO_ECC_PUBLIC_KEY_SIZE      (64)
#define CRYPTO_ECC_SIGNATURE_SIZE       (64)
#define CRYPTO_ECC_SHARED_SECRET_SIZE   (32)

// Constantes Enterprise spécifiques
#define CRYPTO_ENTERPRISE_MAX_KEY_SIZE  (64)    // Support clés plus longues
#define CRYPTO_ENTERPRISE_MAX_DIGEST    (64)    // SHA-512
#define CRYPTO_ENTERPRISE_SLOTS         (8)     // 8 slots crypto

// ================================
// Types et énumérations Enterprise
// ================================

/**
 * @brief Types d'algorithmes de hachage Enterprise
 */
typedef enum {
    CRYPTO_HASH_SHA256 = 0,
    CRYPTO_HASH_SHA512,                         // Enterprise
    CRYPTO_HASH_SHA1,
    CRYPTO_HASH_MD5,
    CRYPTO_HASH_SHA3_256,                       // Futur Enterprise
    CRYPTO_HASH_SHA3_512                        // Futur Enterprise
} crypto_hash_algorithm_t;

/**
 * @brief Types de chiffrement symétrique Enterprise
 */
typedef enum {
    CRYPTO_CIPHER_AES_256_CBC = 0,
    CRYPTO_CIPHER_AES_256_GCM,
    CRYPTO_CIPHER_AES_128_CBC,
    CRYPTO_CIPHER_AES_128_GCM,
    CRYPTO_CIPHER_AES_256_CCM,                  // Enterprise
    CRYPTO_CIPHER_CHACHA20_POLY1305             // Enterprise
} crypto_cipher_algorithm_t;

/**
 * @brief Modes d'opération pour la dérivation de clés Enterprise
 */
typedef enum {
    CRYPTO_KDF_PBKDF2 = 0,
    CRYPTO_KDF_HKDF,
    CRYPTO_KDF_SCRYPT,
    CRYPTO_KDF_ARGON2                           // Enterprise
} crypto_kdf_algorithm_t;

/**
 * @brief Résultats des opérations cryptographiques Enterprise
 */
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_PARAM = -1,
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -2,
    CRYPTO_ERROR_OPERATION_FAILED = -3,
    CRYPTO_ERROR_NOT_SUPPORTED = -4,
    CRYPTO_ERROR_VERIFICATION_FAILED = -5,
    CRYPTO_ERROR_MEMORY = -6,
    CRYPTO_ERROR_SE_COMMUNICATION = -7,
    CRYPTO_ERROR_TIMING_ATTACK_DETECTED = -8,   // Enterprise
    CRYPTO_ERROR_ENTROPY_INSUFFICIENT = -9,     // Enterprise
    CRYPTO_ERROR_QUANTUM_RESISTANCE_REQUIRED = -10 // Futur Enterprise
} crypto_result_t;

/**
 * @brief Niveaux de sécurité Enterprise
 */
typedef enum {
    CRYPTO_SECURITY_BASIC = 1,
    CRYPTO_SECURITY_STANDARD = 2,
    CRYPTO_SECURITY_HIGH = 3,
    CRYPTO_SECURITY_CRITICAL = 4,
    CRYPTO_SECURITY_MAXIMUM = 5                 // Enterprise
} crypto_security_level_t;

// ================================
// Structures de données Enterprise
// ================================

/**
 * @brief Contexte pour les opérations de hachage Enterprise
 */
typedef struct {
    crypto_hash_algorithm_t algorithm;
    void* internal_ctx;
    uint8_t digest[CRYPTO_ENTERPRISE_MAX_DIGEST];  // Support SHA-512
    size_t digest_size;
    bool is_finalized;
    
    // Métadonnées Enterprise
    uint64_t start_time;
    uint32_t data_processed;
    crypto_security_level_t security_level;
    bool timing_protection_enabled;
} crypto_hash_ctx_t;

/**
 * @brief Contexte pour le chiffrement symétrique Enterprise
 */
typedef struct {
    crypto_cipher_algorithm_t algorithm;
    uint8_t key[CRYPTO_ENTERPRISE_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    void* internal_ctx;
    bool is_encrypt;
    bool is_initialized;
    
    // Métadonnées Enterprise
    crypto_security_level_t security_level;
    bool side_channel_protection;
    uint32_t operation_counter;
} crypto_cipher_ctx_t;

/**
 * @brief Paramètres pour la dérivation de clés Enterprise
 */
typedef struct {
    crypto_kdf_algorithm_t algorithm;
    const uint8_t* password;
    size_t password_len;
    const uint8_t* salt;
    size_t salt_len;
    uint32_t iterations;
    size_t output_len;
    
    // Paramètres Enterprise
    crypto_security_level_t security_level;
    uint32_t memory_cost;                       // Pour Argon2
    uint32_t parallelism;                       // Pour Argon2
    bool timing_attack_protection;
} crypto_kdf_params_t;

/**
 * @brief Structure pour les clés ECC Enterprise
 */
typedef struct {
    uint8_t private_key[CRYPTO_ECC_PRIVATE_KEY_SIZE];
    uint8_t public_key[CRYPTO_ECC_PUBLIC_KEY_SIZE];
    bool has_private;
    bool has_public;
    uint8_t curve_id;                           // Identificateur de courbe
    
    // Métadonnées Enterprise
    crypto_security_level_t security_level;
    bool quantum_resistant;                     // Préparation futur
    uint32_t creation_time;
    uint32_t usage_count;
    bool hardware_backed;                       // Stocké en eFuse
} crypto_ecc_keypair_t;

/**
 * @brief Structure pour les signatures ECC Enterprise
 */
typedef struct {
    uint8_t r[32];                              // Composante R de la signature
    uint8_t s[32];                              // Composante S de la signature
    uint8_t signature[CRYPTO_ECC_SIGNATURE_SIZE];
    bool is_valid;
    
    // Métadonnées Enterprise
    uint32_t timestamp;
    crypto_security_level_t security_level;
    float confidence_score;                     // Score de confiance
    uint32_t verification_time_us;              // Temps de vérification
    bool timing_safe_verified;                  // Vérification en temps constant
} crypto_ecc_signature_t;

/**
 * @brief Statistiques cryptographiques Enterprise
 */
typedef struct {
    uint32_t total_operations;
    uint32_t successful_operations;
    uint32_t failed_operations;
    uint64_t total_time_us;
    uint64_t average_time_us;
    uint32_t timing_attacks_detected;           // Enterprise
    uint32_t quantum_operations;                // Futur Enterprise
    uint32_t hardware_operations;               // Operations via eFuse
    float overall_performance_score;
} crypto_statistics_t;

// ================================
// Fonctions de hachage Enterprise
// ================================

/**
 * @brief Initialise un contexte de hachage Enterprise
 */
crypto_result_t crypto_hash_init_enterprise(crypto_hash_ctx_t* ctx, crypto_hash_algorithm_t algorithm);

/**
 * @brief Met à jour le hachage avec de nouvelles données Enterprise
 */
crypto_result_t crypto_hash_update_enterprise(crypto_hash_ctx_t* ctx, const uint8_t* data, size_t data_len);

/**
 * @brief Finalise le hachage et obtient le digest Enterprise
 */
crypto_result_t crypto_hash_final_enterprise(crypto_hash_ctx_t* ctx, uint8_t* digest, size_t* digest_len);

/**
 * @brief Calcule le hachage d'un bloc de données Enterprise (one-shot)
 */
crypto_result_t crypto_hash_compute_enterprise(crypto_hash_algorithm_t algorithm, 
                                               const uint8_t* data, size_t data_len,
                                               uint8_t* digest, size_t* digest_len);

/**
 * @brief Libère les ressources du contexte de hachage Enterprise
 */
void crypto_hash_cleanup_enterprise(crypto_hash_ctx_t* ctx);

// ================================
// Fonctions ECC avec crypto ESP32 Enterprise
// ================================

/**
 * @brief Génère une paire de clés ECC Enterprise dans le crypto ESP32
 */
crypto_result_t crypto_ecc_generate_keypair_se_enterprise(uint8_t slot_id, crypto_ecc_keypair_t* keypair);

/**
 * @brief Signe des données avec une clé privée Enterprise dans le crypto ESP32
 */
crypto_result_t crypto_ecc_sign_se_enterprise(uint8_t slot_id, const uint8_t* data, size_t data_len,
                                              crypto_ecc_signature_t* signature);

/**
 * @brief Vérifie une signature ECC Enterprise
 */
crypto_result_t crypto_ecc_verify_enterprise(const uint8_t* public_key, 
                                             const uint8_t* data, size_t data_len,
                                             const crypto_ecc_signature_t* signature);

/**
 * @brief Effectue un échange de clés ECDH Enterprise avec le crypto ESP32
 */
crypto_result_t crypto_ecdh_se_enterprise(uint8_t private_key_slot, const uint8_t* remote_public_key,
                                          uint8_t* shared_secret);

// ================================
// Fonctions de génération aléatoire sécurisée Enterprise
// ================================

/**
 * @brief Génère des bytes aléatoires sécurisés Enterprise avec le crypto ESP32
 */
crypto_result_t crypto_random_se_enterprise(uint8_t* buffer, size_t length);

/**
 * @brief Génère un nonce aléatoire sécurisé Enterprise
 */
crypto_result_t crypto_generate_nonce_enterprise(uint8_t* nonce, size_t nonce_len);

/**
 * @brief Génère une clé symétrique aléatoire Enterprise
 */
crypto_result_t crypto_generate_symmetric_key_enterprise(uint8_t* key, size_t key_len);

// ================================
// Fonctions d'authentification et d'intégrité Enterprise
// ================================

/**
 * @brief Calcule un MAC d'intégrité pour un firmware Enterprise
 */
crypto_result_t crypto_compute_firmware_mac_enterprise(const uint8_t* firmware_data, size_t firmware_size,
                                                       uint8_t key_slot, uint8_t* mac, size_t* mac_len);

/**
 * @brief Vérifie l'intégrité d'un firmware Enterprise
 */
crypto_result_t crypto_verify_firmware_integrity_enterprise(const uint8_t* firmware_data, size_t firmware_size,
                                                            uint8_t key_slot, const uint8_t* expected_mac, 
                                                            size_t mac_len);

// ================================
// Fonctions utilitaires Enterprise
// ================================

/**
 * @brief Convertit un résultat crypto en string Enterprise
 */
const char* crypto_result_to_string_enterprise(crypto_result_t result);

/**
 * @brief Efface de manière sécurisée un buffer mémoire Enterprise
 */
void crypto_secure_memzero_enterprise(void* buffer, size_t size);

/**
 * @brief Compare deux buffers de manière sécurisée Enterprise (constant time)
 */
int crypto_secure_memcmp_enterprise(const void* a, const void* b, size_t len);

/**
 * @brief Initialise le sous-système cryptographique Enterprise
 */
crypto_result_t crypto_init_enterprise(void);

/**
 * @brief Dé-initialise le sous-système cryptographique Enterprise
 */
void crypto_deinit_enterprise(void);

/**
 * @brief Test de performance des opérations cryptographiques Enterprise
 */
crypto_result_t crypto_performance_test_enterprise(void);

/**
 * @brief Obtient les statistiques cryptographiques Enterprise
 */
crypto_result_t crypto_get_statistics_enterprise(uint32_t* total_ops, uint32_t* failures, uint64_t* avg_time_us);

/**
 * @brief Affiche les statistiques cryptographiques Enterprise
 */
void crypto_print_statistics_enterprise(void);

// ================================
// Protection contre les attaques Enterprise
// ================================

/**
 * @brief Configure la protection contre les attaques temporelles
 */
crypto_result_t crypto_enable_timing_protection(bool enable);

/**
 * @brief Configure la protection contre les canaux auxiliaires
 */
crypto_result_t crypto_enable_side_channel_protection(bool enable);

/**
 * @brief Vérifie la détection d'attaques en cours
 */
crypto_result_t crypto_check_attack_detection(void);

// ================================
// Support crypto post-quantique (préparation futur)
// ================================

/**
 * @brief Vérifie la disponibilité des algorithmes post-quantiques
 */
bool crypto_is_quantum_resistant_available(void);

/**
 * @brief Configure le niveau de résistance quantique
 */
crypto_result_t crypto_set_quantum_resistance_level(uint8_t level);

// ================================
// Fonctions de compatibilité avec l'API de base
// ================================

/**
 * @brief Initialise un contexte de hachage (wrapper Enterprise)
 */
crypto_result_t crypto_hash_init(crypto_hash_ctx_t* ctx, crypto_hash_algorithm_t algorithm);

/**
 * @brief Met à jour le hachage avec de nouvelles données (wrapper Enterprise)
 */
crypto_result_t crypto_hash_update(crypto_hash_ctx_t* ctx, const uint8_t* data, size_t data_len);

/**
 * @brief Finalise le hachage et obtient le digest (wrapper Enterprise)
 */
crypto_result_t crypto_hash_final(crypto_hash_ctx_t* ctx, uint8_t* digest, size_t* digest_len);

/**
 * @brief Calcule le hachage d'un bloc de données (wrapper Enterprise)
 */
crypto_result_t crypto_hash_compute(crypto_hash_algorithm_t algorithm, 
                                    const uint8_t* data, size_t data_len,
                                    uint8_t* digest, size_t* digest_len);

/**
 * @brief Libère les ressources du contexte de hachage (wrapper Enterprise)
 */
void crypto_hash_cleanup(crypto_hash_ctx_t* ctx);

/**
 * @brief Génère une paire de clés ECC dans le crypto ESP32 (wrapper Enterprise)
 */
crypto_result_t crypto_ecc_generate_keypair_se(uint8_t slot_id, crypto_ecc_keypair_t* keypair);

/**
 * @brief Signe des données avec une clé privée (wrapper Enterprise)
 */
crypto_result_t crypto_ecc_sign_se(uint8_t slot_id, const uint8_t* data, size_t data_len,
                                   crypto_ecc_signature_t* signature);

/**
 * @brief Vérifie une signature ECC (wrapper Enterprise)
 */
crypto_result_t crypto_ecc_verify(const uint8_t* public_key, 
                                  const uint8_t* data, size_t data_len,
                                  const crypto_ecc_signature_t* signature);

/**
 * @brief Génère des bytes aléatoires sécurisés (wrapper Enterprise)
 */
crypto_result_t crypto_random_se(uint8_t* buffer, size_t length);

/**
 * @brief Génère un nonce aléatoire sécurisé (wrapper Enterprise)
 */
crypto_result_t crypto_generate_nonce(uint8_t* nonce, size_t nonce_len);

/**
 * @brief Génère une clé symétrique aléatoire (wrapper Enterprise)
 */
crypto_result_t crypto_generate_symmetric_key(uint8_t* key, size_t key_len);

/**
 * @brief Calcule un MAC d'intégrité pour un firmware (wrapper Enterprise)
 */
crypto_result_t crypto_compute_firmware_mac(const uint8_t* firmware_data, size_t firmware_size,
                                            uint8_t key_slot, uint8_t* mac, size_t* mac_len);

/**
 * @brief Vérifie l'intégrité d'un firmware (wrapper Enterprise)
 */
crypto_result_t crypto_verify_firmware_integrity(const uint8_t* firmware_data, size_t firmware_size,
                                                 uint8_t key_slot, const uint8_t* expected_mac, 
                                                 size_t mac_len);

/**
 * @brief Convertit un résultat crypto en string (wrapper Enterprise)
 */
const char* crypto_result_to_string(crypto_result_t result);

/**
 * @brief Efface de manière sécurisée un buffer mémoire (wrapper Enterprise)
 */
void crypto_secure_memzero(void* buffer, size_t size);

/**
 * @brief Compare deux buffers de manière sécurisée (wrapper Enterprise)
 */
int crypto_secure_memcmp(const void* a, const void* b, size_t len);

/**
 * @brief Initialise le sous-système cryptographique (wrapper Enterprise)
 */
crypto_result_t crypto_init(void);

/**
 * @brief Dé-initialise le sous-système cryptographique (wrapper Enterprise)
 */
void crypto_deinit(void);

/**
 * @brief Test de performance des opérations cryptographiques (wrapper Enterprise)
 */
crypto_result_t crypto_performance_test(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_OPERATIONS_H */