/**
 * @file crypto_operations.h
 * @brief Opérations cryptographiques avancées pour SecureIoT-VIF
 * 
 * Ce module fournit des opérations cryptographiques de haut niveau
 * utilisant les capacités crypto intégrées de l'ESP32.
 * 
 * @author Framework SecureIoT-VIF
 * @version 2.0.0 - ESP32 Crypto Intégré
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
// Constantes cryptographiques
// ================================

#define CRYPTO_SHA256_DIGEST_SIZE       (32)
#define CRYPTO_AES_KEY_SIZE             (32)    // AES-256
#define CRYPTO_AES_IV_SIZE              (16)
#define CRYPTO_AES_BLOCK_SIZE           (16)
#define CRYPTO_HMAC_KEY_SIZE            (32)
#define CRYPTO_NONCE_SIZE               (16)
#define CRYPTO_SALT_SIZE                (16)
#define CRYPTO_DERIVED_KEY_SIZE         (32)

// Tailles pour les algorithmes ECC
#define CRYPTO_ECC_PRIVATE_KEY_SIZE     (32)
#define CRYPTO_ECC_PUBLIC_KEY_SIZE      (64)
#define CRYPTO_ECC_SIGNATURE_SIZE       (64)
#define CRYPTO_ECC_SHARED_SECRET_SIZE   (32)

// ================================
// Types et énumérations
// ================================

/**
 * @brief Types d'algorithmes de hachage
 */
typedef enum {
    CRYPTO_HASH_SHA256 = 0,
    CRYPTO_HASH_SHA1,
    CRYPTO_HASH_MD5
} crypto_hash_algorithm_t;

/**
 * @brief Types de chiffrement symétrique
 */
typedef enum {
    CRYPTO_CIPHER_AES_256_CBC = 0,
    CRYPTO_CIPHER_AES_256_GCM,
    CRYPTO_CIPHER_AES_128_CBC,
    CRYPTO_CIPHER_AES_128_GCM
} crypto_cipher_algorithm_t;

/**
 * @brief Modes d'opération pour la dérivation de clés
 */
typedef enum {
    CRYPTO_KDF_PBKDF2 = 0,
    CRYPTO_KDF_HKDF,
    CRYPTO_KDF_SCRYPT
} crypto_kdf_algorithm_t;

/**
 * @brief Résultats des opérations cryptographiques
 */
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_PARAM = -1,
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -2,
    CRYPTO_ERROR_OPERATION_FAILED = -3,
    CRYPTO_ERROR_NOT_SUPPORTED = -4,
    CRYPTO_ERROR_VERIFICATION_FAILED = -5,
    CRYPTO_ERROR_MEMORY = -6,
    CRYPTO_ERROR_SE_COMMUNICATION = -7
} crypto_result_t;

// ================================
// Structures de données
// ================================

/**
 * @brief Contexte pour les opérations de hachage
 */
typedef struct {
    crypto_hash_algorithm_t algorithm;
    void* internal_ctx;
    uint8_t digest[CRYPTO_SHA256_DIGEST_SIZE];
    size_t digest_size;
    bool is_finalized;
} crypto_hash_ctx_t;

/**
 * @brief Contexte pour le chiffrement symétrique
 */
typedef struct {
    crypto_cipher_algorithm_t algorithm;
    uint8_t key[CRYPTO_AES_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    void* internal_ctx;
    bool is_encrypt;
    bool is_initialized;
} crypto_cipher_ctx_t;

/**
 * @brief Paramètres pour la dérivation de clés
 */
typedef struct {
    crypto_kdf_algorithm_t algorithm;
    const uint8_t* password;
    size_t password_len;
    const uint8_t* salt;
    size_t salt_len;
    uint32_t iterations;
    size_t output_len;
} crypto_kdf_params_t;

/**
 * @brief Structure pour les clés ECC
 */
typedef struct {
    uint8_t private_key[CRYPTO_ECC_PRIVATE_KEY_SIZE];
    uint8_t public_key[CRYPTO_ECC_PUBLIC_KEY_SIZE];
    bool has_private;
    bool has_public;
    uint8_t curve_id;  // Identificateur de courbe
} crypto_ecc_keypair_t;

/**
 * @brief Structure pour les signatures ECC
 */
typedef struct {
    uint8_t r[32];  // Composante R de la signature
    uint8_t s[32];  // Composante S de la signature
    uint8_t signature[CRYPTO_ECC_SIGNATURE_SIZE];
    bool is_valid;
} crypto_ecc_signature_t;

// ================================
// Fonctions de hachage
// ================================

/**
 * @brief Initialise un contexte de hachage
 * 
 * @param ctx Contexte de hachage
 * @param algorithm Algorithme de hachage
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_init(crypto_hash_ctx_t* ctx, crypto_hash_algorithm_t algorithm);

/**
 * @brief Met à jour le hachage avec de nouvelles données
 * 
 * @param ctx Contexte de hachage
 * @param data Données à hacher
 * @param data_len Longueur des données
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_update(crypto_hash_ctx_t* ctx, const uint8_t* data, size_t data_len);

/**
 * @brief Finalise le hachage et obtient le digest
 * 
 * @param ctx Contexte de hachage
 * @param digest Buffer pour le digest
 * @param digest_len Pointeur vers la longueur du digest
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_final(crypto_hash_ctx_t* ctx, uint8_t* digest, size_t* digest_len);

/**
 * @brief Calcule le hachage d'un bloc de données (one-shot)
 * 
 * @param algorithm Algorithme de hachage
 * @param data Données à hacher
 * @param data_len Longueur des données
 * @param digest Buffer pour le digest
 * @param digest_len Pointeur vers la longueur du digest
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_compute(crypto_hash_algorithm_t algorithm, 
                                    const uint8_t* data, size_t data_len,
                                    uint8_t* digest, size_t* digest_len);

// ================================
// Fonctions de chiffrement symétrique
// ================================

/**
 * @brief Initialise un contexte de chiffrement
 * 
 * @param ctx Contexte de chiffrement
 * @param algorithm Algorithme de chiffrement
 * @param key Clé de chiffrement
 * @param key_len Longueur de la clé
 * @param iv Vecteur d'initialisation
 * @param is_encrypt true pour chiffrement, false pour déchiffrement
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_cipher_init(crypto_cipher_ctx_t* ctx, 
                                   crypto_cipher_algorithm_t algorithm,
                                   const uint8_t* key, size_t key_len,
                                   const uint8_t* iv, bool is_encrypt);

/**
 * @brief Traite des données avec le chiffrement
 * 
 * @param ctx Contexte de chiffrement
 * @param input Données d'entrée
 * @param input_len Longueur des données d'entrée
 * @param output Buffer de sortie
 * @param output_len Pointeur vers la longueur de sortie
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_cipher_update(crypto_cipher_ctx_t* ctx,
                                     const uint8_t* input, size_t input_len,
                                     uint8_t* output, size_t* output_len);

/**
 * @brief Finalise l'opération de chiffrement
 * 
 * @param ctx Contexte de chiffrement
 * @param output Buffer pour les derniers données
 * @param output_len Pointeur vers la longueur de sortie
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_cipher_final(crypto_cipher_ctx_t* ctx, uint8_t* output, size_t* output_len);

/**
 * @brief Libère les ressources du contexte de chiffrement
 * 
 * @param ctx Contexte de chiffrement
 */
void crypto_cipher_cleanup(crypto_cipher_ctx_t* ctx);

// ================================
// Fonctions de dérivation de clés
// ================================

/**
 * @brief Dérive une clé à partir d'un mot de passe
 * 
 * @param params Paramètres de dérivation
 * @param output Buffer pour la clé dérivée
 * @param output_len Longueur de la clé à générer
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_kdf_derive_key(const crypto_kdf_params_t* params, 
                                      uint8_t* output, size_t output_len);

/**
 * @brief Génère un sel aléatoire sécurisé
 * 
 * @param salt Buffer pour le sel
 * @param salt_len Longueur du sel
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_generate_salt(uint8_t* salt, size_t salt_len);

// ================================
// Fonctions ECC avec crypto ESP32
// ================================

/**
 * @brief Génère une paire de clés ECC dans le crypto ESP32
 * 
 * @param slot_id Slot du crypto ESP32
 * @param keypair Structure pour stocker les clés
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_ecc_generate_keypair_se(uint8_t slot_id, crypto_ecc_keypair_t* keypair);

/**
 * @brief Signe des données avec une clé privée dans le crypto ESP32
 * 
 * @param slot_id Slot contenant la clé privée
 * @param data Données à signer
 * @param data_len Longueur des données
 * @param signature Structure pour la signature
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_ecc_sign_se(uint8_t slot_id, const uint8_t* data, size_t data_len,
                                   crypto_ecc_signature_t* signature);

/**
 * @brief Vérifie une signature ECC
 * 
 * @param public_key Clé publique pour la vérification
 * @param data Données originales
 * @param data_len Longueur des données
 * @param signature Signature à vérifier
 * @return crypto_result_t CRYPTO_SUCCESS si la signature est valide
 */
crypto_result_t crypto_ecc_verify(const uint8_t* public_key, 
                                  const uint8_t* data, size_t data_len,
                                  const crypto_ecc_signature_t* signature);

/**
 * @brief Effectue un échange de clés ECDH avec le crypto ESP32
 * 
 * @param private_key_slot Slot de la clé privée locale
 * @param remote_public_key Clé publique distante
 * @param shared_secret Buffer pour le secret partagé
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_ecdh_se(uint8_t private_key_slot, const uint8_t* remote_public_key,
                               uint8_t* shared_secret);

// ================================
// Fonctions HMAC
// ================================

/**
 * @brief Calcule un HMAC avec le crypto ESP32
 * 
 * @param key_slot Slot contenant la clé HMAC
 * @param data Données à authentifier
 * @param data_len Longueur des données
 * @param hmac Buffer pour le HMAC
 * @param hmac_len Pointeur vers la longueur du HMAC
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hmac_se(uint8_t key_slot, const uint8_t* data, size_t data_len,
                               uint8_t* hmac, size_t* hmac_len);

/**
 * @brief Vérifie un HMAC
 * 
 * @param key_slot Slot contenant la clé HMAC
 * @param data Données originales
 * @param data_len Longueur des données
 * @param expected_hmac HMAC attendu
 * @param hmac_len Longueur du HMAC
 * @return crypto_result_t CRYPTO_SUCCESS si le HMAC est valide
 */
crypto_result_t crypto_hmac_verify_se(uint8_t key_slot, const uint8_t* data, size_t data_len,
                                      const uint8_t* expected_hmac, size_t hmac_len);

// ================================
// Fonctions de génération aléatoire sécurisée
// ================================

/**
 * @brief Génère des bytes aléatoires sécurisés avec le crypto ESP32
 * 
 * @param buffer Buffer pour les bytes aléatoires
 * @param length Nombre de bytes à générer
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_random_se(uint8_t* buffer, size_t length);

/**
 * @brief Génère un nonce aléatoire sécurisé
 * 
 * @param nonce Buffer pour le nonce
 * @param nonce_len Longueur du nonce
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_generate_nonce(uint8_t* nonce, size_t nonce_len);

/**
 * @brief Génère une clé symétrique aléatoire
 * 
 * @param key Buffer pour la clé
 * @param key_len Longueur de la clé
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_generate_symmetric_key(uint8_t* key, size_t key_len);

// ================================
// Fonctions d'authentification et d'intégrité
// ================================

/**
 * @brief Calcule un MAC d'intégrité pour un firmware
 * 
 * @param firmware_data Données du firmware
 * @param firmware_size Taille du firmware
 * @param key_slot Slot contenant la clé d'intégrité
 * @param mac Buffer pour le MAC
 * @param mac_len Pointeur vers la longueur du MAC
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_compute_firmware_mac(const uint8_t* firmware_data, size_t firmware_size,
                                            uint8_t key_slot, uint8_t* mac, size_t* mac_len);

/**
 * @brief Vérifie l'intégrité d'un firmware
 * 
 * @param firmware_data Données du firmware
 * @param firmware_size Taille du firmware
 * @param key_slot Slot contenant la clé d'intégrité
 * @param expected_mac MAC attendu
 * @param mac_len Longueur du MAC
 * @return crypto_result_t CRYPTO_SUCCESS si l'intégrité est OK
 */
crypto_result_t crypto_verify_firmware_integrity(const uint8_t* firmware_data, size_t firmware_size,
                                                 uint8_t key_slot, const uint8_t* expected_mac, 
                                                 size_t mac_len);

// ================================
// Fonctions utilitaires
// ================================

/**
 * @brief Convertit un résultat crypto en string
 * 
 * @param result Code de résultat
 * @return const char* Description du résultat
 */
const char* crypto_result_to_string(crypto_result_t result);

/**
 * @brief Efface de manière sécurisée un buffer mémoire
 * 
 * @param buffer Buffer à effacer
 * @param size Taille du buffer
 */
void crypto_secure_memzero(void* buffer, size_t size);

/**
 * @brief Compare deux buffers de manière sécurisée (constant time)
 * 
 * @param a Premier buffer
 * @param b Deuxième buffer
 * @param len Longueur à comparer
 * @return int 0 si égaux, non-zéro sinon
 */
int crypto_secure_memcmp(const void* a, const void* b, size_t len);

/**
 * @brief Initialise le sous-système cryptographique
 * 
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_init(void);

/**
 * @brief Dé-initialise le sous-système cryptographique
 */
void crypto_deinit(void);

/**
 * @brief Test de performance des opérations cryptographiques
 * 
 * @return crypto_result_t CRYPTO_SUCCESS si tous les tests passent
 */
crypto_result_t crypto_performance_test(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_OPERATIONS_H */