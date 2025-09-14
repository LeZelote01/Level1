/**
 * @file crypto_operations_basic.h
 * @brief Header pour les opérations cryptographiques de base - Community Edition
 * 
 * Définit l'interface crypto simplifiée pour la version Community de SecureIoT-VIF.
 * Utilise uniquement le crypto software via mbedTLS.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#ifndef CRYPTO_OPERATIONS_BASIC_H
#define CRYPTO_OPERATIONS_BASIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

// ================================
// Constantes crypto Community
// ================================

#define CRYPTO_BASIC_AES_KEY_SIZE           (16)    // AES-128
#define CRYPTO_BASIC_AES_IV_SIZE            (12)    // GCM IV
#define CRYPTO_BASIC_AES_TAG_SIZE           (16)    // GCM Tag
#define CRYPTO_BASIC_SHA256_SIZE            (32)    // SHA-256 hash
#define CRYPTO_BASIC_ECDSA_PUBLIC_KEY_SIZE  (65)    // P-256 uncompressed
#define CRYPTO_BASIC_ECDSA_PRIVATE_KEY_SIZE (32)    // P-256 private key
#define CRYPTO_BASIC_ECDSA_SIGNATURE_MAX    (72)    // DER encoded max

// ================================
// Types et structures Community
// ================================

/**
 * @brief Structure pour une paire de clés ECDSA basique
 */
typedef struct {
    uint8_t public_key[CRYPTO_BASIC_ECDSA_PUBLIC_KEY_SIZE];
    size_t public_key_len;
    uint8_t private_key[CRYPTO_BASIC_ECDSA_PRIVATE_KEY_SIZE];
    size_t private_key_len;
} crypto_basic_keypair_t;

/**
 * @brief Résultats des opérations crypto basiques
 */
typedef enum {
    CRYPTO_BASIC_SUCCESS = 0,
    CRYPTO_BASIC_ERROR_INVALID_PARAM,
    CRYPTO_BASIC_ERROR_NOT_INITIALIZED,
    CRYPTO_BASIC_ERROR_MEMORY,
    CRYPTO_BASIC_ERROR_CRYPTO_FAILURE,
    CRYPTO_BASIC_MAX
} crypto_basic_result_t;

// ================================
// Fonctions d'initialisation
// ================================

/**
 * @brief Initialise le système cryptographique de base
 * 
 * Configure mbedTLS pour les opérations crypto software.
 * Version simplifiée pour Community Edition.
 * 
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_operations_basic_init(void);

/**
 * @brief Deinitialise le système cryptographique
 * 
 * @return ESP_OK si succès
 */
esp_err_t crypto_operations_basic_deinit(void);

// ================================
// Fonctions de génération aléatoire
// ================================

/**
 * @brief Génère des données aléatoires (software uniquement)
 * 
 * Utilise le générateur software mbedTLS (moins sécurisé que TRNG hardware).
 * 
 * @param buffer Buffer de sortie
 * @param length Nombre de bytes à générer
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_basic_generate_random(uint8_t *buffer, size_t length);

// ================================
// Fonctions de hash
// ================================

/**
 * @brief Calcule un hash SHA-256 (software)
 * 
 * Version software plus lente que l'accélération hardware ESP32.
 * 
 * @param input Données à hasher
 * @param input_len Taille des données
 * @param output Buffer de sortie (32 bytes)
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_basic_sha256(const uint8_t *input, size_t input_len, uint8_t *output);

// ================================
// Fonctions de chiffrement symétrique
// ================================

/**
 * @brief Chiffre des données avec AES-128-GCM
 * 
 * Version simplifiée AES-128 (vs AES-256 Enterprise).
 * 
 * @param key Clé AES-128 (16 bytes)
 * @param iv Vecteur d'initialisation (12 bytes)
 * @param input Données à chiffrer
 * @param input_len Taille des données
 * @param output Buffer de sortie
 * @param tag Tag d'authentification (16 bytes)
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_basic_aes_encrypt(const uint8_t *key, const uint8_t *iv,
                                  const uint8_t *input, size_t input_len,
                                  uint8_t *output, uint8_t *tag);

/**
 * @brief Déchiffre des données avec AES-128-GCM
 * 
 * @param key Clé AES-128 (16 bytes)
 * @param iv Vecteur d'initialisation (12 bytes)
 * @param input Données chiffrées
 * @param input_len Taille des données
 * @param tag Tag d'authentification (16 bytes)
 * @param output Buffer de sortie
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_basic_aes_decrypt(const uint8_t *key, const uint8_t *iv,
                                  const uint8_t *input, size_t input_len,
                                  const uint8_t *tag, uint8_t *output);

// ================================
// Fonctions de signature numérique
// ================================

/**
 * @brief Génère une paire de clés ECDSA P-256 (software)
 * 
 * ATTENTION: Les clés sont stockées en RAM (non sécurisé).
 * En Enterprise, les clés sont protégées par eFuse.
 * 
 * @param keypair Structure pour stocker la paire de clés
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_basic_generate_ecdsa_keypair(crypto_basic_keypair_t *keypair);

/**
 * @brief Signe un hash avec ECDSA (software)
 * 
 * @param keypair Paire de clés contenant la clé privée
 * @param hash Hash à signer (32 bytes SHA-256)
 * @param hash_len Taille du hash
 * @param signature Buffer pour la signature
 * @param signature_len Pointeur vers la taille de la signature
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t crypto_basic_ecdsa_sign(const crypto_basic_keypair_t *keypair,
                                 const uint8_t *hash, size_t hash_len,
                                 uint8_t *signature, size_t *signature_len);

/**
 * @brief Vérifie une signature ECDSA (software)
 * 
 * @param keypair Paire de clés contenant la clé publique
 * @param hash Hash original
 * @param hash_len Taille du hash
 * @param signature Signature à vérifier
 * @param signature_len Taille de la signature
 * @return ESP_OK si signature valide, ESP_FAIL sinon
 */
esp_err_t crypto_basic_ecdsa_verify(const crypto_basic_keypair_t *keypair,
                                   const uint8_t *hash, size_t hash_len,
                                   const uint8_t *signature, size_t signature_len);

// ================================
// Fonctions utilitaires
// ================================

/**
 * @brief Auto-test du système cryptographique de base
 * 
 * Teste toutes les fonctions crypto disponibles en Community Edition.
 * 
 * @return ESP_OK si tous les tests passent, ESP_FAIL sinon
 */
esp_err_t crypto_basic_self_test(void);

/**
 * @brief Affiche les informations du système crypto Community
 */
void crypto_basic_print_info(void);

/**
 * @brief Convertit un code d'erreur crypto en chaîne
 * 
 * @param error Code d'erreur crypto_basic_result_t
 * @return Chaîne décrivant l'erreur
 */
const char* crypto_basic_error_to_string(crypto_basic_result_t error);

// ================================
// Macros utilitaires Community
// ================================

/**
 * @brief Efface de manière sécurisée un buffer (Community)
 */
#define CRYPTO_BASIC_SECURE_ZERO(ptr, len) do { \
    volatile uint8_t *p = (volatile uint8_t *)(ptr); \
    size_t i; \
    for (i = 0; i < (len); i++) { \
        p[i] = 0; \
    } \
} while(0)

/**
 * @brief Vérifie si le crypto est initialisé
 */
#define CRYPTO_BASIC_CHECK_INIT() do { \
    if (!crypto_initialized) { \
        ESP_LOGE(TAG, "Crypto de base non initialisé"); \
        return ESP_ERR_INVALID_STATE; \
    } \
} while(0)

// ================================
// Messages informatifs Community
// ================================

#define CRYPTO_BASIC_SECURITY_WARNING \
    "⚠️  ATTENTION Community Edition ⚠️\n" \
    "• Crypto SOFTWARE uniquement (plus lent)\n" \
    "• Clés stockées en RAM (non sécurisé)\n" \
    "• Pas de protection hardware\n" \
    "• Usage éducatif/recherche UNIQUEMENT\n" \
    "• Pour production: SecureIoT-VIF Enterprise\n"

#define CRYPTO_BASIC_FEATURE_COMPARISON \
    "🆚 Community vs Enterprise:\n" \
    "Community: AES-128, Software, RAM storage\n" \
    "Enterprise: AES-256, Hardware, eFuse storage\n" \
    "Performance: Enterprise 4x plus rapide\n" \
    "Sécurité: Enterprise niveau industriel\n"

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_OPERATIONS_BASIC_H */