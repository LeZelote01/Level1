/**
 * @file esp32_crypto_manager.h
 * @brief Gestionnaire cryptographique ESP32 intégré pour SecureIoT-VIF
 * 
 * Ce module gère toutes les opérations cryptographiques en utilisant
 * les capacités matérielles intégrées de l'ESP32 (HSM, TRNG, AES, SHA, RSA).
 * 
 * @author Framework SecureIoT-VIF
 * @version 2.0.0 - ESP32 Crypto Intégré
 * @date 2025
 */

#ifndef ESP32_CRYPTO_MANAGER_H
#define ESP32_CRYPTO_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_efuse.h"
#include "esp_random.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// ================================
// Constantes et définitions
// ================================

#define ESP32_SERIAL_NUMBER_SIZE        (6)     // MAC Address comme ID unique
#define ESP32_PUBLIC_KEY_SIZE           (64)    // ECDSA P-256
#define ESP32_PRIVATE_KEY_SIZE          (32)    // ECDSA P-256
#define ESP32_SIGNATURE_SIZE            (64)    // ECDSA P-256
#define ESP32_CERTIFICATE_SIZE          (512)   // Certificat auto-signé
#define ESP32_RANDOM_BYTES_SIZE         (32)    // TRNG output
#define ESP32_AES_KEY_SIZE              (32)    // AES-256
#define ESP32_SHA256_SIZE               (32)    // SHA-256 digest

// eFuse blocks pour stockage sécurisé des clés
#define ESP32_EFUSE_KEY_BLOCK_0         (0)     // Clé privée principale
#define ESP32_EFUSE_KEY_BLOCK_1         (1)     // Clé d'attestation
#define ESP32_EFUSE_KEY_BLOCK_2         (2)     // Clé de chiffrement
#define ESP32_EFUSE_KEY_BLOCK_3         (3)     // Clé HMAC

// États du gestionnaire crypto ESP32
typedef enum {
    ESP32_CRYPTO_STATE_UNINITIALIZED = 0,
    ESP32_CRYPTO_STATE_INITIALIZING,
    ESP32_CRYPTO_STATE_CONFIGURED,
    ESP32_CRYPTO_STATE_SECURE_BOOT_ENABLED,
    ESP32_CRYPTO_STATE_ERROR,
    ESP32_CRYPTO_STATE_FLASH_ENCRYPTED
} esp32_crypto_state_t;

// Types d'opérations cryptographiques ESP32
typedef enum {
    ESP32_CRYPTO_SIGN = 0,
    ESP32_CRYPTO_VERIFY,
    ESP32_CRYPTO_ENCRYPT_AES,
    ESP32_CRYPTO_DECRYPT_AES,
    ESP32_CRYPTO_ECDH,
    ESP32_CRYPTO_HMAC_SHA256,
    ESP32_CRYPTO_RANDOM_TRNG,
    ESP32_CRYPTO_HASH_SHA256,
    ESP32_CRYPTO_RSA_ENCRYPT,
    ESP32_CRYPTO_RSA_DECRYPT
} esp32_crypto_operation_t;

// Résultat des opérations crypto ESP32
typedef enum {
    ESP32_CRYPTO_SUCCESS = 0,
    ESP32_CRYPTO_ERROR_INVALID_PARAM = -1,
    ESP32_CRYPTO_ERROR_NOT_INITIALIZED = -2,
    ESP32_CRYPTO_ERROR_MEMORY = -3,
    ESP32_CRYPTO_ERROR_EFUSE_PROGRAMMING = -4,
    ESP32_CRYPTO_ERROR_VERIFICATION_FAILED = -5,
    ESP32_CRYPTO_ERROR_EXECUTION_FAILED = -6,
    ESP32_CRYPTO_ERROR_ENTROPY_FAILED = -7,
    ESP32_CRYPTO_ERROR_KEY_GENERATION = -8,
    ESP32_CRYPTO_ERROR_FLASH_ENCRYPTION = -9,
    ESP32_CRYPTO_ERROR_SECURE_BOOT = -10
} esp32_crypto_result_t;

// ================================
// Structures de données
// ================================

/**
 * @brief Configuration du gestionnaire crypto ESP32
 */
typedef struct {
    bool enable_secure_boot;            // Activer Secure Boot v2
    bool enable_flash_encryption;       // Activer chiffrement flash
    bool enable_hardware_random;        // Utiliser TRNG matériel
    bool enable_efuse_protection;       // Protéger les eFuses
    uint8_t entropy_source;             // Source d'entropie
    uint32_t rsa_key_size;              // Taille clé RSA (1024, 2048, 4096)
    bool enable_debug_mode;             // Mode debug (désactivé en prod)
    uint8_t max_retries;                // Tentatives max pour opérations
} esp32_crypto_config_t;

/**
 * @brief Informations sur le crypto ESP32
 */
typedef struct {
    uint8_t device_id[ESP32_SERIAL_NUMBER_SIZE];  // ID unique (MAC)
    uint32_t chip_revision;                        // Révision du chip
    bool secure_boot_enabled;                      // État Secure Boot
    bool flash_encryption_enabled;                 // État chiffrement flash
    bool efuse_keys_programmed;                    // Clés eFuse programmées
    esp32_crypto_state_t state;                    // État actuel
    uint32_t error_count;                          // Compteur d'erreurs
    uint32_t operation_count;                      // Compteur d'opérations
    uint64_t last_operation_time;                  // Dernière opération
    uint32_t available_entropy;                    // Entropie disponible
} esp32_crypto_info_t;

/**
 * @brief Structure pour les clés ESP32
 */
typedef struct {
    uint8_t key_id;                                // ID de la clé
    uint8_t key_type;                              // Type (ECDSA, AES, RSA, HMAC)
    size_t key_size;                               // Taille de la clé
    uint8_t key_data[ESP32_PUBLIC_KEY_SIZE];       // Données de clé (publique)
    bool is_in_efuse;                              // Stockée dans eFuse
    bool is_protected;                             // Protection activée
    uint32_t usage_count;                          // Compteur d'utilisation
    uint8_t efuse_block;                           // Block eFuse utilisé
} esp32_key_info_t;

/**
 * @brief Structure pour les signatures ESP32
 */
typedef struct {
    uint8_t signature[ESP32_SIGNATURE_SIZE];       // Signature ECDSA
    size_t signature_size;                         // Taille de la signature
    uint8_t message_hash[ESP32_SHA256_SIZE];       // Hash SHA-256 du message
    bool is_valid;                                 // État de validation
    uint32_t timestamp;                            // Timestamp de création
} esp32_signature_t;

/**
 * @brief Structure pour l'attestation ESP32
 */
typedef struct {
    uint8_t challenge[32];                         // Challenge reçu
    uint8_t response[ESP32_SIGNATURE_SIZE];        // Réponse signée
    uint8_t device_cert[ESP32_CERTIFICATE_SIZE];   // Certificat auto-signé
    uint32_t timestamp;                            // Timestamp attestation
    uint8_t device_id[ESP32_SERIAL_NUMBER_SIZE];   // ID unique ESP32
    bool is_valid;                                 // État de validation
    uint32_t boot_count;                           // Compteur de démarrages
} esp32_attestation_t;

// ================================
// Fonctions principales
// ================================

/**
 * @brief Initialise le gestionnaire crypto ESP32
 * 
 * @param config Configuration crypto (NULL pour défaut)
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t esp32_crypto_manager_init(const esp32_crypto_config_t* config);

/**
 * @brief Dé-initialise le gestionnaire crypto ESP32
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t esp32_crypto_manager_deinit(void);

/**
 * @brief Obtient les informations du crypto ESP32
 * 
 * @param info Pointeur vers la structure d'informations
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_get_device_info(esp32_crypto_info_t* info);

/**
 * @brief Vérifie l'état de santé du crypto ESP32
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si tout est OK
 */
esp32_crypto_result_t esp32_crypto_health_check(void);

// ================================
// Gestion des clés
// ================================

/**
 * @brief Génère une paire de clés ECDSA dans eFuse
 * 
 * @param key_id ID de la clé (0-3)
 * @param public_key Buffer pour la clé publique (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_generate_ecdsa_keypair(uint8_t key_id, uint8_t* public_key);

/**
 * @brief Obtient la clé publique depuis eFuse
 * 
 * @param key_id ID de la clé
 * @param public_key Buffer pour la clé publique (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_get_public_key(uint8_t key_id, uint8_t* public_key);

/**
 * @brief Programme une clé AES dans eFuse
 * 
 * @param key_id ID de la clé (0-3)
 * @param key_data Données de la clé AES (32 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_program_aes_key(uint8_t key_id, const uint8_t* key_data);

/**
 * @brief Obtient les informations d'une clé
 * 
 * @param key_id ID de la clé
 * @param key_info Structure d'informations sur la clé
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_get_key_info(uint8_t key_id, esp32_key_info_t* key_info);

// ================================
// Opérations cryptographiques
// ================================

/**
 * @brief Signe un message avec ECDSA
 * 
 * @param key_id ID de la clé privée dans eFuse
 * @param message_hash Hash SHA-256 du message (32 bytes)
 * @param signature Buffer pour la signature (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_ecdsa_sign(uint8_t key_id, const uint8_t* message_hash, uint8_t* signature);

/**
 * @brief Vérifie une signature ECDSA
 * 
 * @param public_key Clé publique ECDSA (64 bytes)
 * @param message_hash Hash SHA-256 du message (32 bytes)
 * @param signature Signature à vérifier (64 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si valide
 */
esp32_crypto_result_t esp32_crypto_ecdsa_verify(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature);

/**
 * @brief Génère des bytes aléatoires sécurisés avec TRNG
 * 
 * @param random_bytes Buffer pour les bytes aléatoires
 * @param length Nombre de bytes à générer
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_generate_random(uint8_t* random_bytes, size_t length);

/**
 * @brief Calcule un hash SHA-256 matériel
 * 
 * @param data Données à hasher
 * @param data_length Longueur des données
 * @param hash Buffer pour le hash (32 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_sha256(const uint8_t* data, size_t data_length, uint8_t* hash);

/**
 * @brief Chiffre des données avec AES-256-CBC matériel
 * 
 * @param key_id ID de la clé AES dans eFuse
 * @param iv Vecteur d'initialisation (16 bytes)
 * @param plaintext Données à chiffrer
 * @param plaintext_len Longueur des données
 * @param ciphertext Buffer pour les données chiffrées
 * @param ciphertext_len Pointeur vers la longueur résultat
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_aes_encrypt(uint8_t key_id, const uint8_t* iv, 
                                                const uint8_t* plaintext, size_t plaintext_len,
                                                uint8_t* ciphertext, size_t* ciphertext_len);

/**
 * @brief Déchiffre des données avec AES-256-CBC matériel
 * 
 * @param key_id ID de la clé AES dans eFuse
 * @param iv Vecteur d'initialisation (16 bytes)
 * @param ciphertext Données chiffrées
 * @param ciphertext_len Longueur des données chiffrées
 * @param plaintext Buffer pour les données déchiffrées
 * @param plaintext_len Pointeur vers la longueur résultat
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_aes_decrypt(uint8_t key_id, const uint8_t* iv,
                                                const uint8_t* ciphertext, size_t ciphertext_len,
                                                uint8_t* plaintext, size_t* plaintext_len);

/**
 * @brief Calcule un HMAC-SHA256
 * 
 * @param key_id ID de la clé HMAC dans eFuse
 * @param data Données à authentifier
 * @param data_length Longueur des données
 * @param hmac Buffer pour le HMAC (32 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_hmac_sha256(uint8_t key_id, const uint8_t* data, size_t data_length, uint8_t* hmac);

// ================================
// Secure Boot et Flash Encryption
// ================================

/**
 * @brief Active le Secure Boot v2
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_enable_secure_boot(void);

/**
 * @brief Active le chiffrement de la flash
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_enable_flash_encryption(void);

/**
 * @brief Vérifie l'état du Secure Boot
 * 
 * @return bool true si Secure Boot est activé
 */
bool esp32_crypto_is_secure_boot_enabled(void);

/**
 * @brief Vérifie l'état du chiffrement flash
 * 
 * @return bool true si chiffrement flash est activé
 */
bool esp32_crypto_is_flash_encryption_enabled(void);

// ================================
// Attestation et vérification
// ================================

/**
 * @brief Effectue une attestation de l'appareil ESP32
 * 
 * @param challenge Challenge reçu du vérifieur
 * @param challenge_size Taille du challenge
 * @param attestation Structure d'attestation à remplir
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_perform_attestation(const uint8_t* challenge, size_t challenge_size, 
                                                        esp32_attestation_t* attestation);

/**
 * @brief Vérifie l'intégrité du système crypto ESP32
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si intégrité OK
 */
esp32_crypto_result_t esp32_crypto_verify_integrity(void);

// ================================
// Gestion d'état et monitoring
// ================================

/**
 * @brief Met à jour le heartbeat dans les eFuses
 * 
 * @param counter Compteur de heartbeat
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_update_heartbeat(uint32_t counter);

/**
 * @brief Stocke l'état d'urgence dans la NVS
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_store_emergency_state(void);

/**
 * @brief Lit l'état d'urgence depuis la NVS
 * 
 * @param emergency_data Buffer pour les données d'urgence
 * @param data_size Taille du buffer
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_read_emergency_state(uint8_t* emergency_data, size_t data_size);

// ================================
// Utilitaires et debugging
// ================================

/**
 * @brief Convertit un code d'erreur en string
 * 
 * @param error Code d'erreur ESP32 crypto
 * @return const char* Description de l'erreur
 */
const char* esp32_crypto_error_to_string(esp32_crypto_result_t error);

/**
 * @brief Affiche les informations du crypto ESP32 (debug)
 */
void esp32_crypto_print_device_info(void);

/**
 * @brief Teste les fonctionnalités crypto de base
 * 
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS si tous les tests passent
 */
esp32_crypto_result_t esp32_crypto_self_test(void);

/**
 * @brief Obtient les statistiques d'utilisation
 * 
 * @param operations_count Nombre total d'opérations
 * @param error_count Nombre d'erreurs
 * @param last_operation_time Timestamp de la dernière opération
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_get_statistics(uint32_t* operations_count, uint32_t* error_count, 
                                                   uint64_t* last_operation_time);

/**
 * @brief Obtient l'ID unique de l'appareil (basé sur MAC)
 * 
 * @param device_id Buffer pour l'ID (6 bytes)
 * @return esp32_crypto_result_t ESP32_CRYPTO_SUCCESS en cas de succès
 */
esp32_crypto_result_t esp32_crypto_get_device_id(uint8_t* device_id);

#ifdef __cplusplus
}
#endif

#endif /* ESP32_CRYPTO_MANAGER_H */