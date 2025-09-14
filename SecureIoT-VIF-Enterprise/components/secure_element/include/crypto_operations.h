/**
 * @file crypto_operations.h
 * @brief Opérations cryptographiques Enterprise pour SecureIoT-VIF
 * 
 * Version Enterprise avec fonctionnalités avancées : ML crypto optimization,
 * performance monitoring, adaptive algorithms, compliance features.
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
#define CRYPTO_SHA512_DIGEST_SIZE       (64)    // Nouveau Enterprise
#define CRYPTO_AES_KEY_SIZE             (32)    // AES-256
#define CRYPTO_AES_IV_SIZE              (16)
#define CRYPTO_AES_BLOCK_SIZE           (16)
#define CRYPTO_HMAC_KEY_SIZE            (32)
#define CRYPTO_NONCE_SIZE               (16)
#define CRYPTO_SALT_SIZE                (32)    // Augmenté Enterprise
#define CRYPTO_DERIVED_KEY_SIZE         (32)

// Tailles pour les algorithmes ECC Enterprise
#define CRYPTO_ECC_PRIVATE_KEY_SIZE     (32)
#define CRYPTO_ECC_PUBLIC_KEY_SIZE      (64)
#define CRYPTO_ECC_SIGNATURE_SIZE       (64)
#define CRYPTO_ECC_SHARED_SECRET_SIZE   (32)
#define CRYPTO_ECC_COMPOSITE_KEY_SIZE   (96)    // Nouveau Enterprise

// Constantes Enterprise avancées
#define CRYPTO_ENTERPRISE_MAX_PARALLEL_OPS    (8)     // Opérations parallèles
#define CRYPTO_ENTERPRISE_PERFORMANCE_WINDOW (100)   // Fenêtre monitoring
#define CRYPTO_ENTERPRISE_ADAPTIVE_THRESHOLD (0.85f) // Seuil adaptation
#define CRYPTO_ENTERPRISE_ML_FEATURE_SIZE    (16)    // Vecteur ML

// ================================
// Types et énumérations Enterprise
// ================================

/**
 * @brief Types d'algorithmes de hachage Enterprise
 */
typedef enum {
    CRYPTO_HASH_SHA256 = 0,
    CRYPTO_HASH_SHA1,
    CRYPTO_HASH_MD5,
    // Nouveaux Enterprise
    CRYPTO_HASH_SHA512,
    CRYPTO_HASH_SHA3_256,
    CRYPTO_HASH_BLAKE2B,
    CRYPTO_HASH_ADAPTIVE       // Hash adaptatif basé performance
} crypto_hash_algorithm_t;

/**
 * @brief Types de chiffrement symétrique Enterprise
 */
typedef enum {
    CRYPTO_CIPHER_AES_256_CBC = 0,
    CRYPTO_CIPHER_AES_256_GCM,
    CRYPTO_CIPHER_AES_128_CBC,
    CRYPTO_CIPHER_AES_128_GCM,
    // Nouveaux Enterprise
    CRYPTO_CIPHER_AES_256_CTR,
    CRYPTO_CIPHER_AES_256_XTS,
    CRYPTO_CIPHER_CHACHA20_POLY1305,
    CRYPTO_CIPHER_ADAPTIVE       // Chiffrement adaptatif
} crypto_cipher_algorithm_t;

/**
 * @brief Modes d'opération KDF Enterprise
 */
typedef enum {
    CRYPTO_KDF_PBKDF2 = 0,
    CRYPTO_KDF_HKDF,
    CRYPTO_KDF_SCRYPT,
    // Nouveaux Enterprise
    CRYPTO_KDF_ARGON2,
    CRYPTO_KDF_ADAPTIVE,         // KDF adaptatif
    CRYPTO_KDF_ENTERPRISE_FAST   // KDF optimisé Enterprise
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
    // Nouveaux codes Enterprise
    CRYPTO_ERROR_PERFORMANCE_DEGRADED = -8,
    CRYPTO_ERROR_ADAPTIVE_FAILED = -9,
    CRYPTO_ERROR_ML_OPTIMIZATION_FAILED = -10,
    CRYPTO_ERROR_COMPLIANCE_VIOLATION = -11,
    CRYPTO_ERROR_PARALLEL_OPERATION_FAILED = -12,
    CRYPTO_ERROR_ENTERPRISE_LICENSE_INVALID = -13
} crypto_result_t;

/**
 * @brief Modes de performance Enterprise
 */
typedef enum {
    CRYPTO_PERFORMANCE_BALANCED = 0,
    CRYPTO_PERFORMANCE_SPEED_OPTIMIZED,
    CRYPTO_PERFORMANCE_SECURITY_OPTIMIZED,
    CRYPTO_PERFORMANCE_POWER_OPTIMIZED,
    CRYPTO_PERFORMANCE_ML_ADAPTIVE       // Nouveau Enterprise
} crypto_performance_mode_t;

// ================================
// Structures de données Enterprise
// ================================

/**
 * @brief Contexte pour les opérations de hachage Enterprise
 */
typedef struct {
    crypto_hash_algorithm_t algorithm;
    void* internal_ctx;
    uint8_t digest[CRYPTO_SHA512_DIGEST_SIZE];  // Augmenté Enterprise
    size_t digest_size;
    bool is_finalized;
    // Extensions Enterprise
    uint64_t start_time_us;
    uint32_t bytes_processed;
    crypto_performance_mode_t performance_mode;
    bool parallel_processing_enabled;
    uint8_t ml_optimization_level;
} crypto_hash_ctx_t;

/**
 * @brief Contexte pour le chiffrement symétrique Enterprise
 */
typedef struct {
    crypto_cipher_algorithm_t algorithm;
    uint8_t key[CRYPTO_AES_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    void* internal_ctx;
    bool is_encrypt;
    bool is_initialized;
    // Extensions Enterprise
    crypto_performance_mode_t performance_mode;
    bool hardware_acceleration_enabled;
    bool parallel_processing_enabled;
    uint32_t blocks_processed;
    uint64_t total_processing_time_us;
    float efficiency_score;
} crypto_cipher_ctx_t;

/**
 * @brief Paramètres KDF Enterprise avec optimisations
 */
typedef struct {
    crypto_kdf_algorithm_t algorithm;
    const uint8_t* password;
    size_t password_len;
    const uint8_t* salt;
    size_t salt_len;
    uint32_t iterations;
    size_t output_len;
    // Extensions Enterprise
    crypto_performance_mode_t performance_mode;
    uint8_t memory_cost_kb;           // Pour Argon2
    uint8_t parallelism;              // Parallélisme
    bool adaptive_iterations;         // Adaptation dynamique
    uint32_t target_time_ms;          // Temps cible
} crypto_kdf_params_t;

/**
 * @brief Structure pour les clés ECC Enterprise
 */
typedef struct {
    uint8_t private_key[CRYPTO_ECC_PRIVATE_KEY_SIZE];
    uint8_t public_key[CRYPTO_ECC_PUBLIC_KEY_SIZE];
    bool has_private;
    bool has_public;
    uint8_t curve_id;
    // Extensions Enterprise
    uint8_t key_strength_level;       // Niveau de robustesse
    uint64_t generation_time;         // Timestamp génération
    uint32_t usage_count;             // Compteur d'utilisation
    bool hardware_generated;          // Généré par HSM
    bool backup_available;            // Sauvegarde disponible
    uint8_t compliance_level;         // Niveau conformité
} crypto_ecc_keypair_t;

/**
 * @brief Structure pour les signatures ECC Enterprise
 */
typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t signature[CRYPTO_ECC_SIGNATURE_SIZE];
    bool is_valid;
    // Extensions Enterprise
    uint8_t signature_algorithm;      // Algorithme utilisé
    uint64_t generation_time;         // Timestamp signature
    uint32_t verification_count;      // Nb vérifications
    float confidence_score;           // Score confiance ML
    bool hardware_signed;             // Signé par HSM
    uint8_t performance_metrics;      // Métriques perf
} crypto_ecc_signature_t;

/**
 * @brief Métriques de performance crypto Enterprise
 */
typedef struct {
    uint32_t operations_per_second;
    uint32_t average_latency_us;
    uint32_t peak_latency_us;
    uint32_t throughput_mbps;
    float cpu_utilization_percent;
    float power_efficiency_score;
    uint32_t cache_hit_ratio;
    uint32_t error_rate_ppm;
    // Spécifique Enterprise
    uint32_t ml_optimization_gain_percent;
    uint32_t adaptive_algorithm_switches;
    float compliance_score;
} crypto_performance_metrics_t;

/**
 * @brief Configuration ML crypto Enterprise
 */
typedef struct {
    bool enable_adaptive_algorithms;
    bool enable_performance_prediction;
    bool enable_security_analysis;
    uint8_t learning_rate_percent;
    uint32_t analysis_window_ms;
    float optimization_threshold;
    uint8_t feature_extraction_level;
} crypto_ml_config_t;

// ================================
// Fonctions de hachage Enterprise
// ================================

/**
 * @brief Initialise un contexte de hachage Enterprise
 * @param ctx Contexte de hachage
 * @param algorithm Algorithme de hachage
 * @param performance_mode Mode de performance
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_init_enterprise(crypto_hash_ctx_t* ctx, 
                                           crypto_hash_algorithm_t algorithm,
                                           crypto_performance_mode_t performance_mode);

/**
 * @brief Hachage parallèle Enterprise pour gros volumes
 * @param algorithm Algorithme de hachage
 * @param data Données à hacher
 * @param data_len Longueur des données
 * @param digest Buffer pour le digest
 * @param digest_len Pointeur vers la longueur du digest
 * @param num_threads Nombre de threads parallèles
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_compute_parallel(crypto_hash_algorithm_t algorithm,
                                            const uint8_t* data, size_t data_len,
                                            uint8_t* digest, size_t* digest_len,
                                            uint8_t num_threads);

/**
 * @brief Hachage adaptatif basé ML Enterprise
 * @param data Données à hacher
 * @param data_len Longueur des données
 * @param digest Buffer pour le digest
 * @param digest_len Pointeur vers la longueur du digest
 * @param ml_config Configuration ML
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_hash_adaptive_ml(const uint8_t* data, size_t data_len,
                                       uint8_t* digest, size_t* digest_len,
                                       const crypto_ml_config_t* ml_config);

// ================================
// Fonctions de chiffrement Enterprise
// ================================

/**
 * @brief Chiffrement parallèle Enterprise haute performance
 * @param algorithm Algorithme de chiffrement
 * @param key Clé de chiffrement
 * @param key_len Longueur de la clé
 * @param iv Vecteur d'initialisation
 * @param input Données d'entrée
 * @param input_len Longueur des données d'entrée
 * @param output Buffer de sortie
 * @param output_len Pointeur vers la longueur de sortie
 * @param num_threads Nombre de threads parallèles
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_cipher_encrypt_parallel(crypto_cipher_algorithm_t algorithm,
                                              const uint8_t* key, size_t key_len,
                                              const uint8_t* iv,
                                              const uint8_t* input, size_t input_len,
                                              uint8_t* output, size_t* output_len,
                                              uint8_t num_threads);

/**
 * @brief Chiffrement adaptatif avec optimisation ML
 * @param input Données d'entrée
 * @param input_len Longueur des données d'entrée
 * @param output Buffer de sortie
 * @param output_len Pointeur vers la longueur de sortie
 * @param key Clé de chiffrement
 * @param key_len Longueur de la clé
 * @param ml_config Configuration ML
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_cipher_adaptive_encrypt(const uint8_t* input, size_t input_len,
                                              uint8_t* output, size_t* output_len,
                                              const uint8_t* key, size_t key_len,
                                              const crypto_ml_config_t* ml_config);

// ================================
// Fonctions ECC Enterprise avancées
// ================================

/**
 * @brief Génération de clés ECC avec optimisation ML
 * @param slot_id Slot du crypto ESP32
 * @param keypair Structure pour stocker les clés
 * @param strength_level Niveau de robustesse requis (1-5)
 * @param compliance_level Niveau de conformité requis
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_ecc_generate_keypair_enterprise(uint8_t slot_id, 
                                                      crypto_ecc_keypair_t* keypair,
                                                      uint8_t strength_level,
                                                      uint8_t compliance_level);

/**
 * @brief Signature ECC avec analyse comportementale ML
 * @param slot_id Slot contenant la clé privée
 * @param data Données à signer
 * @param data_len Longueur des données
 * @param signature Structure pour la signature
 * @param behavioral_analysis Activer l'analyse comportementale
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_ecc_sign_behavioral(uint8_t slot_id, 
                                          const uint8_t* data, size_t data_len,
                                          crypto_ecc_signature_t* signature,
                                          bool behavioral_analysis);

/**
 * @brief Vérification ECC avec scoring de confiance ML
 * @param public_key Clé publique pour la vérification
 * @param data Données originales
 * @param data_len Longueur des données
 * @param signature Signature à vérifier
 * @param confidence_score Pointeur vers le score de confiance
 * @return crypto_result_t CRYPTO_SUCCESS si la signature est valide
 */
crypto_result_t crypto_ecc_verify_with_confidence(const uint8_t* public_key,
                                                 const uint8_t* data, size_t data_len,
                                                 const crypto_ecc_signature_t* signature,
                                                 float* confidence_score);

// ================================
// Fonctions de monitoring Enterprise
// ================================

/**
 * @brief Obtient les métriques de performance crypto
 * @param metrics Structure pour les métriques
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_get_performance_metrics(crypto_performance_metrics_t* metrics);

/**
 * @brief Optimisation automatique basée ML
 * @param target_performance Performance cible
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_ml_auto_optimization(float target_performance);

/**
 * @brief Analyse prédictive des performances
 * @param workload_pattern Pattern de charge de travail
 * @param predicted_performance Performance prédite
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_predictive_analysis(const uint8_t* workload_pattern,
                                          crypto_performance_metrics_t* predicted_performance);

// ================================
// Fonctions de conformité Enterprise
// ================================

/**
 * @brief Vérification de conformité cryptographique
 * @param compliance_standard Standard de conformité (FIPS, CC, etc.)
 * @param compliance_level Niveau de conformité atteint
 * @return crypto_result_t CRYPTO_SUCCESS si conforme
 */
crypto_result_t crypto_compliance_check(uint8_t compliance_standard,
                                       uint8_t* compliance_level);

/**
 * @brief Audit cryptographique automatique
 * @param audit_report Buffer pour le rapport d'audit
 * @param report_size Taille du buffer de rapport
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_security_audit(uint8_t* audit_report, size_t report_size);

// ================================
// Fonctions Enterprise avancées
// ================================

/**
 * @brief Test de performance crypto complet Enterprise
 * @param performance_metrics Métriques de performance obtenues
 * @return crypto_result_t CRYPTO_SUCCESS si tous les tests passent
 */
crypto_result_t crypto_performance_test_enterprise(crypto_performance_metrics_t* performance_metrics);

/**
 * @brief Configuration du système ML crypto
 * @param ml_config Configuration ML
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_configure_ml_system(const crypto_ml_config_t* ml_config);

/**
 * @brief Entraînement du modèle ML crypto
 * @param training_data Données d'entraînement
 * @param data_size Taille des données
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_train_ml_model(const uint8_t* training_data, size_t data_size);

// ================================
// Fonctions utilitaires Enterprise
// ================================

/**
 * @brief Convertit un résultat crypto en string détaillée
 * @param result Code de résultat
 * @return const char* Description détaillée du résultat
 */
const char* crypto_result_to_string_enterprise(crypto_result_t result);

/**
 * @brief Obtient la version et les capacités Enterprise
 * @param version_info Buffer pour les informations de version
 * @param info_size Taille du buffer
 * @return crypto_result_t CRYPTO_SUCCESS en cas de succès
 */
crypto_result_t crypto_get_enterprise_info(char* version_info, size_t info_size);

// ================================
// Macros de compatibilité
// ================================

// Maintient la compatibilité avec les versions Community/Full
#define crypto_init() crypto_init_enterprise()
#define crypto_hash_init(ctx, alg) crypto_hash_init_enterprise(ctx, alg, CRYPTO_PERFORMANCE_BALANCED)
#define crypto_hash_compute(alg, data, len, digest, digest_len) crypto_hash_compute_parallel(alg, data, len, digest, digest_len, 1)
#define crypto_ecc_generate_keypair_se(slot, keypair) crypto_ecc_generate_keypair_enterprise(slot, keypair, 3, 2)
#define crypto_ecc_sign_se(slot, data, len, sig) crypto_ecc_sign_behavioral(slot, data, len, sig, false)
#define crypto_ecc_verify(key, data, len, sig) crypto_ecc_verify_with_confidence(key, data, len, sig, NULL)
#define crypto_performance_test() crypto_performance_test_enterprise(NULL)

// Fonctions supplémentaires Enterprise
crypto_result_t crypto_init_enterprise(void);
void crypto_deinit_enterprise(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_OPERATIONS_H */