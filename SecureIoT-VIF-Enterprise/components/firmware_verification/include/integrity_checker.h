/**
 * @file integrity_checker.h
 * @brief Vérificateur d'intégrité du firmware pour SecureIoT-VIF Enterprise Edition
 * 
 * Ce module implémente la vérification d'intégrité continue du firmware,
 * une fonctionnalité unique qui permet de détecter les modifications
 * non autorisées pendant l'exécution du système.
 * 
 * Version Enterprise : Support complet temps réel, ML adaptatif, HSM intégré
 * 
 * @author Framework SecureIoT-VIF Enterprise
 * @version 2.0.0 Enterprise
 * @date 2025
 */

#ifndef INTEGRITY_CHECKER_H
#define INTEGRITY_CHECKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

// ================================
// Constantes et définitions Enterprise
// ================================

#define INTEGRITY_SIGNATURE_SIZE        (64)    // Signature ECC P-256
#define INTEGRITY_HASH_SIZE             (32)    // SHA-256
#define INTEGRITY_CHUNK_SIZE            (4096)  // Taille des chunks de vérification
#define INTEGRITY_MAX_CHUNKS            (512)   // Nombre max de chunks (Enterprise: 2x)
#define INTEGRITY_METADATA_SIZE         (256)   // Métadonnées d'intégrité (Enterprise: 2x)

// Types de vérification d'intégrité Enterprise
#define INTEGRITY_TYPE_FULL             (0x01)  // Vérification complète
#define INTEGRITY_TYPE_INCREMENTAL      (0x02)  // Vérification par chunks
#define INTEGRITY_TYPE_CRITICAL_ONLY    (0x04)  // Sections critiques uniquement
#define INTEGRITY_TYPE_RUNTIME          (0x08)  // Vérification en temps réel
#define INTEGRITY_TYPE_PREDICTIVE       (0x10)  // Vérification prédictive Enterprise
#define INTEGRITY_TYPE_ML_ASSISTED      (0x20)  // Vérification assistée par ML Enterprise
#define INTEGRITY_TYPE_HSM_VERIFIED     (0x40)  // Vérification via HSM Enterprise
#define INTEGRITY_TYPE_CONTINUOUS       (0x80)  // Vérification continue Enterprise

// Niveaux de priorité pour la vérification Enterprise
#define INTEGRITY_PRIORITY_EMERGENCY    (0)     // Urgence Enterprise
#define INTEGRITY_PRIORITY_CRITICAL     (1)
#define INTEGRITY_PRIORITY_HIGH         (2)
#define INTEGRITY_PRIORITY_MEDIUM       (3)
#define INTEGRITY_PRIORITY_LOW          (4)
#define INTEGRITY_PRIORITY_BACKGROUND   (5)     // Arrière-plan Enterprise

// ================================
// Types et énumérations Enterprise
// ================================

/**
 * @brief États de l'intégrité Enterprise
 */
typedef enum {
    INTEGRITY_OK = 0,                   // Intégrité validée
    INTEGRITY_ERROR_CORRUPTED = -1,     // Corruption détectée
    INTEGRITY_ERROR_SIGNATURE = -2,     // Signature invalide
    INTEGRITY_ERROR_HASH_MISMATCH = -3, // Hash ne correspond pas
    INTEGRITY_ERROR_METADATA = -4,      // Métadonnées corrompues
    INTEGRITY_ERROR_NOT_INITIALIZED = -5, // Non initialisé
    INTEGRITY_ERROR_MEMORY = -6,        // Erreur mémoire
    INTEGRITY_ERROR_FLASH_READ = -7,    // Erreur lecture flash
    INTEGRITY_ERROR_TIMEOUT = -8,       // Timeout de vérification
    INTEGRITY_ERROR_HSM_FAILURE = -9,   // Échec HSM Enterprise
    INTEGRITY_ERROR_ML_ANOMALY = -10,   // Anomalie ML détectée Enterprise
    INTEGRITY_ERROR_TAMPERING = -11,    // Tentative de sabotage Enterprise
    INTEGRITY_ERROR_EFUSE_INVALID = -12, // eFuse invalide Enterprise
    INTEGRITY_ERROR_ATTESTATION_FAILED = -13, // Échec attestation Enterprise
    INTEGRITY_ERROR_UNKNOWN = -14       // Erreur inconnue
} integrity_status_t;

/**
 * @brief Types de sections du firmware Enterprise
 */
typedef enum {
    FIRMWARE_SECTION_BOOTLOADER = 0,    // Section bootloader
    FIRMWARE_SECTION_APP,               // Section application
    FIRMWARE_SECTION_PARTITION_TABLE,   // Table des partitions
    FIRMWARE_SECTION_CONFIG,            // Configuration
    FIRMWARE_SECTION_DATA,              // Données
    FIRMWARE_SECTION_CUSTOM,            // Section personnalisée
    FIRMWARE_SECTION_SECURE_BOOT,       // Secure Boot Enterprise
    FIRMWARE_SECTION_FLASH_ENCRYPTION,  // Flash Encryption Enterprise
    FIRMWARE_SECTION_EFUSE_CONFIG,      // Configuration eFuse Enterprise
    FIRMWARE_SECTION_HSM_KEYS,          // Clés HSM Enterprise
    FIRMWARE_SECTION_MAX
} firmware_section_type_t;

/**
 * @brief Méthodes de vérification Enterprise
 */
typedef enum {
    INTEGRITY_METHOD_HASH = 0,          // Vérification par hash uniquement
    INTEGRITY_METHOD_SIGNATURE,         // Vérification par signature
    INTEGRITY_METHOD_MAC,               // Vérification par MAC
    INTEGRITY_METHOD_HYBRID,            // Combinaison de méthodes
    INTEGRITY_METHOD_HSM_ACCELERATED,   // Accélération HSM Enterprise
    INTEGRITY_METHOD_ML_ENHANCED,       // ML amélioré Enterprise
    INTEGRITY_METHOD_ATTESTATION_BASED, // Basé attestation Enterprise
    INTEGRITY_METHOD_CONTINUOUS_MONITOR // Monitoring continu Enterprise
} integrity_method_t;

// ================================
// Structures de données Enterprise
// ================================

/**
 * @brief Informations sur un chunk de firmware Enterprise
 */
typedef struct {
    uint32_t chunk_id;                  // Identifiant du chunk
    uint32_t start_address;             // Adresse de début
    uint32_t size;                      // Taille du chunk
    uint8_t hash[INTEGRITY_HASH_SIZE];  // Hash du chunk
    uint8_t signature[INTEGRITY_SIGNATURE_SIZE]; // Signature du chunk
    firmware_section_type_t section_type; // Type de section
    uint8_t priority;                   // Priorité de vérification
    uint32_t last_check_time;           // Dernière vérification
    uint32_t check_count;               // Nombre de vérifications
    bool is_critical;                   // Section critique
    bool is_verified;                   // État de vérification
    // Extensions Enterprise
    bool is_hsm_protected;              // Protection HSM Enterprise
    bool is_ml_monitored;               // Monitoring ML Enterprise
    uint8_t security_level;             // Niveau sécurité Enterprise
    uint32_t prediction_score;          // Score prédiction ML Enterprise
    uint64_t last_attestation_time;     // Dernière attestation Enterprise
    uint8_t efuse_key_slot;             // Slot clé eFuse Enterprise
} integrity_chunk_info_t;

/**
 * @brief Métadonnées d'intégrité du firmware Enterprise
 */
typedef struct {
    uint32_t magic;                     // Nombre magique pour validation
    uint32_t version;                   // Version des métadonnées
    uint32_t firmware_size;             // Taille totale du firmware
    uint32_t chunk_count;               // Nombre de chunks
    uint32_t chunk_size;                // Taille standard des chunks
    uint8_t global_hash[INTEGRITY_HASH_SIZE]; // Hash global du firmware
    uint8_t global_signature[INTEGRITY_SIGNATURE_SIZE]; // Signature globale
    integrity_method_t verification_method; // Méthode de vérification
    uint32_t timestamp;                 // Timestamp de création
    uint32_t build_id;                  // Identifiant de build
    uint32_t checksum;                  // Checksum des métadonnées
    // Extensions Enterprise
    uint32_t enterprise_version;        // Version Enterprise
    uint8_t hsm_key_fingerprint[32];    // Empreinte clé HSM Enterprise
    uint32_t ml_model_version;          // Version modèle ML Enterprise
    uint64_t attestation_timestamp;     // Timestamp attestation Enterprise
    uint8_t security_policy_hash[32];   // Hash politique sécurité Enterprise
    uint32_t efuse_config_hash;         // Hash configuration eFuse Enterprise
} integrity_metadata_t;

/**
 * @brief Configuration du vérificateur d'intégrité Enterprise
 */
typedef struct {
    bool enable_runtime_check;          // Vérification en temps réel
    bool enable_incremental_check;      // Vérification incrémentale
    bool enable_critical_only;          // Vérifier sections critiques uniquement
    uint32_t check_interval_ms;         // Intervalle entre vérifications
    uint32_t chunk_size;                // Taille des chunks
    uint8_t max_concurrent_checks;      // Vérifications simultanées max
    integrity_method_t preferred_method; // Méthode préférée
    uint8_t signature_key_slot;         // Slot de clé de signature
    uint8_t mac_key_slot;               // Slot de clé MAC
    // Extensions Enterprise
    bool enable_hsm_acceleration;       // Accélération HSM Enterprise
    bool enable_ml_prediction;          // Prédiction ML Enterprise
    bool enable_continuous_attestation; // Attestation continue Enterprise
    bool enable_tamper_detection;       // Détection sabotage Enterprise
    uint8_t enterprise_security_level;  // Niveau sécurité Enterprise (1-5)
    uint32_t ml_learning_rate;          // Taux apprentissage ML Enterprise
    uint32_t attestation_interval_ms;   // Intervalle attestation Enterprise
    uint8_t efuse_key_slots[8];         // Slots clés eFuse Enterprise
} integrity_config_t;

/**
 * @brief Résultat de vérification d'intégrité Enterprise
 */
typedef struct {
    integrity_status_t status;          // État global
    uint32_t total_chunks;              // Nombre total de chunks
    uint32_t verified_chunks;           // Chunks vérifiés
    uint32_t failed_chunks;             // Chunks en échec
    uint32_t corrupted_chunks;          // Chunks corrompus
    uint32_t verification_time_ms;      // Temps de vérification
    uint32_t failed_chunk_ids[16];      // IDs des chunks en échec
    uint8_t failed_count;               // Nombre de chunks en échec
    bool has_corruption;                // Corruption détectée
    bool signature_valid;               // Signature globale valide
    // Extensions Enterprise
    bool hsm_verification_success;      // Vérification HSM réussie Enterprise
    bool ml_anomaly_detected;           // Anomalie ML détectée Enterprise
    bool attestation_valid;             // Attestation valide Enterprise
    bool tamper_detected;               // Sabotage détecté Enterprise
    uint32_t security_score;            // Score sécurité Enterprise
    uint32_t ml_confidence_score;       // Score confiance ML Enterprise
    uint64_t attestation_timestamp;     // Timestamp attestation Enterprise
    uint8_t threat_level;               // Niveau menace Enterprise
} integrity_result_t;

/**
 * @brief Statistiques du vérificateur d'intégrité Enterprise
 */
typedef struct {
    uint32_t total_checks;              // Nombre total de vérifications
    uint32_t successful_checks;         // Vérifications réussies
    uint32_t failed_checks;             // Vérifications échouées
    uint32_t corruption_detections;     // Détections de corruption
    uint64_t total_check_time_us;       // Temps total de vérification
    uint64_t last_full_check_time;      // Dernière vérification complète
    uint32_t avg_check_time_ms;         // Temps moyen de vérification
    uint32_t max_check_time_ms;         // Temps max de vérification
    uint32_t min_check_time_ms;         // Temps min de vérification
    // Extensions Enterprise
    uint32_t hsm_accelerated_checks;    // Vérifications HSM Enterprise
    uint32_t ml_predictions_made;       // Prédictions ML Enterprise
    uint32_t attestations_performed;    // Attestations effectuées Enterprise
    uint32_t tamper_attempts_detected;  // Tentatives sabotage Enterprise
    uint64_t total_hsm_time_us;         // Temps total HSM Enterprise
    uint64_t total_ml_time_us;          // Temps total ML Enterprise
    uint32_t false_positive_rate;       // Taux faux positifs Enterprise
    uint32_t threat_detections;         // Détections menaces Enterprise
} integrity_stats_t;

// ================================
// Fonctions principales Enterprise
// ================================

/**
 * @brief Initialise le vérificateur d'intégrité Enterprise
 * 
 * @param config Configuration du vérificateur (NULL pour config par défaut)
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_checker_init(const integrity_config_t* config);

/**
 * @brief Dé-initialise le vérificateur d'intégrité Enterprise
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_checker_deinit(void);

/**
 * @brief Effectue une vérification complète du firmware Enterprise
 * 
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_firmware(void);

/**
 * @brief Effectue une vérification complète avec résultat détaillé Enterprise
 * 
 * @param result Structure pour le résultat détaillé
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_firmware_detailed(integrity_result_t* result);

/**
 * @brief Vérifie l'intégrité d'un chunk spécifique Enterprise
 * 
 * @param chunk_id Identifiant du chunk
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_chunk(uint32_t chunk_id);

/**
 * @brief Vérifie les sections critiques uniquement Enterprise
 * 
 * @param result Résultat de la vérification
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_critical_sections(integrity_result_t* result);

// ================================
// Fonctions Enterprise Avancées
// ================================

/**
 * @brief Vérification temps réel avec accélération HSM Enterprise
 * 
 * @param result Résultat de la vérification
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_realtime_hsm(integrity_result_t* result);

/**
 * @brief Vérification avec prédiction ML Enterprise
 * 
 * @param chunk_id Identifiant du chunk
 * @param prediction_score Score de prédiction ML
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_ml_assisted(uint32_t chunk_id, uint32_t* prediction_score);

/**
 * @brief Vérification avec attestation continue Enterprise
 * 
 * @param attestation_data Données d'attestation
 * @param result Résultat de la vérification
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_with_attestation(uint8_t* attestation_data, integrity_result_t* result);

/**
 * @brief Détection de tentatives de sabotage Enterprise
 * 
 * @param tamper_level Niveau de sabotage détecté
 * @return integrity_status_t État de détection
 */
integrity_status_t integrity_detect_tampering(uint8_t* tamper_level);

// ================================
// Gestion des métadonnées Enterprise
// ================================

/**
 * @brief Initialise les métadonnées d'intégrité du firmware Enterprise
 * 
 * @param firmware_start Adresse de début du firmware
 * @param firmware_size Taille du firmware
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_init_metadata(uint32_t firmware_start, uint32_t firmware_size);

/**
 * @brief Lit les métadonnées d'intégrité depuis la flash Enterprise
 * 
 * @param metadata Structure pour les métadonnées
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_read_metadata(integrity_metadata_t* metadata);

/**
 * @brief Écrit les métadonnées d'intégrité dans la flash Enterprise
 * 
 * @param metadata Métadonnées à écrire
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_write_metadata(const integrity_metadata_t* metadata);

/**
 * @brief Valide les métadonnées d'intégrité Enterprise
 * 
 * @param metadata Métadonnées à valider
 * @return bool true si valides
 */
bool integrity_validate_metadata(const integrity_metadata_t* metadata);

/**
 * @brief Met à jour les métadonnées avec informations HSM Enterprise
 * 
 * @param metadata Métadonnées à mettre à jour
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_update_metadata_hsm(integrity_metadata_t* metadata);

// ================================
// Gestion des chunks Enterprise
// ================================

/**
 * @brief Génère les informations de chunks pour le firmware Enterprise
 * 
 * @param firmware_start Adresse de début du firmware
 * @param firmware_size Taille du firmware
 * @param chunk_size Taille des chunks
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_generate_chunks(uint32_t firmware_start, uint32_t firmware_size, uint32_t chunk_size);

/**
 * @brief Obtient les informations d'un chunk Enterprise
 * 
 * @param chunk_id Identifiant du chunk
 * @param chunk_info Structure pour les informations
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_get_chunk_info(uint32_t chunk_id, integrity_chunk_info_t* chunk_info);

/**
 * @brief Met à jour les informations d'un chunk après vérification Enterprise
 * 
 * @param chunk_id Identifiant du chunk
 * @param is_verified État de vérification
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_update_chunk_status(uint32_t chunk_id, bool is_verified);

/**
 * @brief Obtient le nombre total de chunks Enterprise
 * 
 * @return uint32_t Nombre de chunks
 */
uint32_t integrity_get_chunk_count(void);

/**
 * @brief Marque un chunk comme protégé par HSM Enterprise
 * 
 * @param chunk_id Identifiant du chunk
 * @param key_slot Slot de clé eFuse
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_mark_chunk_hsm_protected(uint32_t chunk_id, uint8_t key_slot);

// ================================
// Vérification en temps réel Enterprise
// ================================

/**
 * @brief Démarre la vérification d'intégrité en temps réel Enterprise
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_start_runtime_check(void);

/**
 * @brief Arrête la vérification d'intégrité en temps réel Enterprise
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_stop_runtime_check(void);

/**
 * @brief Vérifie si la vérification en temps réel est active Enterprise
 * 
 * @return bool true si active
 */
bool integrity_is_runtime_check_active(void);

/**
 * @brief Effectue une vérification incrémentale Enterprise
 * 
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_incremental_check(void);

/**
 * @brief Démarre la vérification continue avec ML Enterprise
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_start_continuous_ml_check(void);

/**
 * @brief Démarre l'attestation continue Enterprise
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_start_continuous_attestation(void);

// ================================
// Détection de corruption Enterprise
// ================================

/**
 * @brief Détecte la corruption mémoire en temps réel Enterprise
 * 
 * @param address Adresse à vérifier
 * @param size Taille de la zone
 * @return bool true si corruption détectée
 */
bool integrity_detect_memory_corruption(uint32_t address, size_t size);

/**
 * @brief Analyse une corruption détectée avec ML Enterprise
 * 
 * @param chunk_id Identifiant du chunk corrompu
 * @param corruption_type Type de corruption détectée
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_analyze_corruption(uint32_t chunk_id, uint8_t* corruption_type);

/**
 * @brief Tente de récupérer d'une corruption Enterprise
 * 
 * @param chunk_id Identifiant du chunk corrompu
 * @return esp_err_t ESP_OK si récupération possible
 */
esp_err_t integrity_recover_from_corruption(uint32_t chunk_id);

/**
 * @brief Détection prédictive de corruption avec ML Enterprise
 * 
 * @param chunk_id Identifiant du chunk
 * @param risk_score Score de risque prédictif
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_predict_corruption_risk(uint32_t chunk_id, uint32_t* risk_score);

// ================================
// Configuration et monitoring Enterprise
// ================================

/**
 * @brief Configure la vérification d'intégrité Enterprise
 * 
 * @param config Nouvelle configuration
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_configure(const integrity_config_t* config);

/**
 * @brief Obtient la configuration actuelle Enterprise
 * 
 * @param config Structure pour la configuration
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_get_config(integrity_config_t* config);

/**
 * @brief Obtient les statistiques de vérification Enterprise
 * 
 * @param stats Structure pour les statistiques
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_get_statistics(integrity_stats_t* stats);

/**
 * @brief Remet à zéro les statistiques Enterprise
 */
void integrity_reset_statistics(void);

/**
 * @brief Configure le niveau de sécurité Enterprise (1-5)
 * 
 * @param security_level Niveau de sécurité
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_set_security_level(uint8_t security_level);

// ================================
// Fonctions de callback Enterprise
// ================================

/**
 * @brief Type de callback pour les événements d'intégrité Enterprise
 * 
 * @param status État de l'intégrité
 * @param chunk_id Identifiant du chunk (si applicable)
 * @param user_data Données utilisateur
 */
typedef void (*integrity_event_callback_t)(integrity_status_t status, uint32_t chunk_id, void* user_data);

/**
 * @brief Type de callback spécialisé pour les menaces Enterprise
 * 
 * @param threat_level Niveau de menace
 * @param threat_type Type de menace
 * @param affected_chunks Chunks affectés
 * @param user_data Données utilisateur
 */
typedef void (*integrity_threat_callback_t)(uint8_t threat_level, uint8_t threat_type, uint32_t* affected_chunks, void* user_data);

/**
 * @brief Enregistre un callback pour les événements d'intégrité Enterprise
 * 
 * @param callback Fonction de callback
 * @param user_data Données utilisateur à passer au callback
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_register_callback(integrity_event_callback_t callback, void* user_data);

/**
 * @brief Enregistre un callback pour les menaces Enterprise
 * 
 * @param callback Fonction de callback spécialisée
 * @param user_data Données utilisateur
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_register_threat_callback(integrity_threat_callback_t callback, void* user_data);

/**
 * @brief Désenregistre le callback d'événements
 */
void integrity_unregister_callback(void);

// ================================
// Utilitaires et debugging Enterprise
// ================================

/**
 * @brief Convertit un statut d'intégrité en string Enterprise
 * 
 * @param status Statut d'intégrité
 * @return const char* Description du statut
 */
const char* integrity_status_to_string(integrity_status_t status);

/**
 * @brief Affiche les informations de vérification d'intégrité Enterprise
 */
void integrity_print_info(void);

/**
 * @brief Affiche les statistiques détaillées Enterprise
 */
void integrity_print_statistics(void);

/**
 * @brief Test complet du système de vérification d'intégrité Enterprise
 * 
 * @return integrity_status_t INTEGRITY_OK si tous les tests passent
 */
integrity_status_t integrity_self_test(void);

/**
 * @brief Benchmark de performance du vérificateur d'intégrité Enterprise
 * 
 * @param iterations Nombre d'itérations pour le test
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_benchmark(uint32_t iterations);

/**
 * @brief Force une vérification d'urgence Enterprise
 * 
 * @return integrity_status_t État de l'intégrité
 */
integrity_status_t integrity_emergency_check(void);

/**
 * @brief Test de stress du système d'intégrité Enterprise
 * 
 * @param duration_ms Durée du test en millisecondes
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_stress_test(uint32_t duration_ms);

/**
 * @brief Génère un rapport de sécurité complet Enterprise
 * 
 * @param report_buffer Buffer pour le rapport
 * @param buffer_size Taille du buffer
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_generate_security_report(char* report_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* INTEGRITY_CHECKER_H */