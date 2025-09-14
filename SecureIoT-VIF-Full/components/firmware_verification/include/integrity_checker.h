/**
 * @file integrity_checker.h
 * @brief Vérificateur d'intégrité du firmware pour SecureIoT-VIF
 * 
 * Ce module implémente la vérification d'intégrité continue du firmware,
 * une fonctionnalité unique qui permet de détecter les modifications
 * non autorisées pendant l'exécution du système.
 * 
 * @author Framework SecureIoT-VIF
 * @version 1.0.0
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
// Constantes et définitions
// ================================

#define INTEGRITY_SIGNATURE_SIZE        (64)    // Signature ECC P-256
#define INTEGRITY_HASH_SIZE             (32)    // SHA-256
#define INTEGRITY_CHUNK_SIZE            (4096)  // Taille des chunks de vérification
#define INTEGRITY_MAX_CHUNKS            (256)   // Nombre max de chunks
#define INTEGRITY_METADATA_SIZE         (128)   // Métadonnées d'intégrité

// Types de vérification d'intégrité
#define INTEGRITY_TYPE_FULL             (0x01)  // Vérification complète
#define INTEGRITY_TYPE_INCREMENTAL      (0x02)  // Vérification par chunks
#define INTEGRITY_TYPE_CRITICAL_ONLY    (0x04)  // Sections critiques uniquement
#define INTEGRITY_TYPE_RUNTIME          (0x08)  // Vérification en temps réel

// Niveaux de priorité pour la vérification
#define INTEGRITY_PRIORITY_CRITICAL     (1)
#define INTEGRITY_PRIORITY_HIGH         (2)
#define INTEGRITY_PRIORITY_MEDIUM       (3)
#define INTEGRITY_PRIORITY_LOW          (4)

// ================================
// Types et énumérations
// ================================

/**
 * @brief États de l'intégrité
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
    INTEGRITY_ERROR_UNKNOWN = -9        // Erreur inconnue
} integrity_status_t;

/**
 * @brief Types de sections du firmware
 */
typedef enum {
    FIRMWARE_SECTION_BOOTLOADER = 0,    // Section bootloader
    FIRMWARE_SECTION_APP,               // Section application
    FIRMWARE_SECTION_PARTITION_TABLE,   // Table des partitions
    FIRMWARE_SECTION_CONFIG,            // Configuration
    FIRMWARE_SECTION_DATA,              // Données
    FIRMWARE_SECTION_CUSTOM,            // Section personnalisée
    FIRMWARE_SECTION_MAX
} firmware_section_type_t;

/**
 * @brief Méthodes de vérification
 */
typedef enum {
    INTEGRITY_METHOD_HASH = 0,          // Vérification par hash uniquement
    INTEGRITY_METHOD_SIGNATURE,         // Vérification par signature
    INTEGRITY_METHOD_MAC,               // Vérification par MAC
    INTEGRITY_METHOD_HYBRID            // Combinaison de méthodes
} integrity_method_t;

// ================================
// Structures de données
// ================================

/**
 * @brief Informations sur un chunk de firmware
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
} integrity_chunk_info_t;

/**
 * @brief Métadonnées d'intégrité du firmware
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
} integrity_metadata_t;

/**
 * @brief Configuration du vérificateur d'intégrité
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
} integrity_config_t;

/**
 * @brief Résultat de vérification d'intégrité
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
} integrity_result_t;

/**
 * @brief Statistiques du vérificateur d'intégrité
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
} integrity_stats_t;

// ================================
// Fonctions principales
// ================================

/**
 * @brief Initialise le vérificateur d'intégrité
 * 
 * @param config Configuration du vérificateur (NULL pour config par défaut)
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_checker_init(const integrity_config_t* config);

/**
 * @brief Dé-initialise le vérificateur d'intégrité
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_checker_deinit(void);

/**
 * @brief Effectue une vérification complète du firmware
 * 
 * @param result Résultat de la vérification
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_firmware(void);

/**
 * @brief Effectue une vérification complète avec résultat détaillé
 * 
 * @param result Structure pour le résultat détaillé
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_firmware_detailed(integrity_result_t* result);

/**
 * @brief Vérifie l'intégrité d'un chunk spécifique
 * 
 * @param chunk_id Identifiant du chunk
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_chunk(uint32_t chunk_id);

/**
 * @brief Vérifie les sections critiques uniquement
 * 
 * @param result Résultat de la vérification
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_check_critical_sections(integrity_result_t* result);

// ================================
// Gestion des métadonnées
// ================================

/**
 * @brief Initialise les métadonnées d'intégrité du firmware
 * 
 * @param firmware_start Adresse de début du firmware
 * @param firmware_size Taille du firmware
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_init_metadata(uint32_t firmware_start, uint32_t firmware_size);

/**
 * @brief Lit les métadonnées d'intégrité depuis la flash
 * 
 * @param metadata Structure pour les métadonnées
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_read_metadata(integrity_metadata_t* metadata);

/**
 * @brief Écrit les métadonnées d'intégrité dans la flash
 * 
 * @param metadata Métadonnées à écrire
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_write_metadata(const integrity_metadata_t* metadata);

/**
 * @brief Valide les métadonnées d'intégrité
 * 
 * @param metadata Métadonnées à valider
 * @return bool true si valides
 */
bool integrity_validate_metadata(const integrity_metadata_t* metadata);

// ================================
// Gestion des chunks
// ================================

/**
 * @brief Génère les informations de chunks pour le firmware
 * 
 * @param firmware_start Adresse de début du firmware
 * @param firmware_size Taille du firmware
 * @param chunk_size Taille des chunks
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_generate_chunks(uint32_t firmware_start, uint32_t firmware_size, uint32_t chunk_size);

/**
 * @brief Obtient les informations d'un chunk
 * 
 * @param chunk_id Identifiant du chunk
 * @param chunk_info Structure pour les informations
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_get_chunk_info(uint32_t chunk_id, integrity_chunk_info_t* chunk_info);

/**
 * @brief Met à jour les informations d'un chunk après vérification
 * 
 * @param chunk_id Identifiant du chunk
 * @param is_verified État de vérification
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_update_chunk_status(uint32_t chunk_id, bool is_verified);

/**
 * @brief Obtient le nombre total de chunks
 * 
 * @return uint32_t Nombre de chunks
 */
uint32_t integrity_get_chunk_count(void);

// ================================
// Vérification en temps réel
// ================================

/**
 * @brief Démarre la vérification d'intégrité en temps réel
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_start_runtime_check(void);

/**
 * @brief Arrête la vérification d'intégrité en temps réel
 * 
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_stop_runtime_check(void);

/**
 * @brief Vérifie si la vérification en temps réel est active
 * 
 * @return bool true si active
 */
bool integrity_is_runtime_check_active(void);

/**
 * @brief Effectue une vérification incrémentale (appelée périodiquement)
 * 
 * @return integrity_status_t INTEGRITY_OK en cas de succès
 */
integrity_status_t integrity_incremental_check(void);

// ================================
// Détection de corruption
// ================================

/**
 * @brief Détecte la corruption mémoire en temps réel
 * 
 * @param address Adresse à vérifier
 * @param size Taille de la zone
 * @return bool true si corruption détectée
 */
bool integrity_detect_memory_corruption(uint32_t address, size_t size);

/**
 * @brief Analyse une corruption détectée
 * 
 * @param chunk_id Identifiant du chunk corrompu
 * @param corruption_type Type de corruption détectée
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_analyze_corruption(uint32_t chunk_id, uint8_t* corruption_type);

/**
 * @brief Tente de récupérer d'une corruption
 * 
 * @param chunk_id Identifiant du chunk corrompu
 * @return esp_err_t ESP_OK si récupération possible
 */
esp_err_t integrity_recover_from_corruption(uint32_t chunk_id);

// ================================
// Configuration et monitoring
// ================================

/**
 * @brief Configure la vérification d'intégrité
 * 
 * @param config Nouvelle configuration
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_configure(const integrity_config_t* config);

/**
 * @brief Obtient la configuration actuelle
 * 
 * @param config Structure pour la configuration
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_get_config(integrity_config_t* config);

/**
 * @brief Obtient les statistiques de vérification
 * 
 * @param stats Structure pour les statistiques
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_get_statistics(integrity_stats_t* stats);

/**
 * @brief Remet à zéro les statistiques
 */
void integrity_reset_statistics(void);

// ================================
// Fonctions de callback
// ================================

/**
 * @brief Type de callback pour les événements d'intégrité
 * 
 * @param status État de l'intégrité
 * @param chunk_id Identifiant du chunk (si applicable)
 * @param user_data Données utilisateur
 */
typedef void (*integrity_event_callback_t)(integrity_status_t status, uint32_t chunk_id, void* user_data);

/**
 * @brief Enregistre un callback pour les événements d'intégrité
 * 
 * @param callback Fonction de callback
 * @param user_data Données utilisateur à passer au callback
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_register_callback(integrity_event_callback_t callback, void* user_data);

/**
 * @brief Désenregistre le callback d'événements
 */
void integrity_unregister_callback(void);

// ================================
// Utilitaires et debugging
// ================================

/**
 * @brief Convertit un statut d'intégrité en string
 * 
 * @param status Statut d'intégrité
 * @return const char* Description du statut
 */
const char* integrity_status_to_string(integrity_status_t status);

/**
 * @brief Affiche les informations de vérification d'intégrité (debug)
 */
void integrity_print_info(void);

/**
 * @brief Affiche les statistiques détaillées (debug)
 */
void integrity_print_statistics(void);

/**
 * @brief Test complet du système de vérification d'intégrité
 * 
 * @return integrity_status_t INTEGRITY_OK si tous les tests passent
 */
integrity_status_t integrity_self_test(void);

/**
 * @brief Benchmark de performance du vérificateur d'intégrité
 * 
 * @param iterations Nombre d'itérations pour le test
 * @return esp_err_t ESP_OK en cas de succès
 */
esp_err_t integrity_benchmark(uint32_t iterations);

/**
 * @brief Force une vérification d'urgence (appelée en cas de panique)
 * 
 * @return integrity_status_t État de l'intégrité
 */
integrity_status_t integrity_emergency_check(void);

#ifdef __cplusplus
}
#endif

#endif /* INTEGRITY_CHECKER_H */