/**
 * @file integrity_checker.h
 * @brief Header pour le vérificateur d'intégrité Community Edition
 * 
 * Définit l'interface simplifiée pour la vérification d'intégrité de base.
 * Version éducative sans fonctionnalités temps réel.
 * 
 * @author Framework SecureIoT-VIF Community
 * @version 1.0.0 - Community Edition
 * @date 2025
 */

#ifndef INTEGRITY_CHECKER_H
#define INTEGRITY_CHECKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

// ================================
// Types et énumérations Community
// ================================

/**
 * @brief États de vérification d'intégrité Community
 */
typedef enum {
    INTEGRITY_OK = 0,                   // Intégrité vérifiée
    INTEGRITY_CORRUPTED,                // Corruption détectée
    INTEGRITY_ERROR,                    // Erreur système
    INTEGRITY_INVALID_CHUNK,            // Chunk invalide
    INTEGRITY_NOT_INITIALIZED,          // Non initialisé
    INTEGRITY_MAX
} integrity_status_t;

/**
 * @brief Statistiques d'intégrité Community
 */
typedef struct {
    uint32_t total_checks;              // Nombre total de vérifications
    uint32_t successful_checks;         // Vérifications réussies
    uint32_t failed_checks;             // Vérifications échouées
    uint64_t last_check_time;           // Dernière vérification (ms)
    uint32_t last_check_duration_ms;    // Durée dernière vérification
    uint32_t chunks_verified;           // Chunks vérifiés au total
    uint32_t chunks_corrupted;          // Chunks corrompus détectés
} integrity_stats_community_t;

// ================================
// Constantes Community
// ================================

#define INTEGRITY_CHUNK_SIZE_COMMUNITY      (8192)      // Plus gros qu'Enterprise
#define INTEGRITY_SAMPLE_RATIO_COMMUNITY    (0.1f)      // 10% des chunks seulement
#define INTEGRITY_MAX_CHUNKS_COMMUNITY      (256)       // Limite éducative

// ================================
// Fonctions d'initialisation
// ================================

/**
 * @brief Initialise le vérificateur d'intégrité Community
 * 
 * Version simplifiée pour usage éducatif et de recherche.
 * 
 * @return ESP_OK si succès, ESP_FAIL sinon
 */
esp_err_t integrity_checker_init(void);

/**
 * @brief Deinitialise le vérificateur d'intégrité
 * 
 * @return ESP_OK si succès
 */
esp_err_t integrity_checker_deinit(void);

// ================================
// Fonctions de vérification Community
// ================================

/**
 * @brief Vérification d'intégrité basique au démarrage
 * 
 * Effectue une vérification simplifiée du firmware au boot.
 * Utilise un échantillonnage de chunks pour l'éducation.
 * 
 * @return integrity_status_t Status de la vérification
 */
integrity_status_t integrity_check_firmware_basic(void);

/**
 * @brief Vérification rapide d'un chunk spécifique
 * 
 * Version éducative pour comprendre le principe des chunks.
 * 
 * @param chunk_id ID du chunk à vérifier
 * @return integrity_status_t Status de la vérification
 */
integrity_status_t integrity_check_chunk_basic(size_t chunk_id);

// ================================
// Fonctions de statistiques Community
// ================================

/**
 * @brief Obtient les statistiques d'intégrité Community
 * 
 * @param stats Pointeur vers la structure de statistiques
 * @return ESP_OK si succès, ESP_ERR_INVALID_ARG sinon
 */
esp_err_t integrity_get_stats_community(integrity_stats_community_t *stats);

/**
 * @brief Affiche les statistiques d'intégrité Community
 */
void integrity_print_stats_community(void);

/**
 * @brief Réinitialise les statistiques d'intégrité
 * 
 * @return ESP_OK si succès, ESP_ERR_INVALID_STATE si non initialisé
 */
esp_err_t integrity_reset_stats_community(void);

// ================================
// Fonctions utilitaires Community
// ================================

/**
 * @brief Test de fonctionnement du vérificateur Community
 * 
 * Auto-test pour vérifier que toutes les fonctions de base marchent.
 * 
 * @return ESP_OK si tous les tests passent, ESP_FAIL sinon
 */
esp_err_t integrity_checker_self_test(void);

/**
 * @brief Affiche les informations du vérificateur Community
 */
void integrity_checker_print_info(void);

/**
 * @brief Convertit un status d'intégrité en chaîne
 * 
 * @param status Status à convertir
 * @return Chaîne décrivant le status
 */
const char* integrity_status_to_string(integrity_status_t status);

// ================================
// Macros utilitaires Community
// ================================

/**
 * @brief Calcule le nombre de chunks pour une taille donnée
 */
#define INTEGRITY_CALC_CHUNKS_COMMUNITY(size) \
    (((size) + INTEGRITY_CHUNK_SIZE_COMMUNITY - 1) / INTEGRITY_CHUNK_SIZE_COMMUNITY)

/**
 * @brief Calcule l'offset d'un chunk
 */
#define INTEGRITY_CHUNK_OFFSET_COMMUNITY(chunk_id) \
    ((chunk_id) * INTEGRITY_CHUNK_SIZE_COMMUNITY)

/**
 * @brief Vérifie si un chunk ID est valide
 */
#define INTEGRITY_IS_VALID_CHUNK_COMMUNITY(chunk_id, max_chunks) \
    ((chunk_id) < (max_chunks))

// ================================
// Messages informatifs Community
// ================================

#define INTEGRITY_COMMUNITY_FEATURES \
    "🎓 Fonctionnalités Community:\n" \
    "• Vérification au démarrage seulement\n" \
    "• Échantillonnage de chunks (éducatif)\n" \
    "• Hash SHA-256 software\n" \
    "• Statistiques basiques\n" \
    "• Idéal pour apprentissage\n"

#define INTEGRITY_COMMUNITY_LIMITATIONS \
    "⚠️  Limitations Community:\n" \
    "• Pas de vérification temps réel\n" \
    "• Pas de vérification de signature\n" \
    "• Échantillonnage partiel seulement\n" \
    "• Performance réduite\n" \
    "• Usage éducatif uniquement\n"

#define INTEGRITY_UPGRADE_TO_ENTERPRISE \
    "🚀 Upgrade vers Enterprise pour:\n" \
    "• Vérification temps réel continue\n" \
    "• Vérification complète (tous chunks)\n" \
    "• Validation signatures cryptographiques\n" \
    "• Performance optimisée hardware\n" \
    "• Support production industrielle\n"

#ifdef __cplusplus
}
#endif

#endif /* INTEGRITY_CHECKER_H */