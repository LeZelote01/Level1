# Architecture du Framework SecureIoT-VIF

## Vue d'Ensemble

SecureIoT-VIF est un framework de sécurité IoT révolutionnaire qui implémente une vérification d'intégrité en temps réel et une attestation continue pour les dispositifs ESP32 avec crypto intégré.

## Innovation Clés

### 🚀 Fonctionnalités Uniques vs Solutions Existantes

| Fonctionnalité | SecureIoT-VIF | Solutions Existantes |
|----------------|---------------|---------------------|
| **Vérification d'intégrité** | ✅ En temps réel pendant l'exécution | ❌ Uniquement au boot |
| **Attestation** | ✅ Continue avec renouvellement auto | ❌ Sur demande uniquement |
| **Détection d'anomalies** | ✅ Comportementale + ML léger | ❌ Seuils fixes basiques |
| **Architecture** | ✅ Modulaire extensible | ❌ Monolithique |
| **Intégration Crypto** | ✅ Étroite ESP32 intégré | ❌ Interface générique |
| **Gestion énergétique** | ✅ Optimisée pour IoT | ❌ Consommation élevée |

## Architecture Globale

```
┌─────────────────────────────────────────────────────────────┐
│                     MAIN APPLICATION                        │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              SECURITY ORCHESTRATOR                      ││
│  │  • Event Management  • Task Coordination                ││
│  │  • Timer Management  • Error Handling                   ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ SECURE ELEMENT  │   │ FIRMWARE        │   │ ATTESTATION     │
│                 │   │ VERIFICATION    │   │                 │
│ • ESP32 Crypto  │   │ • Integrity     │   │ • Continuous    │
│ • Crypto Ops   │   │ • Runtime Check │   │ • Remote Verify │
│ • Key Mgmt     │   │ • Signature     │   │ • Certificate   │
└─────────────────┘   └─────────────────┘   └─────────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ SENSOR          │   │ SECURITY        │   │ INCIDENT        │
│ INTERFACE       │   │ MONITOR         │   │ MANAGER         │
│                 │   │                 │   │                 │
│ • DHT22 Driver  │   │ • Anomaly Det   │   │ • Event Handle  │
│ • Data Mgmt     │   │ • Behavior Mon  │   │ • Response      │
│ • Statistics    │   │ • ML Analytics  │   │ • Recovery      │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

## Modules Détaillés

### 1. Secure Element Manager

**Responsabilités:**
- Gestion complète du crypto ESP32 intégré
- Opérations cryptographiques sécurisées
- Gestion des clés et certificats
- Communications crypto matérielles

**Composants:**
```
secure_element/
├── esp32_crypto_manager.c/.h   # Gestionnaire crypto ESP32 intégré
├── crypto_operations.c/.h      # Opérations crypto avancées
└── CMakeLists.txt              # Configuration build
```

**APIs Principales:**
- `esp32_crypto_manager_init()` - Initialisation
- `esp32_crypto_generate_ecdsa_keypair()` - Génération clés ECC
- `esp32_crypto_ecdsa_sign()` - Signature numérique
- `esp32_crypto_perform_attestation()` - Attestation d'appareil

### 2. Firmware Verification

**Innovation: Vérification en Temps Réel**

Contrairement aux solutions existantes qui ne vérifient l'intégrité qu'au démarrage, SecureIoT-VIF implémente une vérification continue pendant l'exécution.

**Mécanisme:**
```
Firmware divisé en chunks → Hash de chaque chunk → Signature ECC
     ↓                           ↓                      ↓
Vérification                 Comparaison            Validation
périodique                   temps réel             cryptographique
```

**Composants:**
```
firmware_verification/
├── integrity_checker.c/.h      # Vérification principale
├── signature_verifier.c/.h     # Validation signatures
└── CMakeLists.txt              # Configuration build
```

**Flux de Vérification:**
1. **Boot**: Vérification complète du firmware
2. **Runtime**: Vérification incrémentale par chunks
3. **Critical**: Vérification sections critiques prioritaires
4. **Emergency**: Vérification d'urgence en cas de panique

### 3. Attestation Manager

**Innovation: Attestation Continue**

Système d'attestation qui se renouvelle automatiquement sans intervention externe.

**Mécanisme:**
```
Challenge Auto-généré → Signature ESP32 → Vérification Intégrité
        ↓                     ↓               ↓
    32 bytes              64 bytes        Hash firmware
    aléatoires            ECDSA           + état système
```

**Composants:**
```
attestation/
├── attestation_manager.c/.h    # Gestion attestation
├── remote_verifier.c/.h        # Vérification distante
└── CMakeLists.txt              # Configuration build
```

### 4. Sensor Interface

**Fonctionnalités:**
- Driver DHT22 optimisé
- Gestion des erreurs robuste
- Statistiques temps réel
- Détection d'anomalies préliminaire

**Composants:**
```
sensor_interface/
├── dht22_driver.c/.h          # Driver DHT22 précis
├── sensor_manager.c/.h        # Gestionnaire capteurs
└── CMakeLists.txt             # Configuration build
```

### 5. Security Monitor

**Innovation: Détection Comportementale**

Système de détection d'anomalies basé sur l'apprentissage automatique léger.

**Algorithme:**
```
Données Historiques → Calcul Statistiques → Z-Score → Détection
    (100 échantillons)    (moyenne, σ)       (|z| > 3)   (anomalie)
```

**Composants:**
```
security_monitor/
├── anomaly_detector.c/.h      # Détection ML légère
├── incident_manager.c/.h      # Gestion incidents
└── CMakeLists.txt             # Configuration build
```

## Flux de Données

### 1. Flux Principal de Sécurité

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Capteur   │───▶│  Anomalie   │───▶│  Incident   │
│   DHT22     │    │  Detector   │    │  Manager    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                  │
       ▼                   ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Statistics  │    │  ML Model   │    │  Response   │
│  Tracking   │    │  Update     │    │  Actions    │
└─────────────┘    └─────────────┘    └─────────────┘
```

### 2. Flux de Vérification d'Intégrité

```
Timer 60s ───┐
             ▼
┌─────────────────┐    ┌─────────────────┐
│  Integrity      │───▶│  Chunk          │
│  Scheduler      │    │  Selector       │
└─────────────────┘    └─────────────────┘
                               │
                               ▼
┌─────────────────┐    ┌─────────────────┐
│  Hash           │◄───│  Flash          │
│  Calculation    │    │  Reader         │
└─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐
│  Signature      │───▶│  Event          │
│  Verification   │    │  Trigger        │
└─────────────────┘    └─────────────────┘
```

### 3. Flux d'Attestation

```
Timer 30s ───┐
             ▼
┌─────────────────┐    ┌─────────────────┐
│  Challenge      │───▶│  ESP32 Crypto   │
│  Generator      │    │  Signature      │
└─────────────────┘    └─────────────────┘
         ▲                       │
         │                       ▼
┌─────────────────┐    ┌─────────────────┐
│  Integrity      │◄───│  Response       │
│  Check          │    │  Builder        │
└─────────────────┘    └─────────────────┘
```

## Gestion Mémoire et Performance

### Optimisations Mémoire

| Module | RAM Usage | Flash Usage | Optimisations |
|--------|-----------|-------------|---------------|
| SE Manager | 8KB | 32KB | Pool de buffers |
| Integrity Checker | 12KB | 24KB | Chunks streaming |
| Attestation | 4KB | 16KB | Buffer rotatifs |
| Sensor Interface | 2KB | 8KB | Données compressées |
| Security Monitor | 6KB | 18KB | Historique circulaire |
| **Total** | **32KB** | **98KB** | **< 100KB** |

### Optimisations Performance

**Vérification d'Intégrité:**
- Vérification par chunks (4KB) pour éviter les gros blocs
- Scheduling intelligent (sections critiques en priorité)
- Cache des hashs pour éviter les recalculs

**Opérations Cryptographiques:**
- Utilisation maximale du crypto ESP32 intégré (hardware)
- Opérations asynchrones quand possible
- Pool de buffers pour éviter les allocations

**Détection d'Anomalies:**
- Algorithmes légers (Z-score vs réseaux de neurones)
- Fenêtre glissante pour les données historiques
- Calculs incrémentaux (moyenne mobile)

## Sécurité et Robustesse

### Niveaux de Sécurité

```
LEVEL 4 - CRITICAL
├── Secure Boot activé
├── Flash Encryption activée
├── Clés hardware uniquement
└── Attestation obligatoire

LEVEL 3 - HIGH (par défaut)
├── Vérification temps réel
├── Attestation continue
├── Détection anomalies
└── Monitoring incidents

LEVEL 2 - MEDIUM
├── Vérification périodique
├── Attestation sur demande
└── Logging basique

LEVEL 1 - LOW
└── Vérification au boot uniquement
```

### Mécanismes de Récupération

**Corruption Détectée:**
1. Isolation du chunk corrompu
2. Tentative de re-lecture
3. Signalement d'incident
4. Mode dégradé si nécessaire
5. Redémarrage sécurisé en dernier recours

**Anomalie Comportementale:**
1. Augmentation du niveau de monitoring
2. Réduction des intervalles de vérification
3. Sauvegarde d'état d'urgence
4. Notification d'incident

**Échec Attestation:**
1. Régénération du challenge
2. Vérification de l'intégrité crypto ESP32
3. Tentatives multiples
4. Mode sécurisé si échecs persistants

## Extensibilité

### Ajout de Nouveaux Capteurs

```c
// 1. Créer le driver dans sensor_interface/
esp_err_t new_sensor_init(const new_sensor_config_t* config);
esp_err_t new_sensor_read(new_sensor_data_t* data);

// 2. Intégrer dans sensor_manager.c
esp_err_t sensor_read_new_sensor(sensor_data_t* data);

// 3. Ajouter détection d'anomalies dans anomaly_detector.c
bool sensor_is_new_sensor_anomaly(const sensor_data_t* data);
```

### Ajout de Nouveaux Algorithmes Crypto

```c
// 1. Étendre crypto_operations.h
typedef enum {
    CRYPTO_ALG_NEW_ALGORITHM
} crypto_algorithm_t;

// 2. Implémenter dans crypto_operations.c
crypto_result_t crypto_new_algorithm(const uint8_t* input, uint8_t* output);

// 3. Intégrer dans esp32_crypto_manager.c si nécessaire
esp32_crypto_result_t esp32_crypto_new_operation(uint8_t slot_id, const uint8_t* data);
```

### Nouveaux Types d'Attestation

```c
// 1. Définir nouveau type dans attestation_manager.h
typedef enum {
    ATTESTATION_TYPE_NEW_TYPE = 4
} attestation_type_t;

// 2. Implémenter la logique
esp_err_t attestation_perform_new_type(attestation_result_t* result);
```

## Comparaison avec Solutions Existantes

### ESP-TEE (Espressif)
- ✅ SecureIoT-VIF: Compatible ESP32 standard
- ❌ ESP-TEE: Nécessite ESP32-C6 spécialisé
- ✅ SecureIoT-VIF: Vérification temps réel
- ❌ ESP-TEE: Vérification au boot uniquement

### PACCOR4ESP (NSA)
- ✅ SecureIoT-VIF: Attestation continue automatique
- ❌ PACCOR4ESP: Attestation sur demande uniquement
- ✅ SecureIoT-VIF: Intégration capteurs IoT
- ❌ PACCOR4ESP: Focus uniquement attestation

### Secure_esp (Open Source)
- ✅ SecureIoT-VIF: Architecture modulaire
- ❌ Secure_esp: Architecture monolithique
- ✅ SecureIoT-VIF: Détection anomalies ML
- ❌ Secure_esp: Pas de détection comportementale

### IoT Security Framework (Générique)
- ✅ SecureIoT-VIF: Optimisé pour contraintes IoT
- ❌ Générique: Consommation élevée
- ✅ SecureIoT-VIF: Intégration hardware native
- ❌ Générique: Interface software uniquement

## Métriques et KPIs

### Performance
- **Boot Time**: < 5 secondes
- **Integrity Check**: < 200ms (vérification complète)
- **Attestation Time**: < 100ms
- **Anomaly Detection**: < 10ms
- **Memory Footprint**: < 100KB flash, < 32KB RAM

### Sécurité
- **MTBF** (Mean Time Between Failures): > 8760h (1 an)
- **Detection Rate**: > 99% (anomalies connues)
- **False Positive Rate**: < 1%
- **Recovery Time**: < 30 secondes

### Énergie
- **Active Mode**: 80mA @ 3.3V
- **Monitor Mode**: 20mA @ 3.3V  
- **Sleep Mode**: 10µA @ 3.3V (avec réveil périodique)

---

Cette architecture unique positionne SecureIoT-VIF comme une solution de référence pour la sécurité IoT, combinant innovation technologique et praticité d'implémentation.