# Architecture du Framework SecureIoT-VIF Community Edition

## Vue d'Ensemble

SecureIoT-VIF Community Edition est la version éducative du framework de sécurité IoT révolutionnaire. Cette édition propose les fonctionnalités de base pour l'apprentissage, la recherche académique et le prototypage.

## 🎓 Objectifs Pédagogiques

### Concepts Enseignés
- **Cryptographie de base** : Comprendre les algorithmes fondamentaux
- **Vérification d'intégrité** : Apprendre les concepts de base
- **Détection d'anomalies** : Méthodes par seuils fixes
- **Architecture modulaire** : Design patterns pour la sécurité
- **Interfaces capteurs** : Communication avec le hardware

### Public Cible
- 🎓 **Étudiants** en cybersécurité et IoT
- 👨‍🏫 **Enseignants** et formateurs
- 🔬 **Chercheurs** académiques
- 🛠️ **Développeurs** apprenant la sécurité IoT

## Architecture Simplifiée Community

```
┌─────────────────────────────────────────────────────────────┐
│                     MAIN APPLICATION                        │
│  ┌─────────────────────────────────────────────────────────┐│
│  │         SECURITY ORCHESTRATOR (Simplifié)               ││
│  │  • Event Management  • Basic Task Coordination          ││
│  │  • Timer Management  • Simple Error Handling            ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ SECURE ELEMENT  │   │ FIRMWARE        │   │ SENSOR          │
│ (Basique)       │   │ VERIFICATION    │   │ INTERFACE       │
│                 │   │ (Boot seulement)│   │ (Complète)      │
│ • Crypto Basic  │   │ • Au démarrage  │   │ • DHT22 Driver  │
│ • Software      │   │ • Échantillonng │   │ • Data Mgmt     │
│ • mbedTLS       │   │ • Hash simple   │   │ • Statistics    │
└─────────────────┘   └─────────────────┘   └─────────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ SECURITY        │   │ INCIDENT        │   │ [PAS            │
│ MONITOR         │   │ MANAGER         │   │ D'ATTESTATION]  │
│ (Seuils fixes) │   │ (Basique)       │   │                 │
│ • Threshold Det │   │ • Logging       │   │ Disponible en   │
│ • Basic Stats   │   │ • Console Alert │   │ Enterprise      │
│ • No ML         │   │ • Statistics    │   │ seulement       │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

## Modules Détaillés Community

### 1. Secure Element Manager (Basique)

**Version Community** : Crypto software uniquement

**Responsabilités** :
- Opérations cryptographiques de base via mbedTLS
- Génération aléatoire software (pas de TRNG hardware)
- Hash SHA-256, chiffrement AES-128, signatures ECDSA P-256
- **SANS** : HSM, eFuse, accélérations hardware

**Composants** :
```
secure_element/
├── crypto_operations_basic.c/.h    # Crypto software simple
└── CMakeLists.txt                  # Configuration Community
```

**APIs Principales** :
- `crypto_operations_basic_init()` - Initialisation software
- `crypto_basic_generate_random()` - Aléatoire software
- `crypto_basic_sha256()` - Hash software
- `crypto_basic_ecdsa_sign()` - Signature software

**⚠️ Limitations Community** :
- Pas de Hardware Security Module (HSM)
- Pas de True Random Number Generator (TRNG)
- Pas de stockage sécurisé eFuse
- Performance réduite (software vs hardware)
- Sécurité réduite (RAM vs hardware protégé)

### 2. Firmware Verification (Simplifié)

**Innovation Réduite** : Vérification au démarrage seulement

**Différences vs Enterprise** :

| Aspect | Community | Enterprise |
|--------|-----------|------------|
| **Quand** | Au boot seulement | Temps réel continu |
| **Couverture** | Échantillonnage | Complète |
| **Chunks** | 10-20% des chunks | 100% des chunks |
| **Fréquence** | Une fois au boot | Toutes les 60s |
| **Signature** | Hash simple | Vérification crypto |

**Mécanisme Community** :
```
Firmware → Chunks 8KB → Hash échantillonnage → Validation basique
     ↓           ↓              ↓                    ↓
Division    Optimisation   Contrôle            Éducatif
Modulaire   Mémoire       Basique             Uniquement
```

**Composants** :
```
firmware_verification/
├── integrity_checker.c/.h      # Vérification de base
└── CMakeLists.txt              # Configuration Community
```

**Flux de Vérification Community** :
1. **Boot** : Vérification échantillonnage (20% des chunks)
2. **Runtime** : Aucune vérification (vs Enterprise temps réel)
3. **Critical** : Non disponible (Enterprise seulement)
4. **Emergency** : Logging basique

### 3. Attestation Manager

**❌ NON DISPONIBLE en Community Edition**

L'attestation continue est une fonctionnalité avancée réservée à Enterprise :
- Attestation continue autonome ❌
- Challenge auto-généré ❌
- Vérification distante ❌
- Renouvellement automatique ❌

**Message éducatif** : Les logs Community mentionnent cette limitation et encouragent l'upgrade vers Enterprise pour la production.

### 4. Sensor Interface (Identique à Enterprise)

**✅ Fonctionnalité Complète** : Aucune limitation vs Enterprise

Cette partie reste entièrement fonctionnelle car elle ne pose pas de problème de sécurité critique.

**Fonctionnalités** :
- Driver DHT22 complet
- Gestion des erreurs robuste
- Statistiques temps réel
- Validation des données
- Calcul de qualité

**Composants** :
```
sensor_interface/
├── dht22_driver.c/.h          # Driver complet
├── sensor_manager.c/.h        # Gestionnaire complet
└── CMakeLists.txt             # Configuration identique
```

### 5. Security Monitor (Simplifié)

**Version Community** : Détection par seuils fixes uniquement

**Différences vs Enterprise** :

| Aspect | Community | Enterprise |
|--------|-----------|------------|
| **Méthode** | Seuils fixes | ML adaptatif |
| **Adaptation** | Manuelle | Automatique |
| **Historique** | 30 échantillons | 100 échantillons |
| **Complexité** | O(1) simple | O(n) ML |
| **Mémoire** | 400 bytes | 2KB+ |

**Algorithme Community** :
```
Données Capteur → Comparaison Seuils → Détection Simple
    (T, H)              (min, max)         (oui/non)
```

**Composants** :
```
security_monitor/
├── anomaly_detector.c/.h      # Seuils fixes seulement
├── incident_manager.c/.h      # Gestion basique
└── CMakeLists.txt             # Configuration Community
```

## Flux de Données Community

### 1. Flux Principal Simplifié

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Capteur   │───▶│   Seuils    │───▶│  Logging    │
│   DHT22     │    │   Fixes     │    │  Basique    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                  │
       ▼                   ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Statistics  │    │ Comparison  │    │  Console    │
│  Basiques   │    │  Simple     │    │  Output     │
└─────────────┘    └─────────────┘    └─────────────┘
```

### 2. Flux de Vérification Community

```
Boot seulement ───┐
                  ▼
┌─────────────────┐    ┌─────────────────┐
│  Échantillonage │───▶│  Chunks Sample  │
│  Éducatif       │    │  (10-20%)       │
└─────────────────┘    └─────────────────┘
                               │
                               ▼
┌─────────────────┐    ┌─────────────────┐
│  Hash Simple    │◄───│  Flash Reader   │
│  Calculation    │    │  Basic          │
└─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│  Result         │
│  Logging        │
└─────────────────┘
```

## Gestion Mémoire et Performance Community

### Optimisations Mémoire Community

| Module | RAM Usage | Flash Usage | vs Enterprise |
|--------|-----------|-------------|---------------|
| SE Manager (Basic) | 4KB | 16KB | 50% réduit |
| Integrity Checker | 6KB | 12KB | 50% réduit |
| Sensor Interface | 2KB | 8KB | Identique |
| Security Monitor | 3KB | 8KB | 50% réduit |
| **Total Community** | **15KB** | **44KB** | **55% réduit** |

### Performance Community vs Enterprise

| Opération | Community | Enterprise | Ratio |
|-----------|-----------|------------|-------|
| **Boot Time** | < 8s | < 3s | 2.7x plus lent |
| **Crypto Hash** | 200ms | 50ms | 4x plus lent |
| **Integrity Check** | 2s | 200ms | 10x plus lent |
| **Anomaly Detection** | 50ms | 10ms | 5x plus lent |

**Explications** :
- Community utilise le crypto software vs hardware Enterprise
- Échantillonnage réduit vs vérification complète
- Algorithmes simplifiés vs optimisés

## Sécurité et Robustesse Community

### Niveaux de Sécurité Community

```
LEVEL 2 - MEDIUM (par défaut Community)
├── Crypto software basique
├── Vérification au boot seulement
├── Détection par seuils fixes
└── Logging et monitoring

LEVEL 1 - LOW
└── Fonctionnalités minimales pour démo

[LEVEL 3-4 - HIGH/CRITICAL : Enterprise seulement]
```

### Mécanismes de Récupération Community

**Corruption Détectée** :
1. Logging de l'incident
2. Notification console
3. Mise à jour statistiques
4. **SANS** : Redémarrage automatique (Enterprise)

**Anomalie Comportementale** :
1. Comparaison seuils fixes
2. Logging de l'anomalie
3. Comptage statistiques
4. **SANS** : Adaptation automatique (Enterprise)

## Messages Éducatifs Intégrés

### Comparaisons Enterprise

Le code Community inclut des messages éducatifs expliquant les différences :

```c
ESP_LOGI(TAG, "💡 En Enterprise: vérification temps réel disponible");
ESP_LOGI(TAG, "🚀 Upgrade pour crypto hardware et performance 4x");
ESP_LOGI(TAG, "🎓 Community: idéal pour comprendre les concepts");
```

### Encouragements à l'Upgrade

```c
#define COMMUNITY_UPGRADE_MESSAGE \
    "🚀 Pour accéder aux fonctionnalités avancées :\n" \
    "   • Vérification d'intégrité temps réel\n" \
    "   • Attestation continue autonome\n" \
    "   • Détection ML comportementale\n" \
    "   • Crypto HSM ESP32 intégré\n" \
    "   • Support professionnel\n" \
    "🚀 Contactez-nous pour SecureIoT-VIF Enterprise Edition !\n"
```

## Extensibilité Community

### Ajout de Nouveaux Capteurs

Identique à Enterprise - aucune limitation.

### Personnalisation des Seuils

```c
// Configuration éducative des seuils
anomaly_thresholds_t custom_thresholds = {
    .temp_min = 10.0f,          // Personnalisable
    .temp_max = 40.0f,          // Personnalisable
    .humidity_min = 20.0f,      // Personnalisable
    .humidity_max = 80.0f,      // Personnalisable
    .temp_change_max = 5.0f,    // Personnalisable
    .humidity_change_max = 15.0f // Personnalisable
};
```

### Ajout d'Algorithmes de Détection

Possible mais limité aux méthodes statiques (pas de ML).

## Comparaison Architecturale Finale

### ✅ Identique à Enterprise
- Interface capteurs complète
- Architecture modulaire
- Logging et statistiques
- Configuration flexible

### 🟡 Simplifié vs Enterprise
- Crypto software vs hardware
- Vérification échantillonnage vs complète
- Détection seuils vs ML
- Performance réduite acceptable

### ❌ Non Disponible (Enterprise Seulement)
- Vérification temps réel continue
- Attestation continue autonome  
- ML adaptatif et apprentissage
- Accélérations crypto hardware
- Actions de récupération automatiques

---

Cette architecture Community permet un **apprentissage progressif** des concepts de sécurité IoT tout en préparant une éventuelle **migration vers Enterprise** pour la production.