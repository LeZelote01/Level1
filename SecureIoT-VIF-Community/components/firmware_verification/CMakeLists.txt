# CMakeLists.txt pour le composant firmware_verification Community Edition

idf_component_register(
    SRCS 
        "integrity_checker.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        esp_partition
        esp_ota
        crypto_operations_basic
        log
        esp_system
    PRIV_REQUIRES
        secure_element
)

# Messages informatifs pour Community Edition
message(STATUS "SecureIoT-VIF Community: Composant firmware_verification")
message(STATUS "  Type: Vérification au démarrage seulement")
message(STATUS "  Méthode: Échantillonnage éducatif")
message(STATUS "  Performance: Optimisée pour apprentissage")