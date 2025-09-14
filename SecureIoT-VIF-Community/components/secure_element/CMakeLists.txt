# CMakeLists.txt pour le composant secure_element Community Edition

idf_component_register(
    SRCS 
        "crypto_operations_basic.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        mbedtls
        esp_system
        log
)

# Messages informatifs pour Community Edition
message(STATUS "SecureIoT-VIF Community: Composant secure_element")
message(STATUS "  Crypto: Software uniquement (mbedTLS)")
message(STATUS "  Sécurité: Niveau éducatif")
message(STATUS "  Performance: Optimisée pour apprentissage")