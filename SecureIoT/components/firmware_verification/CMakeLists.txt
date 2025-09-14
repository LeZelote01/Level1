# Configuration du composant firmware_verification
idf_component_register(
    SRCS 
        "integrity_checker.c"
        "signature_verifier.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        driver 
        esp_system 
        esp_log
        nvs_flash
        secure_element
        app_update
        spi_flash
    PRIV_REQUIRES 
        freertos
)

# Configuration des flags de compilation pour la sécurité
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Définition des macros de configuration
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    FIRMWARE_VERIFICATION_VERSION="1.0.0"
    INTEGRITY_CHECK_ENABLED=1
)