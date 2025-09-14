# Configuration du composant firmware_verification Enterprise
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
        esp_timer
        freertos
    PRIV_REQUIRES 
        freertos
        esp_common
)

# Configuration des flags de compilation pour sécurité Enterprise maximale
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIC
    -fPIE
    -Wformat-security
    -Wstack-protector
)

# Définition des macros de configuration Enterprise
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    FIRMWARE_VERIFICATION_VERSION="2.0.0"
    FIRMWARE_VERIFICATION_ENTERPRISE=1
    INTEGRITY_CHECK_ENABLED=1
    INTEGRITY_REALTIME_ENABLED=1
    INTEGRITY_CHUNKED_VERIFICATION=1
    SIGNATURE_VERIFICATION_ENABLED=1
    HARDWARE_CRYPTO_ACCELERATION=1
)