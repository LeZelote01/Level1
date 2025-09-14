# CMakeLists.txt pour le module ESP32 Crypto Enterprise
# SecureIoT-VIF Enterprise Edition v2.0

idf_component_register(
    SRCS 
        "esp32_crypto_manager.c"
        "crypto_operations.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES
        "mbedtls"
        "nvs_flash"
        "esp_system"
        "esp_efuse"
        "bootloader_support"
        "esp_hw_support"
    PRIV_REQUIRES
        "esp_hw_support"
        "driver"
        "spi_flash"
)

# Configuration des flags de compilation Enterprise
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wformat-security
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -O2
    -DSECURE_IOT_VIF_ENTERPRISE=1
)

# Définition des macros de configuration Enterprise
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ESP32_CRYPTO_ENTERPRISE_EDITION=1
    ESP32_CRYPTO_VERSION="2.0.0-ENTERPRISE"
    ESP32_CRYPTO_MAX_SLOTS=8
    ESP32_CRYPTO_ENTERPRISE_FEATURES=1
    ESP32_CRYPTO_PERFORMANCE_MONITORING=1
    ESP32_CRYPTO_TIMING_PROTECTION=1
    ESP32_CRYPTO_QUANTUM_PREPARATION=1
)

# Configuration des optimisations Enterprise
if(CONFIG_SECURE_IOT_VIF_ENTERPRISE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        CONFIG_MBEDTLS_HARDWARE_AES=1
        CONFIG_MBEDTLS_HARDWARE_SHA=1
        CONFIG_MBEDTLS_HARDWARE_ECC=1
        CONFIG_MBEDTLS_ECDSA_C=1
        CONFIG_MBEDTLS_ECP_C=1
        CONFIG_ESP32_CRYPTO_ENTERPRISE_OPTIMIZATIONS=1
    )
endif()

# Optimisations de sécurité Enterprise
target_compile_options(${COMPONENT_LIB} PRIVATE
    -fstack-protector-all
    -Wstack-protector
    -fPIE
    -Wl,-z,now
    -Wl,-z,relro
)

# Configuration spécifique au mode Release Enterprise
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NDEBUG=1
        ESP32_CRYPTO_PRODUCTION_MODE=1
        ESP32_CRYPTO_DEBUG_DISABLED=1
    )
endif()