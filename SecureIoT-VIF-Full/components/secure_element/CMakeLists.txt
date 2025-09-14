# CMakeLists.txt pour le module ESP32 Crypto Intégré
# SecureIoT-VIF v2.0 - ESP32 Crypto Intégré

idf_component_register(
    SRCS 
        "esp32_crypto_manager.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES
        "mbedtls"
        "nvs_flash"
        "esp_system"
        "esp_efuse"
        "bootloader_support"
    PRIV_REQUIRES
        "esp_hw_support"
)