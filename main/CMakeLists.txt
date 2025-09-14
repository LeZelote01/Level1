# Configuration du composant main
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES 
        freertos
        esp_wifi
        esp_event
        esp_log
        esp_system
        nvs_flash
        driver
        secure_element
        firmware_verification
        attestation
        sensor_interface
        security_monitor
)