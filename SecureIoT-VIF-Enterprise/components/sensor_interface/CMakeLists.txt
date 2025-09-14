# Configuration du composant sensor_interface Enterprise
idf_component_register(
    SRCS 
        "dht22_driver.c"
        "sensor_manager.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        driver 
        esp_system 
        esp_log
        esp_timer
        secure_element
        nvs_flash
        freertos
    PRIV_REQUIRES 
        freertos
        esp_common
)

# Flags de compilation optimisés pour performance Enterprise
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Définitions Enterprise
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    SENSOR_INTERFACE_VERSION="2.0.0"
    SENSOR_INTERFACE_ENTERPRISE=1
    SENSOR_VALIDATION_ENHANCED=1
    SENSOR_MONITORING_REALTIME=1
    SENSOR_CALIBRATION_ENABLED=1
    SENSOR_REDUNDANCY_ENABLED=1
)