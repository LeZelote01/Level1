# Configuration du composant security_monitor Enterprise
idf_component_register(
    SRCS 
        "anomaly_detector.c"
        "incident_manager.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        driver 
        esp_system 
        esp_log
        nvs_flash
        secure_element
        firmware_verification
        sensor_interface
        esp_timer
        freertos
    PRIV_REQUIRES 
        freertos
        esp_common
        esp_wifi
        esp_netif
)

# Flags de compilation optimisés pour ML Enterprise
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -O3
    -ffast-math
    -funroll-loops
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Définitions Enterprise
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    SECURITY_MONITOR_VERSION="2.0.0"
    SECURITY_MONITOR_ENTERPRISE=1
    ANOMALY_DETECTION_ML_ENABLED=1
    BEHAVIORAL_ANALYSIS_ENABLED=1
    INCIDENT_MANAGEMENT_ADVANCED=1
    PERFORMANCE_MONITORING_ENABLED=1
)