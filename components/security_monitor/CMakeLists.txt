# Configuration du composant security_monitor
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
    PRIV_REQUIRES 
        freertos
)