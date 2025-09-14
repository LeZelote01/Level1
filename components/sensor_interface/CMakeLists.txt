# Configuration du composant sensor_interface
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
    PRIV_REQUIRES 
        freertos
)