# CMakeLists.txt pour le composant sensor_interface Community Edition

idf_component_register(
    SRCS 
        "sensor_manager.c"
        "dht22_driver.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        driver
        esp_system
        log
        freertos
    PRIV_REQUIRES
        esp_timer
)

# Messages informatifs pour Community Edition
message(STATUS "SecureIoT-VIF Community: Composant sensor_interface")
message(STATUS "  Capteurs: DHT22 (fonctionnalité complète)")
message(STATUS "  Interface: Identique à Enterprise Edition")
message(STATUS "  Performance: Optimale pour apprentissage")