# CMakeLists.txt pour le composant security_monitor Community Edition

idf_component_register(
    SRCS 
        "anomaly_detector.c"
        "incident_manager.c"
    INCLUDE_DIRS 
        "include"
    REQUIRES 
        esp_system
        log
        esp_timer
    PRIV_REQUIRES
        sensor_interface
)

# Messages informatifs pour Community Edition
message(STATUS "SecureIoT-VIF Community: Composant security_monitor")
message(STATUS "  Détection: Seuils fixes (éducatif)")
message(STATUS "  Incidents: Gestion basique")
message(STATUS "  Performance: Optimisée pour apprentissage")