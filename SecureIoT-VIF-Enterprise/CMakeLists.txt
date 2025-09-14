# CMake version minimum requise
cmake_minimum_required(VERSION 3.16)

# Configuration du projet Enterprise
set(PROJECT_NAME "SecureIoT-VIF-Enterprise")
set(PROJECT_VER "2.0.0")

# Inclusion d'ESP-IDF
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Définition du projet avec support C et C++
project(${PROJECT_NAME} VERSION ${PROJECT_VER} LANGUAGES C CXX)

# Configuration du compilateur
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Options de compilation pour optimiser la sécurité Enterprise
add_compile_options(
    -Wall
    -Wextra
    -Werror
    -Wformat-security
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -O2
    -DSECURE_IOT_VIF_ENTERPRISE=1
)

# Configuration des chemins d'inclusion Enterprise
include_directories(
    "components/secure_element/include"
    "components/firmware_verification/include"
    "components/attestation/include"
    "components/sensor_interface/include"
    "components/security_monitor/include"
)

# Définition des macros de configuration Enterprise
add_definitions(
    -DSECURE_IOT_VIF_VERSION="${PROJECT_VER}"
    -DSECURE_IOT_VIF_NAME="${PROJECT_NAME}"
    -DSECURE_IOT_VIF_ENTERPRISE_EDITION=1
    -DFEATURE_REAL_TIME_INTEGRITY=1
    -DFEATURE_CONTINUOUS_ATTESTATION=1
    -DFEATURE_ML_ANOMALY_DETECTION=1
    -DFEATURE_HARDWARE_HSM=1
    -DFEATURE_EFUSE_PROTECTION=1
    -DFEATURE_SECURE_BOOT_V2=1
    -DFEATURE_FLASH_ENCRYPTION=1
)