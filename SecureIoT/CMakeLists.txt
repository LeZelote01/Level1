# CMake version minimum requise
cmake_minimum_required(VERSION 3.16)

# Configuration du projet
set(PROJECT_NAME "SecureIoT-VIF")
set(PROJECT_VER "1.0.0")

# Inclusion d'ESP-IDF
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Définition du projet avec support C et C++
project(${PROJECT_NAME} VERSION ${PROJECT_VER} LANGUAGES C CXX)

# Configuration du compilateur
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Options de compilation pour optimiser la sécurité
add_compile_options(
    -Wall
    -Wextra
    -Werror
    -Wformat-security
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Configuration des chemins d'inclusion
include_directories(
    "components/secure_element/include"
    "components/firmware_verification/include"
    "components/attestation/include"
    "components/sensor_interface/include"
    "components/security_monitor/include"
)

# Définition des macros de configuration
add_definitions(
    -DSECURE_IOT_VIF_VERSION="${PROJECT_VER}"
    -DSECURE_IOT_VIF_NAME="${PROJECT_NAME}"
)