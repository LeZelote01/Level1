# CMake version minimum requise
cmake_minimum_required(VERSION 3.16)

# Configuration du projet Community
set(PROJECT_NAME "SecureIoT-VIF-Community")
set(PROJECT_VER "1.0.0")

# Inclusion d'ESP-IDF
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Définition du projet avec support C et C++
project(${PROJECT_NAME} VERSION ${PROJECT_VER} LANGUAGES C CXX)

# Configuration du compilateur
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Options de compilation pour Community Edition (moins strictes)
add_compile_options(
    -Wall
    -Wextra
    -Wformat-security
    -fstack-protector
    -D_FORTIFY_SOURCE=1
)

# Configuration des chemins d'inclusion Community
include_directories(
    "components/secure_element/include"
    "components/firmware_verification/include"
    "components/sensor_interface/include"
    "components/security_monitor/include"
)

# Définition des macros de configuration Community
add_definitions(
    -DSECURE_IOT_VIF_VERSION="${PROJECT_VER}"
    -DSECURE_IOT_VIF_NAME="${PROJECT_NAME}"
    -DSECURE_IOT_VIF_COMMUNITY_EDITION=1
    -DSECURE_IOT_VIF_BASIC_CRYPTO_ONLY=1
)

# Messages informatifs lors de la compilation
message(STATUS "Configuration SecureIoT-VIF Community Edition")
message(STATUS "  Version: ${PROJECT_VER}")
message(STATUS "  Édition: Community (Éducation & Recherche)")
message(STATUS "  Fonctionnalités: Basiques pour apprentissage")
message(STATUS "  Crypto: Software seulement")
message(STATUS "  Intégrité: Au démarrage seulement")
message(STATUS "  Détection: Seuils fixes")