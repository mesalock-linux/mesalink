#
#   __  __                 _     _       _
#  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
#  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
#  | |  | |  __/\__ \ (_| | |___| | | | |   <
#  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
#
# Copyright (c) 2017-2018, The MesaLink Authors.
# All rights reserved.
#
# This work is licensed under the terms of the BSD 3-Clause License.
# For a copy, see the LICENSE file.
#

cmake_minimum_required(VERSION 3.0)

project(MesaLink C CXX)
set(DEFAULT_BUILD_TYPE "Release")
set(MESALINK_VERSION_STRING "1.1.0")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_language(Rust)
include(CMakeCargo)

if(RUSTC_VERSION AND RUSTC_VERSION VERSION_LESS 1.31)
    message(FATAL_ERROR "Rust is too old, please install at least 1.31 to support the Rust 2018 edition")
endif()

project(MesaLink VERSION 15.1.0)
set(LIB_NAME mesalink)

# Config options
configure_file(${PROJECT_SOURCE_DIR}/mesalink/version.h.cmake.in ${PROJECT_SOURCE_DIR}/mesalink/version.h @ONLY)

if(WIN32)
    set(HAVE_WINDOWS ON)
endif()

if(UNIX)
    set(HAVE_UNIX ON)
endif()

option(HAVE_EXAMPLES "Enable examples (default: disabled)" OFF)

option(HAVE_CLIENT "Enable client APIs (default: enabled)" ON)
if(HAVE_CLIENT)
    string(APPEND CONFIG_FEATURES client_apis,)
endif()

option(HAVE_SERVER "Enable server APIs (default: enabled)" ON)
if(HAVE_SERVER)
    string(APPEND CONFIG_FEATURES server_apis,)
endif()

option(HAVE_ERROR_STRINGS "Enable error string table (default: enabled)" ON)
if(HAVE_ERROR_STRINGS)
    string(APPEND CONFIG_FEATURES error_strings,)
endif()

option(HAVE_AESGCM "Enable AES-GCM bulk encryption (default: enabled)" ON)
if(HAVE_AESGCM)
    string(APPEND CONFIG_FEATURES aesgcm,)
endif()

option(HAVE_CHACHAPOLY "Enable Chacha20Poly1305 bulk encryption (default: enabled)" ON)
if(HAVE_CHACHAPOLY)
    string(APPEND CONFIG_FEATURES chachapoly,)
endif()

option(HAVE_TLS13 "Enable TLS 1.3" ON)
if(HAVE_TLS13)
    string(APPEND CONFIG_FEATURES tls13,)
endif()

option(HAVE_X25519 "Enable Curve25519 for key exchange (default: enabled)" ON)
if(HAVE_X25519)
    string(APPEND CONFIG_FEATURES x25519,)
endif()

option(HAVE_ECDH "Enable curve secp256r1 and secp384r1 for key exchange (default: enabled)" ON)
if(HAVE_ECDH)
    string(APPEND CONFIG_FEATURES ecdh,)
endif()

option(HAVE_ECDSA "Enable curve secp256r1 and secp384r1 for signature verification (default: enabled)" ON)
if(HAVE_ECDSA)
    string(APPEND CONFIG_FEATURES ecdsa,)
endif()

option(HAVE_SGX "Enable experimental SGX attestation (default: disabled)" OFF)
if(HAVE_SGX)
    string(APPEND CONFIG_FEATURES sgx,)
endif()

option(HAVE_SNI "Enable SNI Support" OFF)
if(NOT HAVE_SNI)
    string(APPEND CONFIG_FEATURES no_sni_check,)
endif()

option(HAVE_JEMALLOC "Enable Jemalloc" OFF)
if(HAVE_JEMALLOC)
    string(APPEND CONFIG_FEATURES jemalloc_allocator,)
endif()

string(APPEND CONFIG_FEATURES verifier,)

configure_file(${PROJECT_SOURCE_DIR}/mesalink/options.h.cmake.in ${PROJECT_SOURCE_DIR}/mesalink/options.h @ONLY)

# Build MesaLink and its examples
cargo_build(NAME mesalink CROSS_RUST_TARGET ${RUST_TARGET} FEATURES ${CONFIG_FEATURES})

if(UNIX AND HAVE_EXAMPLES)
    add_executable(client examples/client/client.c)
    target_include_directories(client PUBLIC ${CMAKE_SOURCE_DIR})
    target_link_libraries(client mesalink)

    add_executable(server examples/server/server.c)
    target_include_directories(server PUBLIC ${CMAKE_SOURCE_DIR})
    target_link_libraries(server mesalink)
endif()

# Install the MesaLink shared library and headers

include(GNUInstallDirs)
get_property(install_lib_files GLOBAL PROPERTY install_lib_files_property)
install(FILES ${install_lib_files}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    COMPONENT libraries
)

set(LIB_FILENAME_SHORTER "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}")

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(LIB_FILENAME "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}.${PROJECT_VERSION}")
    set(LIB_FILENAME_SHORT "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}.${PROJECT_VERSION_MAJOR}")
elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(LIB_FILENAME "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}.${PROJECT_VERSION}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(LIB_FILENAME_SHORT "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}.${PROJECT_VERSION_MAJOR}${CMAKE_SHARED_LIBRARY_SUFFIX}")
endif()

if(UNIX)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E rename ${LIB_FILENAME_SHORTER} ${LIB_FILENAME}
                                  WORKING_DIRECTORY ${CMAKE_INSTALL_FULL_LIBDIR})")
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${LIB_FILENAME} ${LIB_FILENAME_SHORT}
                                  WORKING_DIRECTORY ${CMAKE_INSTALL_FULL_LIBDIR})")
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${LIB_FILENAME} ${LIB_FILENAME_SHORTER}
                                  WORKING_DIRECTORY ${CMAKE_INSTALL_FULL_LIBDIR})")
endif()

install(DIRECTORY mesalink
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT headers
)

# Set up CPack
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "Github")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MesaLink - A memory-safe and OpenSSL-compatible TLS Library")
set(CPACK_PACKAGE_VERSION ${MESALINK_VERSION_STRING})
set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)

set(CPACK_COMPONENTS_ALL libraries headers)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "C Headers")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION
  "Shared and static libraries of MesaLink")
set(CPACK_COMPONENT_HEADERS_DESCRIPTION
  "C/C++ header files. OpenSSL compatible.")
set(CPACK_COMPONENT_HEADERS_DEPENDS libraries)
set(CPACK_COMPONENT_LIBRARIES_GROUP "Development")
set(CPACK_COMPONENT_HEADERS_GROUP "Development")

SET(CPACK_GENERATOR "TGZ")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Yiming Jing (jingyiming@baidu.com)")
INCLUDE(CPack)
