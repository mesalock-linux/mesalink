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

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_language(Rust)
include(CMakeCargo)

project(MesaLink VERSION 12.0.0)
set(LIB_NAME mesalink)

# Set up CPack
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MesaLink TLS Library")
SET(CPACK_GENERATOR "TGZ")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Yiming Jing (jingyiming@baidu.com)")
INCLUDE(CPack)

# Config options
set(MESALINK_VERSION ${PROJECT_VERSION})
configure_file(${PROJECT_SOURCE_DIR}/mesalink/version.h.cmake.in ${PROJECT_SOURCE_DIR}/mesalink/version.h @ONLY)

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

string(APPEND CONFIG_FEATURES verifier,)

option(HAVE_JEMALLOC "Enable Jemalloc" ON)
if(HAVE_JEMALLOC)
    string(APPEND CONFIG_FEATURES jemalloc_allocator,)
endif()

configure_file(${PROJECT_SOURCE_DIR}/mesalink/options.h.cmake.in ${PROJECT_SOURCE_DIR}/mesalink/options.h @ONLY)

# Build MesaLink and its examples
cargo_build(NAME mesalink FEATURES ${CONFIG_FEATURES})

set_target_properties(mesalink PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/mesalink"
)
add_executable(client_example examples/client/client.c)
target_link_libraries(client_example mesalink)
add_executable(server_example examples/server/server.c)
target_link_libraries(server_example mesalink)

# Install the MesaLink shared library and headers

include(GNUInstallDirs)
get_property(install_lib_files GLOBAL PROPERTY install_lib_files_property)
install(FILES ${install_lib_files} 
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

set(LIB "${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}")

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(SYMLINK_LONG "${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}.${PROJECT_VERSION}")
    set(SYMLINK_SHORT "${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}.${PROJECT_VERSION_MAJOR}")
elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(SYMLINK_LONG "${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}.${PROJECT_VERSION}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(SYMLINK_SHORT "${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}.${PROJECT_VERSION_MAJOR}${CMAKE_SHARED_LIBRARY_SUFFIX}")
endif()

install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${LIB} ${SYMLINK_LONG})")
install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${LIB} ${SYMLINK_SHORT})")

install(DIRECTORY mesalink DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})