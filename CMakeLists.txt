cmake_minimum_required(VERSION 3.0)

project(MesaLink C CXX)
set(DEFAULT_BUILD_TYPE "Release")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_language(Rust)
include(CMakeCargo)

project(MesaLink VERSION 12.0.0)
set(LIB_NAME mesalink)

# Config options
set(CONFIG_FEATURES "")
option(WITH_TLS_13 "Enable TLS 1.3" ON)

if(WITH_TLS_13)
    list(APPEND CONFIG_FEATURES "tls13")
endif()

# Build MesaLink and its examples

cargo_build(NAME mesalink)
set_target_properties(mesalink PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/mesalink"
)
add_executable(client_example examples/client/client.c)
target_link_libraries(client_example mesalink)
add_executable(server_example examples/server/server.c)
target_link_libraries(server_example mesalink)

# Install the MesaLink shared library and headers

include(GNUInstallDirs)
get_property(install_lib_file GLOBAL PROPERTY install_lib_file_property)
install(FILES ${install_lib_file} 
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