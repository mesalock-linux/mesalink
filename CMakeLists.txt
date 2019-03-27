cmake_minimum_required(VERSION 3.0)

project(MesaLink C CXX)
set(DEFAULT_BUILD_TYPE "Release")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_language(Rust)
include(CMakeCargo)

project(MesaLink VERSION 12.0.0)

add_subdirectory(src)
get_property(install_lib_file GLOBAL PROPERTY install_lib_file_property)
get_property(soname GLOBAL PROPERTY soname_property)

include(GNUInstallDirs)
install(FILES ${install_lib_file} 
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
install(DIRECTORY mesalink DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})