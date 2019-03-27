cmake_minimum_required(VERSION 3.0)

project(MesaLink C CXX)
set(DEFAULT_BUILD_TYPE "Release")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_language(Rust)
include(CMakeCargo)

project(MesaLink LANGUAGES C VERSION 12.0.0)

add_subdirectory(src)
add_library(${PROJECT_NAME} SHARED src)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(LD_FLAGS_PRE "-Wl,-force_load")
    set(LD_FLAGS_POST "-Wl,-dead_strip -lm -ldl -lresolv -framework Security")
elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(LD_FLAGS_PRE "--Wl,--whole-archive")
    set(LD_FLAGS_POST "-Wl,--no-whole-archive -Wl,--gc-sections -pthread -lm -ldl")
elseif(CMAKE_SYSTEM_NAME STREQUAL Windows)
    set(LD_FLAGS_PRE "/WHOLEARCHIVE:")
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC
    ${LD_FLAGS_PRE}
    mesalink
    ${LD_FLAGS_POST}
)

set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 12)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER mesalink/*)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})