function(cargo_build)
    set(one_value_args NAME CROSS_RUST_TARGET)
    cmake_parse_arguments(CARGO "" "${one_value_args}" "FEATURES" ${ARGN})
    string(REPLACE "-" "_" LIB_NAME ${CARGO_NAME})
    set(CARGO_FEATURE_ARG --no-default-features --features ${CARGO_FEATURES})
    
    set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR})

    if(CARGO_CROSS_RUST_TARGET)
        set(LIB_TARGET ${CARGO_CROSS_RUST_TARGET})
    else()
        if(WIN32)
            if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                set(LIB_TARGET "x86_64-pc-windows-msvc")
            else()
                set(LIB_TARGET "i686-pc-windows-msvc")
            endif()
	    elseif(ANDROID)
            if(ANDROID_SYSROOT_ABI STREQUAL "x86")
                set(LIB_TARGET "i686-linux-android")
            elseif(ANDROID_SYSROOT_ABI STREQUAL "x86_64")
                set(LIB_TARGET "x86_64-linux-android")
            elseif(ANDROID_SYSROOT_ABI STREQUAL "arm")
                set(LIB_TARGET "arm-linux-androideabi")
            elseif(ANDROID_SYSROOT_ABI STREQUAL "arm64")
                set(LIB_TARGET "aarch64-linux-android")
            endif()
        elseif(IOS)
            set(LIB_TARGET "universal")
        elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
            set(LIB_TARGET "x86_64-apple-darwin")
	    else()
            if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                set(LIB_TARGET "x86_64-unknown-linux-gnu")
            else()
                set(LIB_TARGET "i686-unknown-linux-gnu")
            endif()
        endif()
    endif()

    if(NOT CMAKE_BUILD_TYPE)
        set(LIB_BUILD_TYPE "release")
    elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(LIB_BUILD_TYPE "release")
    else()
        set(LIB_BUILD_TYPE "debug")
    endif()

    set(STATIC_LIB_FILE "${CARGO_TARGET_DIR}/${LIB_TARGET}/${LIB_BUILD_TYPE}/${CMAKE_STATIC_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}")
    
    set(SHARED_LIB_FILE "${CARGO_TARGET_DIR}/${LIB_TARGET}/${LIB_BUILD_TYPE}/${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    
    list(APPEND LIB_FILES ${STATIC_LIB_FILE})
    list(APPEND LIB_FILES ${SHARED_LIB_FILE})

    if(WIN32)
        set(SHARED_LIB_INDEX_FILE "${CARGO_TARGET_DIR}/${LIB_TARGET}/${LIB_BUILD_TYPE}/${CMAKE_STATIC_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        list(APPEND LIB_FILES ${SHARED_LIB_INDEX_FILE})
    endif()

    set_property(GLOBAL PROPERTY install_lib_files_property ${LIB_FILES})

    if(CMAKE_SYSTEM_NAME STREQUAL Linux)
        set(SONAME "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}.${PROJECT_VERSION_MAJOR}")
    elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
        set(SONAME "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}.${PROJECT_VERSION_MAJOR}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    endif()
    set_property(GLOBAL PROPERTY soname_property "${SONAME}")

	if(IOS)
		set(CARGO_ARGS "lipo")
	else()
    	set(CARGO_ARGS "build")
		list(APPEND CARGO_ARGS "--target" ${LIB_TARGET})
	endif()

    if(${LIB_BUILD_TYPE} STREQUAL "release")
        list(APPEND CARGO_ARGS "--release")
    endif()

    file(GLOB_RECURSE LIB_SOURCES "*.rs")

    if(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
        set(CARGO_LINKER_ARGS "-C linker=${CMAKE_C_COMPILER} -C link-arg=-Wl,-soname -C link-arg=-Wl,${SONAME}" VERBATIM)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL Clang)
        set(CARGO_LINKER_ARGS "\
            -C linker=${CMAKE_C_COMPILER} \
            -C link-arg=-Wl,-install_name -C link-arg=-Wl,${SONAME} \
            -C link-arg=-Wl,-compatibility_version -C link-arg=-Wl,${PROJECT_VERSION_MAJOR} \
            -C link-arg=-Wl,-current_version -C link-arg=-Wl,${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}" VERBATIM)
    else()
        set(CARGO_LINKER_ARGS "-C linker=${CMAKE_C_COMPILER}" VERBATIM)
    endif()

    set(CARGO_ENV_COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" "RUSTFLAGS=${CARGO_LINKER_ARGS}")

    add_custom_command(
        OUTPUT ${LIB_FILES}
        COMMAND ${CARGO_ENV_COMMAND} ${CARGO_LINKER_ARGS_COMMAND} ${CARGO_EXECUTABLE} ARGS ${CARGO_ARGS} ${CARGO_FEATURE_ARG}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${LIB_SOURCES}
        COMMENT "running cargo")
    add_custom_target(${CARGO_NAME}_target ALL DEPENDS ${LIB_FILES})
    add_library(${CARGO_NAME} SHARED IMPORTED GLOBAL)
    add_dependencies(${CARGO_NAME} ${CARGO_NAME}_target)
    set_target_properties(${CARGO_NAME} PROPERTIES IMPORTED_LOCATION ${SHARED_LIB_FILE})
endfunction()