cmake_minimum_required(VERSION 3.25)
project(libmobile VERSION 0.2.99)

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
set(lt_current  0)
set(lt_revision 0)
set(lt_age      0)
math(EXPR lt_soversion "${lt_current} - ${lt_age}")
set(lt_version "${lt_soversion}.${lt_current}.${lt_age}")

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
option(LIBMOBILE_BUILD_SHARED "Build shared library" ON)
option(LIBMOBILE_BUILD_STATIC "Build static library" ON)
include(CMakeOptions.txt)

# Disable shared libs when the target doesn't support it
get_property(TARGET_SUPPORTS_SHARED_LIBS GLOBAL PROPERTY
    TARGET_SUPPORTS_SHARED_LIBS)
if(NOT TARGET_SUPPORTS_SHARED_LIBS)
    set(LIBMOBILE_BUILD_SHARED OFF)
endif()

set(c_args)
set(c_defs
    MOBILE_LIBCONF_USE
)

# Default cflags
if(NOT MSVC)
    list(APPEND c_args -Wall -Wextra)
endif()

# Variables for configure_file
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX})
set(libdir ${CMAKE_INSTALL_FULL_LIBDIR})
set(includedir ${CMAKE_INSTALL_FULL_INCLUDEDIR})
set(PACKAGE ${CMAKE_PROJECT_NAME})
set(VERSION ${CMAKE_PROJECT_VERSION})

set(MOBILE_ENABLE_IMPL_WEAK ${LIBMOBILE_ENABLE_IMPL_WEAK})
set(MOBILE_ENABLE_NOALLOC ${LIBMOBILE_ENABLE_NOALLOC})
set(MOBILE_ENABLE_NO32BIT ${LIBMOBILE_ENABLE_NO32BIT})

configure_file(mobile_config.cmake.h.in mobile_config.h)
configure_file(libmobile.pc.in libmobile.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libmobile.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

set(sources
    atomic.h
    callback.c
    callback.h
    commands.c
    commands.h
    compat.h
    config.c
    config.h
    debug.c
    debug.h
    device_auth.c
    device_auth.h
    dns.c
    dns.h
    global.h
    inet_pton.c
    md5.c
    md5.h
    mobile.c
    mobile_data.h
    pop3_auth.c
    pop3_auth.h
    relay.c
    relay.h
    serial.c
    serial.h
    sha256.c
    sha256.h
    util.c
    util.h
)

set(headers
    mobile.h
    mobile_inet.h
)

foreach(flavor shared static)
    string(TOUPPER ${flavor} flavor_up)
    if(NOT LIBMOBILE_BUILD_${flavor_up})
        continue()
    endif()

    add_library(libmobile_${flavor} ${flavor_up})
    target_sources(libmobile_${flavor} PRIVATE ${sources})
    target_include_directories(libmobile_${flavor} PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_options(libmobile_${flavor} PRIVATE ${c_args})
    target_compile_definitions(libmobile_${flavor} PRIVATE ${c_defs})
    set_target_properties(libmobile_${flavor} PROPERTIES
        OUTPUT_NAME mobile
        VERSION ${lt_version}
        SOVERSION ${lt_soversion})
    install(TARGETS libmobile_${flavor} DESTINATION ${CMAKE_INSTALL_LIBDIR})

    # Options for projects including this library
    target_include_directories(libmobile_${flavor} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_definitions(libmobile_${flavor} PUBLIC
        MOBILE_LIBCONF_USE)
endforeach()

# Alias for the default library type
if(BUILD_SHARED_LIBS AND LIBMOBILE_BUILD_SHARED)
    add_library(libmobile ALIAS libmobile_shared)
elseif(LIBMOBILE_BUILD_STATIC)
    add_library(libmobile ALIAS libmobile_static)
endif()

# Install the headers
install(FILES ${headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Tests -- off by default when this is pulled in as a subproject (mGBA,
#   libmobile-bgb, PicoAdapterGB all add_subdirectory() this), on when it's
#   built directly.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    option(LIBMOBILE_BUILD_TESTS "Build the test suite" ON)
else()
    option(LIBMOBILE_BUILD_TESTS "Build the test suite" OFF)
endif()

if(LIBMOBILE_BUILD_TESTS)
    enable_testing()
    file(GLOB test_sources CONFIGURE_DEPENDS tests/*.c)
    foreach(test_source ${test_sources})
        get_filename_component(test_name ${test_source} NAME_WE)
        add_executable(${test_name} ${test_source})
        target_link_libraries(${test_name} PRIVATE libmobile)
        target_compile_options(${test_name} PRIVATE ${c_args})
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()
