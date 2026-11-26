# Linux C core build and installation. Other native targets remain unsupported.
cmake_minimum_required(VERSION 3.20)
project(Archx LANGUAGES C)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "The complete Archx C core currently supports Linux only; platform primitive tests are separate.")
endif()
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(Threads REQUIRED)
foreach(path_var IN ITEMS CMAKE_INSTALL_BINDIR CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR)
  if(IS_ABSOLUTE "${${path_var}}")
    message(FATAL_ERROR "${path_var} must be relative for a relocatable Archx installation")
  endif()
endforeach()
file(RELATIVE_PATH archx_lib_from_bin "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# The repository has not declared a release version; expose the existing ABI
# version without inventing a package release number or compatibility range.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/archx.h" abi_line REGEX "^#define AX_ABI_VERSION [0-9]+$")
if(NOT abi_line MATCHES "^#define AX_ABI_VERSION ([0-9]+)$")
  message(FATAL_ERROR "Could not read the public ABI version")
endif()
set(ARCHX_ABI_VERSION "${CMAKE_MATCH_1}")

set(core_sources src/archx.c src/sha256.c src/json.c src/signals_linux.c src/signals.c
    src/store.c src/platform_posix.c src/platform_linux.c)
add_library(archx_objects OBJECT ${core_sources})
set_target_properties(archx_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(archx_objects PRIVATE include src)
target_compile_definitions(archx_objects PRIVATE _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
target_compile_options(archx_objects PRIVATE -Wall -Wextra -Wpedantic)

add_library(archx_shared SHARED $<TARGET_OBJECTS:archx_objects>)
add_library(archx_static STATIC $<TARGET_OBJECTS:archx_objects>)
foreach(target IN ITEMS archx_shared archx_static)
  set_target_properties(${target} PROPERTIES OUTPUT_NAME archx)
  target_include_directories(${target} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
  target_link_libraries(${target} PRIVATE Threads::Threads m)
endforeach()
set_target_properties(archx_shared PROPERTIES EXPORT_NAME core SOVERSION "${ARCHX_ABI_VERSION}")
set_target_properties(archx_static PROPERTIES EXPORT_NAME static)
add_library(Archx::core ALIAS archx_shared)
add_library(Archx::static ALIAS archx_static)

add_executable(archx-probe tools/archx-probe.c)
target_compile_definitions(archx-probe PRIVATE _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
target_compile_options(archx-probe PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(archx-probe PRIVATE archx_shared)
set_target_properties(archx-probe PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
  INSTALL_RPATH "$ORIGIN/${archx_lib_from_bin}")

set(package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/Archx")
configure_package_config_file(cmake/ArchxConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/ArchxConfig.cmake" INSTALL_DESTINATION "${package_dir}")
install(TARGETS archx_shared archx_static EXPORT ArchxTargets
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(TARGETS archx-probe RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES include/archx.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(EXPORT ArchxTargets FILE ArchxTargets.cmake NAMESPACE Archx:: DESTINATION "${package_dir}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ArchxConfig.cmake" DESTINATION "${package_dir}")
