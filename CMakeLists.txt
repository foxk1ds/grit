cmake_minimum_required(VERSION 3.20)
project(grit C)

# Enforce C23 standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Compiler flags for defensive systems programming
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror=implicit-function-declaration
    -pthread
    -fstack-protector-strong
)

# Optional include and library fallbacks
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
link_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

# Package Discovery
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(GTK4 gtk4)
    pkg_check_modules(ADWAITA libadwaita-1)
endif()
find_package(SQLite3 QUIET)
find_package(CURL QUIET)
find_package(Threads REQUIRED)

# Fallback libraries for sqlite3 and curl if not found via CMake module
if(TARGET SQLite::SQLite3)
    set(SQLITE3_LIB SQLite::SQLite3)
else()
    set(SQLITE3_LIB sqlite3)
endif()

if(TARGET CURL::libcurl)
    set(CURL_LIB CURL::libcurl)
else()
    set(CURL_LIB curl)
endif()

# Core Library Sources
set(CORE_SOURCES
    src/core/watcher.c
    src/core/simulator.c
    src/mentor/command_guard.c
    src/mentor/llm_client.c
    src/db/db.c
)

# Shared Library Target (libgrit.so for Python ctypes / modular linking)
add_library(grit_shared SHARED ${CORE_SOURCES})
set_target_properties(grit_shared PROPERTIES OUTPUT_NAME "grit")
target_link_libraries(grit_shared PRIVATE
    Threads::Threads
    ${SQLITE3_LIB}
    ${CURL_LIB}
)

# Standalone Executable Target (grit)
add_executable(grit
    src/main.c
    ${CORE_SOURCES}
)

if(GTK4_FOUND)
    target_compile_definitions(grit PRIVATE HAVE_GTK4=1)
    target_link_libraries(grit PRIVATE PkgConfig::GTK4)
endif()

if(ADWAITA_FOUND)
    target_link_libraries(grit PRIVATE PkgConfig::ADWAITA)
endif()

target_link_libraries(grit PRIVATE
    Threads::Threads
    ${SQLITE3_LIB}
    ${CURL_LIB}
)

# Test Harness Targets
option(BUILD_TESTS "Build Grit verification test runners" ON)

if(BUILD_TESTS)
    # End-to-End Pipeline Test
    add_executable(grit_pipeline_test
        tests/test_full_pipeline.c
        ${CORE_SOURCES}
    )
    target_link_libraries(grit_pipeline_test PRIVATE
        Threads::Threads
        ${SQLITE3_LIB}
        ${CURL_LIB}
    )
    target_include_directories(grit_pipeline_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    # Core Watcher & Redaction Test
    add_executable(grit_test
        tests/test_watcher_guard.c
        src/core/watcher.c
        src/mentor/command_guard.c
        src/db/db.c
    )
    target_link_libraries(grit_test PRIVATE
        Threads::Threads
        ${SQLITE3_LIB}
    )
    target_include_directories(grit_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    # LLM Orchestration Test
    add_executable(grit_llm_test
        tests/test_llm_client.c
        src/mentor/llm_client.c
        src/mentor/command_guard.c
        src/db/db.c
    )
    target_link_libraries(grit_llm_test PRIVATE
        Threads::Threads
        ${SQLITE3_LIB}
        ${CURL_LIB}
    )
    target_include_directories(grit_llm_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
endif()

# Installation Targets (GNOME Desktop Integration & FreeDesktop Icons)
install(TARGETS grit_shared DESTINATION lib)
install(FILES data/org.grit.workstation.desktop DESTINATION share/applications)
install(FILES data/icons/hicolor/scalable/apps/org.grit.workstation.svg DESTINATION share/icons/hicolor/scalable/apps)
foreach(SIZE 16 24 32 48 64 128 256 512)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/data/icons/hicolor/${SIZE}x${SIZE}/apps/org.grit.workstation.png")
        install(FILES data/icons/hicolor/${SIZE}x${SIZE}/apps/org.grit.workstation.png DESTINATION share/icons/hicolor/${SIZE}x${SIZE}/apps)
    endif()
endforeach()

