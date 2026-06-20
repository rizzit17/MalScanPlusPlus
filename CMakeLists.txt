cmake_minimum_required(VERSION 3.20)
project(MalScan++ VERSION 1.0.0 LANGUAGES CXX)

# Standard C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable compiler warnings
if(MSVC)
    add_compile_options(/W4)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Dependencies using vcpkg
find_package(nlohmann_json CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)

# Include directories
include_directories(include)

# Gather source files (In production, list explicitly to avoid glob issues, but GLOB is fine for quick bootstrap)
file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp")
file(GLOB_RECURSE ANALYZER_SOURCES "src/analyzers/*.cpp")
file(GLOB_RECURSE REPORTING_SOURCES "src/reporting/*.cpp")
file(GLOB_RECURSE UTILS_SOURCES "src/utils/*.cpp")

# Core Library
add_library(malscan_core STATIC
    ${CORE_SOURCES}
    ${ANALYZER_SOURCES}
    ${REPORTING_SOURCES}
    ${UTILS_SOURCES}
)
target_link_libraries(malscan_core PRIVATE nlohmann_json::nlohmann_json cxxopts::cxxopts httplib::httplib)

# Main Executable
add_executable(scanner src/main.cpp)
target_link_libraries(scanner PRIVATE malscan_core httplib::httplib)

# Tests
enable_testing()
find_package(GTest CONFIG REQUIRED)

file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")

# If tests folder is empty initially, this prevents CMake errors
if(TEST_SOURCES)
    add_executable(malscan_tests ${TEST_SOURCES})
    target_link_libraries(malscan_tests PRIVATE malscan_core GTest::gtest GTest::gtest_main)
    add_test(NAME MalScan_UnitTests COMMAND malscan_tests)
endif()
