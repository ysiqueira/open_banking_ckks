cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)

## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(utils LANGUAGES CXX)

# Define standard installation directories (GNU)
include(GNUInstallDirs)

# Set default output folder
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}")

find_package(helib EXACT REQUIRED)

add_executable(bapp bank_app.cpp)

target_link_libraries(bapp helib)

