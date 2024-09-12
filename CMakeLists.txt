cmake_minimum_required(VERSION 3.0)

project(VectorizedBatchPIR)

# Set the build directory
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
# Set the output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    SET(OPENSSL_LIBRARIES /usr/local/openssl/lib64/libcrypto.a /usr/local/openssl/lib64/libssl.a)
    SET(OPENSSL_INCLUDE_DIR /usr/local/openssl/include)
    SET(OPENSSL_DIR /usr/local/openssl/lib64)
ELSEIF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    SET(OPENSSL_LIBRARIES /usr/local/lib/libcrypto.a /usr/local/lib/libssl.a)
    SET(OPENSSL_INCLUDE_DIR /usr/local/include)
    SET(OPENSSL_DIR /usr/local/lib)
ENDIF()

FIND_PACKAGE(OpenMP REQUIRED)

# Add seal library
if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/SEAL/native/src/CMakeLists.txt")
    find_package(Git REQUIRED)
    message("initialize Git submodule: extern/SEAL")
    execute_process(COMMAND git submodule update --init --recursive extern/SEAL
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
endif()
option(SEAL_USE_ZLIB ${SEAL_USE_ZLIB_OPTION_STR} OFF)
option(SEAL_USE_ZSTD ${SEAL_USE_ZSTD_OPTION_STR} OFF)
add_subdirectory(extern/SEAL)

# Add Kunlun library
if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/Kunlun/CMakeLists.txt")
    find_package(Git REQUIRED)
    message("initialize Git submodule: extern/Kunlun")
    execute_process(COMMAND git submodule update --init --recursive extern/Kunlun
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
endif()

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -fpic -Wno-deprecated-declarations -Wno-unused-result -Wno-ignored-attributes -Xpreprocessor -O3 -msse4.1")

SET(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -ldl")

# Get all source files under src
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create static library target and add source files
add_library(vectorized_batch_pir STATIC ${SOURCES})

# Set include directories
target_include_directories(vectorized_batch_pir PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/header ${CMAKE_CURRENT_SOURCE_DIR}/extern ${OPENSSL_INCLUDE_DIR})

target_link_libraries(vectorized_batch_pir SEAL::seal ${OPENSSL_LIBRARIES} OpenMP::OpenMP_CXX)

# Add compiler flags for optimization
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vectorized_batch_pir PRIVATE "-O3")
endif()

