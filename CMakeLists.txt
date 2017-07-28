cmake_minimum_required(VERSION 3.5)
project(argon2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall")

option(BUILD_TESTS "Build tests." ON)
option(BUILD_BENCHMARK "Build benchmark." ON)

option(BUILD_WITH_OPENMP "Use OpenMP" ON)
if(BUILD_WITH_OPENMP)
    find_package(OpenMP)
    if(OPENMP_FOUND)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    else()
        message(WARNING
                "OpenMP package not found! Argon2 will process sequentially that may result in lower performance if threads > 1 are used!")
    endif()
endif()

include_directories(.)

set(SOURCE_FILES_LIB
        internal/proxies/ref/proxy_ref.cpp
        internal/proxies/sse2/proxy_sse2.cpp
        internal/proxies/ssse3/proxy_ssse3.cpp
        internal/proxies/sse41/proxy_sse41.cpp
        internal/proxies/avx2/proxy_avx2.cpp
        cpuid/cpuid.cpp
        factory/factory.cpp
        factory/utils.cpp
        )

set_source_files_properties(internal/proxies/ref/proxy_ref.cpp PROPERTIES COMPILE_FLAGS "-m64")
set_source_files_properties(internal/proxies/sse2/proxy_sse2.cpp PROPERTIES COMPILE_FLAGS "-msse2")
set_source_files_properties(internal/proxies/ssse3/proxy_ssse3.cpp PROPERTIES COMPILE_FLAGS "-mssse3")
set_source_files_properties(internal/proxies/sse41/proxy_sse41.cpp PROPERTIES COMPILE_FLAGS "-msse4.1")
set_source_files_properties(internal/proxies/avx2/proxy_avx2.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mbmi2")

add_library(argonishche STATIC ${SOURCE_FILES_LIB})
add_library(argonishche_sh SHARED ${SOURCE_FILES_LIB})
set_target_properties(argonishche_sh PROPERTIES OUTPUT_NAME argonishche)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(BUILD_BENCHMARK)
    add_subdirectory(benchmark)
endif()
