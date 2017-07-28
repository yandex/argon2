set(CMAKE_CXX_STANDARD 14)

set_source_files_properties(ref_test.cpp PROPERTIES COMPILE_FLAGS "-m64")
add_executable(test_ref ref_test.cpp)
target_link_libraries(test_ref argonishche)
add_test(test_ref test_ref)

set_source_files_properties(sse2_test.cpp PROPERTIES COMPILE_FLAGS "-msse2")
add_executable(test_sse2 sse2_test.cpp)
target_link_libraries(test_sse2 argonishche)
add_test(test_sse2 test_sse2)

set_source_files_properties(ssse3_test.cpp PROPERTIES COMPILE_FLAGS "-mssse3")
add_executable(test_ssse3 ssse3_test.cpp)
target_link_libraries(test_ssse3 argonishche)
add_test(test_ssse3 test_ssse3)

set_source_files_properties(sse41_test.cpp PROPERTIES COMPILE_FLAGS "-msse4.1")
add_executable(test_sse41 sse41_test.cpp)
target_link_libraries(test_sse41 argonishche)
add_test(test_sse41 test_sse41)

set_source_files_properties(avx2_test.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mbmi -mbmi2")
add_executable(test_avx2 avx2_test.cpp)
target_link_libraries(test_avx2 argonishche)
add_test(test_avx2 test_avx2)

add_executable(test_cpuid cpuid_test.cpp)
target_link_libraries(test_cpuid argonishche)
add_test(test_cpuid test_cpuid)

add_executable(test_factory factory_test.cpp)
target_link_libraries(test_factory argonishche)
add_test(test_factory test_factory)

add_executable(test_sde sde.cpp)
target_link_libraries(test_sde argonishche)
add_test(test_sde test_sde)
