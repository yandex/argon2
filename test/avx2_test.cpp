#include <cstdint>
#include <iostream>

#include "argonishche.h"
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_avx2.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_avx2.h"
#include "tests.h"

using namespace std;
using namespace argonishche;

DECLARE_ARGON2_TESTS(AVX2)
DECLARE_BLAKE2B_TESTS(AVX2)

int main(int argc, char** argv) {
    RUN_BLAKE2B_TESTS(AVX2)
    RUN_ARGON2_TESTS(AVX2)
    return 0;
}
