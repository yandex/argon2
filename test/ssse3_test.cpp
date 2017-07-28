#include <cstdint>
#include <iostream>

#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_ssse3.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_ssse3.h"
#include "tests.h"

using namespace std;
using namespace argonishche;

DECLARE_BLAKE2B_TESTS(SSSE3)
DECLARE_ARGON2_TESTS(SSSE3)

int main(int argc, char** argv) {
    RUN_BLAKE2B_TESTS(SSSE3)
    RUN_ARGON2_TESTS(SSSE3)
    return 0;
}
