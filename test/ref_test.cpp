#include <cstdint>
#include <iostream>
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_ref.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_ref.h"
#include "tests.h"

using namespace std;
using namespace argonishche;

DECLARE_BLAKE2B_TESTS(REF)
DECLARE_ARGON2_TESTS(REF)

int main(int argc, char** argv) {
    RUN_BLAKE2B_TESTS(REF)
    RUN_ARGON2_TESTS(REF)
    return 0;
}
