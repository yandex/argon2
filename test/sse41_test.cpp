#include <cstdint>
#include <iostream>
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_sse41.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_sse41.h"
#include "tests.h"

using namespace std;
using namespace argonishche;

DECLARE_BLAKE2B_TESTS(SSE41)
DECLARE_ARGON2_TESTS(SSE41)

int main(int argc, char** argv) {
    RUN_BLAKE2B_TESTS(SSE41)
    RUN_ARGON2_TESTS(SSE41)
    return 0;
}
