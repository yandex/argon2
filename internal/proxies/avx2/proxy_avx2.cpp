#include "proxy_avx2.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_avx2.h"
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_avx2.h"

#define ZEROUPPER _mm256_zeroupper();

namespace argonishche {
    ARGON2_PROXY_CLASS_IMPL(AVX2)
    BLAKE2B_PROXY_CLASS_IMPL(AVX2)
}

#undef ZEROUPPER
