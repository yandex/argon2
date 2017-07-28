#include "proxy_sse41.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_sse41.h"
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_sse41.h"

#define ZEROUPPER ;

namespace argonishche {
    ARGON2_PROXY_CLASS_IMPL(SSE41)
    BLAKE2B_PROXY_CLASS_IMPL(SSE41)
}

#undef ZEROUPPER
