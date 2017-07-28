#include "argonishche.h"
#include "internal/proxies/proxy_macros.h"
#include "internal/proxies/ssse3/proxy_ssse3.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_ssse3.h"
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_ssse3.h"

#define ZEROUPPER ;

namespace argonishche {
    ARGON2_PROXY_CLASS_IMPL(SSSE3)
    BLAKE2B_PROXY_CLASS_IMPL(SSSE3)
}

#undef ZEROUPPER
