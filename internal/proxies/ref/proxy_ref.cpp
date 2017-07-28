#include "proxy_ref.h"
#include "internal/argon2/argon2_base.h"
#include "internal/argon2/argon2_ref.h"
#include "internal/blake2b/blake2b.h"
#include "internal/blake2b/blake2b_ref.h"

#include <stdexcept>

#define ZEROUPPER ;

namespace argonishche {
    ARGON2_PROXY_CLASS_IMPL(REF)
    BLAKE2B_PROXY_CLASS_IMPL(REF)
}

#undef ZEROUPPER
