#pragma once

#include <cstdint>
#include "argonishche.h"
#include "internal/proxies/proxy_macros.h"

namespace argonishche {
    ARGON2_PROXY_CLASS_DECL(SSE41)
    BLAKE2B_PROXY_CLASS_DECL(SSE41)
}
