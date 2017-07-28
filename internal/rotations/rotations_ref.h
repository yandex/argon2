#pragma once

namespace argonishche {
    static inline uint64_t rotr(const uint64_t w, const unsigned c) {
        return (w >> c) | (w << (64 - c));
    }
}
