#pragma once

namespace argonishche {
    static const __m128i* get_iv() {
        static const __m128i iv[4] = {
                _mm_set_epi64x(0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL),
                _mm_set_epi64x(0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL),
                _mm_set_epi64x(0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL),
                _mm_set_epi64x(0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL)
        };

        return iv;
    }
}
