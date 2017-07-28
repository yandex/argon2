#pragma once

#include <emmintrin.h>
#include <tmmintrin.h>

namespace argonishche {
    static inline void xor_values(__m128i* result, __m128i* val1, __m128i* val2) {
        _mm_storeu_si128(result, _mm_xor_si128(
                _mm_loadu_si128(val1),
                _mm_loadu_si128(val2)
        ));
    }

    static inline __m128i rotr32(__m128i x) {
        return _mm_shuffle_epi32(x, _MM_SHUFFLE(2,3,0,1));
    }

    static inline __m128i rotr24(__m128i x) {
        return _mm_shuffle_epi8(x, _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10));
    }

    static inline __m128i rotr16(__m128i x) {
        return _mm_shuffle_epi8(x, _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9));
    }

    static inline __m128i rotr63(__m128i x) {
        return _mm_xor_si128(_mm_srli_epi64(x, 63), _mm_add_epi64(x, x));
    }
}
