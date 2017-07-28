#pragma once

#include <immintrin.h>

namespace argonishche {
    static inline void xor_values(__m256i* result, const __m256i* val1, const __m256i* val2) {
        _mm256_storeu_si256(result, _mm256_xor_si256(
                _mm256_loadu_si256(val1), _mm256_loadu_si256(val2)
        ));
    }

    static inline __m256i rotr32(__m256i x) {
        return _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
    }

    static inline __m256i rotr24(__m256i x) {
        return _mm256_shuffle_epi8(x, _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10
        ));
    }

    static inline __m256i rotr16(__m256i x) {
        return _mm256_shuffle_epi8(x, _mm256_setr_epi8(
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9
        ));
    }

    static inline __m256i rotr63(__m256i x) {
        return _mm256_xor_si256(_mm256_srli_epi64(x, 63), _mm256_add_epi64(x, x));
    }
}
