#pragma once

#include "blake2b.h"
#include "internal/rotations/rotations_ref.h"

namespace argonishche {
    static const uint8_t sigma[12][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
    };

    static const uint64_t iv[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    static inline void G_REF(uint64_t r, uint64_t i, uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, const uint64_t* m) {
        a = a + b + m[sigma[r][2 * i + 0]];
        d = rotr(d ^ a, 32);
        c = c + d;
        b = rotr(b ^ c, 24);
        a = a + b + m[sigma[r][2 * i + 1]];
        d = rotr(d ^ a, 16);
        c = c + d;
        b = rotr(b ^ c, 63);
    }

    static inline void ROUND_REF(uint64_t r, uint64_t* v, const uint64_t* m) {
        G_REF(r, 0, v[ 0], v[ 4], v[ 8], v[12], m);
        G_REF(r, 1, v[ 1], v[ 5], v[ 9], v[13], m);
        G_REF(r, 2, v[ 2], v[ 6], v[10], v[14], m);
        G_REF(r, 3, v[ 3], v[ 7], v[11], v[15], m);
        G_REF(r, 4, v[ 0], v[ 5], v[10], v[15], m);
        G_REF(r, 5, v[ 1], v[ 6], v[11], v[12], m);
        G_REF(r, 6, v[ 2], v[ 7], v[ 8], v[13], m);
        G_REF(r, 7, v[ 3], v[ 4], v[ 9], v[14], m);
    }

    template<>
    void Blake2B<InstructionSet::REF>::initial_xor__(uint8_t *h, const uint8_t *p) {
        for(size_t i = 0; i < 8; ++i)
            ((uint64_t*)h)[i] = iv[i] ^ ((uint64_t*)p)[i];
    }

    template<>
    void Blake2B<InstructionSet::REF>::compress__(const uint8_t block[BLAKE2B_BLOCKBYTES])
    {
        uint64_t v[16];
        uint64_t* m = (uint64_t*)block;

        for(size_t i = 0; i < 8; ++i) {
            v[i] = state__.h[i];
        }

        v[ 8] = iv[0];
        v[ 9] = iv[1];
        v[10] = iv[2];
        v[11] = iv[3];
        v[12] = iv[4] ^ state__.t[0];
        v[13] = iv[5] ^ state__.t[1];
        v[14] = iv[6] ^ state__.f[0];
        v[15] = iv[7] ^ state__.f[1];

        for(uint64_t r = 0; r < 12; ++r)
            ROUND_REF(r, v, m);

        for(size_t i = 0; i < 8; ++i) {
            state__.h[i] = state__.h[i] ^ v[i] ^ v[i + 8];
        }
    }
}
