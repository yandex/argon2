#pragma once

#include "argon2_base.h"
#include "internal/rotations/rotations_ref.h"

namespace argonishche {

    static inline uint64_t FBlaMka(uint64_t x, uint64_t y) {
        const uint64_t m = 0xFFFFFFFF;
        const uint64_t xy = (x & m) * (y & m);
        return x + y + 2 * xy;
    }

    static inline void BlamkaGRef(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) {
        a = FBlaMka(a, b);
        d = rotr(d ^ a, 32);
        c = FBlaMka(c, d);
        b = rotr(b ^ c, 24);
        a = FBlaMka(a, b);
        d = rotr(d ^ a, 16);
        c = FBlaMka(c, d);
        b = rotr(b ^ c, 63);
}

    static inline void BlamkaRoundRef(
        uint64_t&  v0, uint64_t&  v1, uint64_t&  v2, uint64_t&  v3,
        uint64_t&  v4, uint64_t&  v5, uint64_t&  v6, uint64_t&  v7,
        uint64_t&  v8, uint64_t&  v9, uint64_t& v10, uint64_t& v11,
        uint64_t& v12, uint64_t& v13, uint64_t& v14, uint64_t& v15
    ) {
        BlamkaGRef(v0, v4,  v8, v12);
        BlamkaGRef(v1, v5,  v9, v13);
        BlamkaGRef(v2, v6, v10, v14);
        BlamkaGRef(v3, v7, v11, v15);
        BlamkaGRef(v0, v5, v10, v15);
        BlamkaGRef(v1, v6, v11, v12);
        BlamkaGRef(v2, v7,  v8, v13);
        BlamkaGRef(v3, v4,  v9, v14);
    }

    template<uint32_t mcost, uint32_t threads>
    class Argon2REF final : public Argon2<InstructionSet::REF, mcost, threads> {
    public:
        Argon2REF(Argon2Type atype, uint32_t tcost, const uint8_t *key, uint32_t keylen)
                : Argon2<InstructionSet::REF, mcost, threads>(atype, tcost, key, keylen) { }

    protected:
        virtual void xor_block__(block *dst, const block *src) const override {
            for (uint32_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
                dst->v[i] ^= src->v[i];
            }
        }

        virtual void copy_block__(block *dst, const block *src) const override {
            memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }

        virtual void fill_block__(const block *prev_block, const block *ref_block, block *next_block, bool with_xor) const override
        {
            block blockR, block_tmp;
            copy_block__(&blockR, ref_block);
            xor_block__(&blockR, prev_block);
            copy_block__(&block_tmp, &blockR);

            if (with_xor)
                xor_block__(&block_tmp, next_block);

            for (uint32_t i = 0; i < 8; ++i) {
                BlamkaRoundRef(
                        blockR.v[16 * i +  0], blockR.v[16 * i +  1], blockR.v[16 * i +  2], blockR.v[16 * i +  3],
                        blockR.v[16 * i +  4], blockR.v[16 * i +  5], blockR.v[16 * i +  6], blockR.v[16 * i +  7],
                        blockR.v[16 * i +  8], blockR.v[16 * i +  9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
                        blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14], blockR.v[16 * i + 15]);
            }

            for (uint32_t i = 0; i < 8; ++i) {
                BlamkaRoundRef(
                        blockR.v[2 * i +  0], blockR.v[2 * i +  1], blockR.v[2 * i +  16], blockR.v[2 * i +  17],
                        blockR.v[2 * i + 32], blockR.v[2 * i + 33], blockR.v[2 * i +  48], blockR.v[2 * i +  49],
                        blockR.v[2 * i + 64], blockR.v[2 * i + 65], blockR.v[2 * i +  80], blockR.v[2 * i +  81],
                        blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112], blockR.v[2 * i + 113]);
            }

            copy_block__(next_block, &block_tmp);
            xor_block__(next_block, &blockR);
        }
    };
}
