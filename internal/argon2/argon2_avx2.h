#pragma once

#include <immintrin.h>
#include "argon2_base.h"
#include "internal/blamka/blamka_avx2.h"

namespace argonishche {

    template<uint32_t mcost, uint32_t threads>
    class Argon2AVX2 final : public Argon2<InstructionSet::AVX2, mcost, threads> {
    public:
        Argon2AVX2(Argon2Type atype, uint32_t tcost, const uint8_t* key, uint32_t keylen)
                : Argon2<InstructionSet::AVX2, mcost, threads>(atype, tcost, key, keylen) { }

    protected:
        virtual void xor_block__(block *dst, const block *src) const override {
            __m256i* mdst = (__m256i*)dst;
            __m256i* msrc = (__m256i*)src;

            for(uint32_t i = 0; i < ARGON2_HWORDS_IN_BLOCK; ++i)
                xor_values(mdst + i, mdst + i, msrc + i);
        }

        virtual void copy_block__(block *dst, const block *src) const override {
            memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }

        virtual void fill_block__(const block *prev_block, const block *ref_block, block *next_block, bool with_xor) const override {
            __m256i block_XY[ARGON2_HWORDS_IN_BLOCK];
            __m256i state[ARGON2_HWORDS_IN_BLOCK];

            memcpy(state, prev_block, ARGON2_BLOCK_SIZE);

            if (with_xor) {
                for (uint32_t i = 0; i < ARGON2_HWORDS_IN_BLOCK; ++i) {
                    state[i] = _mm256_xor_si256(state[i], _mm256_loadu_si256((const __m256i *) ref_block->v + i));
                    block_XY[i] = _mm256_xor_si256(state[i], _mm256_loadu_si256((const __m256i *) next_block->v + i));
                }
            } else {
                for (uint32_t i = 0; i < ARGON2_HWORDS_IN_BLOCK; ++i) {
                    block_XY[i] = state[i] = _mm256_xor_si256(
                            state[i], _mm256_loadu_si256((const __m256i *) ref_block->v + i));
                }
            }

            /**
             * state[ 8*i + 0 ] = ( v0_0,  v1_0,  v2_0,  v3_0)
             * state[ 8*i + 1 ] = ( v4_0,  v5_0,  v6_0,  v7_0)
             * state[ 8*i + 2 ] = ( v8_0,  v9_0, v10_0, v11_0)
             * state[ 8*i + 3 ] = (v12_0, v13_0, v14_0, v15_0)
             * state[ 8*i + 4 ] = ( v0_1,  v1_1,  v2_1,  v3_1)
             * state[ 8*i + 5 ] = ( v4_1,  v5_1,  v6_1,  v7_1)
             * state[ 8*i + 6 ] = ( v8_1,  v9_1, v10_1, v11_1)
             * state[ 8*i + 7 ] = (v12_1, v13_1, v14_1, v15_1)
             */
            for (uint32_t i = 0; i < 4; ++i) {
                BLAMKA_G1_AVX2(
                        state[8 * i + 0], state[8 * i + 4], state[8 * i + 1], state[8 * i + 5],
                        state[8 * i + 2], state[8 * i + 6], state[8 * i + 3], state[8 * i + 7]
                );
                BLAMKA_G2_AVX2(
                        state[8 * i + 0], state[8 * i + 4], state[8 * i + 1], state[8 * i + 5],
                        state[8 * i + 2], state[8 * i + 6], state[8 * i + 3], state[8 * i + 7]
                );

                DIAGONALIZE_AVX2_1(
                        state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]
                );
                BLAMKA_G1_AVX2(
                        state[8 * i + 0], state[8 * i + 4], state[8 * i + 1], state[8 * i + 5],
                        state[8 * i + 2], state[8 * i + 6], state[8 * i + 3], state[8 * i + 7]
                );
                BLAMKA_G2_AVX2(
                        state[8 * i + 0], state[8 * i + 4], state[8 * i + 1], state[8 * i + 5],
                        state[8 * i + 2], state[8 * i + 6], state[8 * i + 3], state[8 * i + 7]
                );
                UNDIAGONALIZE_AVX2_1(
                        state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]
                );
            }

            /**
             * state[ 0 + i] = ( v0_0,  v1_0,  v0_1,  v1_1)
             * state[ 4 + i] = ( v2_0,  v3_0,  v2_1,  v3_1)
             * state[ 8 + i] = ( v4_0,  v5_0,  v4_1,  v5_1)
             * state[12 + i] = ( v6_0,  v7_0,  v6_1,  v7_1)
             * state[16 + i] = ( v8_0,  v9_0,  v8_1,  v9_1)
             * state[20 + i] = (v10_0, v11_0, v10_1, v11_1)
             * state[24 + i] = (v12_0, v13_0, v12_1, v13_1)
             * state[28 + i] = (v14_0, v15_0, v14_1, v15_1)
             */
            for(uint32_t i = 0; i < 4; ++i) {
                BLAMKA_G1_AVX2(
                        state[ 0 + i], state[ 4 + i], state[ 8 + i], state[12 + i],
                        state[16 + i], state[20 + i], state[24 + i], state[28 + i]
                );
                BLAMKA_G2_AVX2(
                        state[ 0 + i], state[ 4 + i], state[ 8 + i], state[12 + i],
                        state[16 + i], state[20 + i], state[24 + i], state[28 + i]
                );
                DIAGONALIZE_AVX2_2(
                        state[ 8 + i], state[12 + i],
                        state[16 + i], state[20 + i],
                        state[24 + i], state[28 + i]
                );
                BLAMKA_G1_AVX2(
                        state[ 0 + i], state[ 4 + i], state[ 8 + i], state[12 + i],
                        state[16 + i], state[20 + i], state[24 + i], state[28 + i]
                );
                BLAMKA_G2_AVX2(
                        state[ 0 + i], state[ 4 + i], state[ 8 + i], state[12 + i],
                        state[16 + i], state[20 + i], state[24 + i], state[28 + i]
                );
                UNDIAGONALIZE_AVX2_2(
                        state[ 8 + i], state[12 + i],
                        state[16 + i], state[20 + i],
                        state[24 + i], state[28 + i]
                );
            }

            for (uint32_t i = 0; i < ARGON2_HWORDS_IN_BLOCK; ++i) {
                state[i] = _mm256_xor_si256(state[i], block_XY[i]);
                _mm256_storeu_si256((__m256i *) next_block->v + i, state[i]);
            }
        }
    };
}
