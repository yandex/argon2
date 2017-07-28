#pragma once

#include <smmintrin.h>
#include "argon2_base.h"
#include "internal/blamka/blamka_ssse3.h"

namespace argonishche {

    template<uint32_t mcost, uint32_t threads>
    class Argon2SSE41 final : public Argon2<InstructionSet::SSE41, mcost, threads> {
    public:
        Argon2SSE41(Argon2Type atype, uint32_t tcost, const uint8_t* key, uint32_t keylen)
                : Argon2<InstructionSet::SSE41, mcost, threads>(atype, tcost, key, keylen) { }

    protected:
        virtual void xor_block__(block *dst, const block *src) const override {
            __m128i* mdst = (__m128i*)dst;
            __m128i* msrc = (__m128i*)src;

            for(uint32_t i = 0; i < ARGON2_OWORDS_IN_BLOCK; ++i)
                xor_values(mdst + i, msrc + i, mdst + i);
        }

        virtual void copy_block__(block *dst, const block *src) const override {
            memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }

        virtual void fill_block__(const block *prev_block, const block *ref_block, block *next_block, bool with_xor) const override
        {
            __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
            __m128i state[ARGON2_OWORDS_IN_BLOCK];

            memcpy(state, prev_block, ARGON2_BLOCK_SIZE);

            if (with_xor) {
                for (uint32_t i = 0; i < ARGON2_OWORDS_IN_BLOCK; ++i) {
                    state[i] = _mm_xor_si128(
                            state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
                    block_XY[i] = _mm_xor_si128(
                            state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
                }
            } else {
                for (uint32_t i = 0; i < ARGON2_OWORDS_IN_BLOCK; ++i) {
                    block_XY[i] = state[i] = _mm_xor_si128(
                            state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
                }
            }

            for (uint32_t i = 0; i < 8; ++i) {
                BLAMKA_G1_SSSE3(
                        state[8 * i + 0], state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 4], state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]
                );
                BLAMKA_G2_SSSE3(
                        state[8 * i + 0], state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 4], state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]
                );
                DIAGONALIZE_SSSE3(
                        state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 4], state[8 * i + 5],
                        state[8 * i + 6], state[8 * i + 7]
                );
                BLAMKA_G1_SSSE3(
                        state[8 * i + 0], state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 4], state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]
                );
                BLAMKA_G2_SSSE3(
                        state[8 * i + 0], state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 4], state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]
                );
                UNDIAGONALIZE_SSSE3(
                        state[8 * i + 2], state[8 * i + 3],
                        state[8 * i + 4], state[8 * i + 5],
                        state[8 * i + 6], state[8 * i + 7]
                );
            }

            for (uint32_t i = 0; i < 8; ++i) {
                BLAMKA_G1_SSSE3(
                        state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i], state[8 * 3 + i],
                        state[8 * 4 + i], state[8 * 5 + i], state[8 * 6 + i], state[8 * 7 + i]
                );
                BLAMKA_G2_SSSE3(
                        state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i], state[8 * 3 + i],
                        state[8 * 4 + i], state[8 * 5 + i], state[8 * 6 + i], state[8 * 7 + i]
                );
                DIAGONALIZE_SSSE3(
                        state[8 * 2 + i], state[8 * 3 + i],
                        state[8 * 4 + i], state[8 * 5 + i],
                        state[8 * 6 + i], state[8 * 7 + i]
                );
                BLAMKA_G1_SSSE3(
                        state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i], state[8 * 3 + i],
                        state[8 * 4 + i], state[8 * 5 + i], state[8 * 6 + i], state[8 * 7 + i]
                );
                BLAMKA_G2_SSSE3(
                        state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i], state[8 * 3 + i],
                        state[8 * 4 + i], state[8 * 5 + i], state[8 * 6 + i], state[8 * 7 + i]
                );
                UNDIAGONALIZE_SSSE3(
                        state[8 * 2 + i], state[8 * 3 + i],
                        state[8 * 4 + i], state[8 * 5 + i],
                        state[8 * 6 + i], state[8 * 7 + i]
                );
            }

            for (uint32_t i = 0; i < ARGON2_OWORDS_IN_BLOCK; ++i) {
                state[i] = _mm_xor_si128(state[i], block_XY[i]);
                _mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
            }
        }

    };
}
