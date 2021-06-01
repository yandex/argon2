#pragma once

#include <cstdint>
#include <stdexcept>
#include <new>
#include <cstdlib>
#include <memory>

#include "argonishche.h"
#include "internal/blake2b/blake2b.h"

namespace argonishche {
    const uint32_t ARGON2_PREHASH_DIGEST_LENGTH = 64;
    const uint32_t ARGON2_SECRET_MAX_LENGTH = 32;
    const uint32_t ARGON2_PREHASH_SEED_LENGTH = 72;
    const uint32_t ARGON2_BLOCK_SIZE = 1024;
    const uint32_t ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;
    const uint32_t ARGON2_OWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 16;
    const uint32_t ARGON2_HWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 32;
    const uint32_t ARGON2_ADDRESSES_IN_BLOCK = 128;
    const uint32_t ARGON2_SYNC_POINTS = 4;
    const uint32_t ARGON2_SALT_MIN_LEN = 8;
    const uint32_t ARGON2_MIN_OUTLEN = 4;

    struct block {
        uint64_t v[ARGON2_QWORDS_IN_BLOCK];
    };

    template <InstructionSet instructionSet, uint32_t mcost, uint32_t threads>
    class Argon2 : public Argon2Base {
    public:
        Argon2(Argon2Type atype, uint32_t tcost, const uint8_t *key, uint32_t keylen)
                : secretlen__(keylen), tcost__(tcost), atype__(atype) {

            if(secretlen__)
                memcpy(secret__, key, keylen);
        }

        virtual ~Argon2() override {
            if (secretlen__) {
                secure_zero_memory__(secret__, secretlen__);
                secretlen__ = 0;
            }
        }

        virtual void Hash(const uint8_t *pwd, uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                  uint8_t *out, uint32_t outlen, const uint8_t *aad = nullptr, uint32_t aadlen = 0) const override {

            std::unique_ptr<block[]> buffer(new block[memory_blocks__]);
            internal_hash__(buffer.get(), pwd, pwdlen, salt, saltlen, out, outlen, aad, aadlen);
        }

        virtual bool Verify(const uint8_t *pwd, uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                    const uint8_t *hash, uint32_t hashlen, const uint8_t *aad = nullptr, uint32_t aadlen = 0) const override {
            std::unique_ptr<uint8_t[]> hash_result(new uint8_t[hashlen]);
            Hash(pwd, pwdlen, salt, saltlen, hash_result.get(), hashlen, aad, aadlen);

            return secure_compare__(hash, hash_result.get(), hashlen);
        }

        virtual void HashWithCustomMemory(uint8_t* memory, size_t mlen, const uint8_t *pwd, uint32_t pwdlen,
                                          const uint8_t* salt, uint32_t saltlen, uint8_t* out, uint32_t outlen,
                                          const uint8_t* aad = nullptr, uint32_t aadlen = 0) const override {
            if(memory == nullptr || mlen < sizeof(block) * memory_blocks__)
                throw std::runtime_error("memory is null or its size is not enough");

            internal_hash__((block*)memory, pwd, pwdlen, salt, saltlen, out, outlen, aad, aadlen);
        }

        virtual bool VerifyWithCustomMemory(uint8_t* memory, size_t mlen, const uint8_t *pwd, uint32_t pwdlen,
                                            const uint8_t *salt, uint32_t saltlen, const uint8_t *hash, uint32_t hashlen,
                                            const uint8_t *aad = nullptr, uint32_t aadlen = 0) const override {
            std::unique_ptr<uint8_t[]> hash_result(new uint8_t[hashlen]);
            HashWithCustomMemory(memory, mlen, pwd, pwdlen, salt, saltlen, hash_result.get(), hashlen, aad, aadlen);

            return secure_compare__(hash_result.get(), hash, hashlen);
        }

        virtual size_t GetMemorySize() const override {
            return memory_blocks__ * sizeof(block);
        }

    protected: /* Constants */
        uint8_t secret__[ARGON2_SECRET_MAX_LENGTH] = {0};
        uint32_t secretlen__ = 0;
        uint32_t tcost__;
        Argon2Type atype__;

        static constexpr uint32_t lanes__ = threads;
        static constexpr uint32_t memory_blocks__ = (mcost >= 2 * ARGON2_SYNC_POINTS * lanes__) ?
                                                    (mcost - mcost % (lanes__ * ARGON2_SYNC_POINTS)) :
                                                    2 * ARGON2_SYNC_POINTS * lanes__;
        static constexpr uint32_t segment_length__ = memory_blocks__ / (lanes__ * ARGON2_SYNC_POINTS);
        static constexpr uint32_t lane_length__ = segment_length__ * ARGON2_SYNC_POINTS;

    protected: /* Prototypes */
        virtual void fill_block__(const block *prev_block, const block *ref_block,
                        block *next_block, bool with_xor) const = 0;

        virtual void copy_block__(block *dst, const block *src) const = 0;
        virtual void xor_block__(block *dst, const block *src) const = 0;

    protected: /* Static functions */
        static bool secure_compare__(const uint8_t* buffer1, const uint8_t* buffer2, uint32_t len) {
            bool result = true;
            for(uint32_t i = 0; i < len; ++i) {
                result &= (buffer1[i] == buffer2[i]);
            }
            return result;
        }

        static void secure_zero_memory__(void *src, size_t len) {
            static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
            memset_v(src, 0, len);
        }

        static void store32__(uint32_t value, void *mem) {
            *((uint32_t *) mem) = value;
        }

        static void blake2b_hash64__(uint8_t out[BLAKE2B_OUTBYTES], const uint8_t in[BLAKE2B_OUTBYTES]) {
            Blake2B<instructionSet> hash(BLAKE2B_OUTBYTES);
            hash.Update(in, BLAKE2B_OUTBYTES);
            hash.Final(out, BLAKE2B_OUTBYTES);
        }

        static void argon2_expand_blockhash__(uint8_t expanded[ARGON2_BLOCK_SIZE],
                                              const uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH]) {
            uint8_t out_buffer[BLAKE2B_OUTBYTES];
            uint8_t in_buffer[BLAKE2B_OUTBYTES];
            const uint32_t HALF_OUT_BYTES = BLAKE2B_OUTBYTES / 2;
            const uint32_t HASH_BLOCKS_COUNT = ((ARGON2_BLOCK_SIZE / HALF_OUT_BYTES));

            Blake2B<instructionSet> hash(BLAKE2B_OUTBYTES);
            hash.Update(ARGON2_BLOCK_SIZE);
            hash.Update(blockhash, ARGON2_PREHASH_SEED_LENGTH);
            hash.Final(out_buffer, BLAKE2B_OUTBYTES);

            memcpy(expanded, out_buffer, HALF_OUT_BYTES);

            for (uint32_t i = 1; i < HASH_BLOCKS_COUNT - 2; ++i) {
                memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
                blake2b_hash64__(out_buffer, in_buffer);
                memcpy(expanded + (i * HALF_OUT_BYTES), out_buffer, HALF_OUT_BYTES);
            }

            blake2b_hash64__(in_buffer, out_buffer);
            memcpy(expanded + HALF_OUT_BYTES * (HASH_BLOCKS_COUNT - 2), in_buffer, BLAKE2B_OUTBYTES);
        }

        static void blake2b_long__(uint8_t* out, uint32_t outlen, const uint8_t* in, uint32_t inlen) {
            if(outlen <= BLAKE2B_OUTBYTES) {
                Blake2B<instructionSet> hash(outlen);
                hash.Update(outlen);
                hash.Update(in, inlen);
                hash.Final(out, outlen);
            } else {
                uint8_t out_buffer[BLAKE2B_OUTBYTES];
                uint8_t in_buffer[BLAKE2B_OUTBYTES];
                uint32_t toproduce = outlen - BLAKE2B_OUTBYTES / 2;

                Blake2B<instructionSet> hash(BLAKE2B_OUTBYTES);
                hash.Update(outlen);
                hash.Update(in, inlen);
                hash.Final(out_buffer, BLAKE2B_OUTBYTES);

                memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
                out += BLAKE2B_OUTBYTES / 2;

                while(toproduce > BLAKE2B_OUTBYTES) {
                    memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
                    Blake2B<instructionSet> hash(BLAKE2B_OUTBYTES);
                    hash.Update(in_buffer, BLAKE2B_OUTBYTES);
                    hash.Final(out_buffer, BLAKE2B_OUTBYTES);
                    memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
                    out += BLAKE2B_OUTBYTES / 2;
                    toproduce -= BLAKE2B_OUTBYTES / 2;
                }

                memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
                {
                    Blake2B<instructionSet> hash(BLAKE2B_OUTBYTES);
                    hash.Update(in_buffer, toproduce);
                    hash.Final(out_buffer, BLAKE2B_OUTBYTES);
                    memcpy(out, out_buffer, toproduce);
                }
            }
        }

        static void init_block_value__(block *b, uint8_t in) {
            memset(b->v, in, sizeof(b->v));
        }

    protected: /* Functions */
        void internal_hash__(block* memory, const uint8_t *pwd, uint32_t pwdlen,
                          const uint8_t *salt, uint32_t saltlen, uint8_t *out, uint32_t outlen,
                          const uint8_t *aad, uint32_t aadlen) const {
            /*
             * all parameters checks are in proxy objects
             */

            initialize__(memory, outlen, pwd, pwdlen, salt, saltlen, aad, aadlen);
            fill_memory_blocks__(memory);
            finalize__(memory, out, outlen);
        }

        void initial_hash__(uint8_t blockhash[ARGON2_PREHASH_DIGEST_LENGTH],
                            uint32_t outlen, const uint8_t *pwd, uint32_t pwdlen,
                            const uint8_t *salt, uint32_t saltlen, const uint8_t *aad, uint32_t aadlen) const {
            Blake2B<instructionSet> hash(ARGON2_PREHASH_DIGEST_LENGTH);
            /* lanes, but lanes == threads */
            hash.Update(lanes__);
            /* outlen */
            hash.Update(outlen);
            /* m_cost */
            hash.Update(mcost);
            /* t_cost */
            hash.Update(tcost__);
            /* version */
            hash.Update(0x00000013);
            hash.Update((uint32_t)atype__);
            /* pwdlen */
            hash.Update(pwdlen);
            /* pwd */
            hash.Update(pwd, pwdlen);
            /* saltlen */
            hash.Update(saltlen);
            /* salt */
            if(saltlen)
                hash.Update(salt, saltlen);
            /* secret */
            hash.Update(secretlen__);
            if (secretlen__)
                hash.Update((void *) secret__, secretlen__);
            /* aadlen */
            hash.Update(aadlen);
            if (aadlen)
                hash.Update((void *) aad, aadlen);
            hash.Final(blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
        }

        void fill_first_blocks__(block* blocks, uint8_t *blockhash) const {
            for (uint32_t l = 0; l < lanes__; l++) {
                /* fill the first block of the lane */
                store32__(l, blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4);
                store32__(0, blockhash + ARGON2_PREHASH_DIGEST_LENGTH);
                argon2_expand_blockhash__((uint8_t*)&(blocks[l * lane_length__]), blockhash);

                /* fill the second block of the lane */
                store32__(1, blockhash + ARGON2_PREHASH_DIGEST_LENGTH);
                argon2_expand_blockhash__((uint8_t*)&(blocks[l * lane_length__ + 1]), blockhash);
            }
        }

        /* The 'if' will be optimized out as the number of threads is known at the compile time */
        void fill_memory_blocks__(block* memory) const {
            for (uint32_t t = 0; t < tcost__; ++t) {
                for (uint32_t s = 0; s < ARGON2_SYNC_POINTS; ++s) {
#ifdef _OPENMP
                    #pragma omp parallel for
#endif
                    for (uint32_t l = 0; l < lanes__; ++l) {
                        fill_segment__(memory, t, l, s);
                    }
                }
            }
        }

        void initialize__(block *memory, uint32_t outlen, const uint8_t *pwd, uint32_t pwdlen,
                          const uint8_t *salt, uint32_t saltlen, const uint8_t *aad, uint32_t aadlen) const {
            uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
            initial_hash__(blockhash, outlen, pwd, pwdlen, salt, saltlen, aad, aadlen);
            fill_first_blocks__(memory, blockhash);
        }

        uint32_t compute_reference_area__(uint32_t pass, uint32_t slice, uint32_t index, bool same_lane) const {
            uint32_t pass_val = pass == 0 ? (slice * segment_length__) : (lane_length__ - segment_length__);
            return same_lane ? pass_val + (index - 1) : pass_val + (index == 0 ? -1 : 0);
        }

        uint32_t index_alpha__(uint32_t pass, uint32_t slice, uint32_t index, uint32_t pseudo_rand, bool same_lane) const {
            uint32_t reference_area_size = compute_reference_area__(pass, slice, index, same_lane);

            uint64_t relative_position = pseudo_rand;
            relative_position = relative_position * relative_position >> 32;
            relative_position = reference_area_size - 1 - (reference_area_size * relative_position >> 32);

            uint32_t start_position = 0;
            if (pass != 0)
                start_position = (slice == ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segment_length__;

            return (uint32_t)((start_position + relative_position) % lane_length__);
        }

        void next_addresses(block *address_block, block *input_block, const block *zero_block) const {
            input_block->v[6]++;
            fill_block__(zero_block, input_block, address_block, false);
            fill_block__(zero_block, address_block, address_block, false);
        }

        void finalize__(const block* memory, uint8_t* out, uint32_t outlen) const {
            block blockhash;
            copy_block__(&blockhash, memory + lane_length__ - 1);

            /* XOR the last blocks */
            for (uint32_t l = 1; l < lanes__; ++l) {
                uint32_t last_block_in_lane = l * lane_length__ + (lane_length__ - 1);
                xor_block__(&blockhash, memory + last_block_in_lane);
            }

            blake2b_long__(out, outlen, (uint8_t*)blockhash.v, ARGON2_BLOCK_SIZE);
        }

        /* The switch will be optimized out by the compiler as the type is known at the compile time */
        void fill_segment__(block *memory, uint32_t pass, uint32_t lane, uint32_t slice) const {
            switch (atype__) {
                case Argon2Type::Argon2_d:
                    fill_segment_d__(memory, pass, lane, slice);
                    return;
                case Argon2Type::Argon2_i:
                    fill_segment_i__(memory, pass, lane, slice, Argon2Type::Argon2_i);
                    return;
                case Argon2Type::Argon2_id:
                    if(pass == 0 && slice < ARGON2_SYNC_POINTS / 2)
                        fill_segment_i__(memory, pass, lane, slice, Argon2Type::Argon2_id);
                    else
                        fill_segment_d__(memory, pass, lane, slice);
                    return;
            }
        }

        void fill_segment_d__(block *memory, uint32_t pass, uint32_t lane, uint32_t slice) const {
            uint32_t starting_index = (pass == 0 && slice == 0) ? 2 : 0;
            uint32_t curr_offset = lane * lane_length__ + slice * segment_length__ + starting_index;
            uint32_t prev_offset = curr_offset + ((curr_offset % lane_length__ == 0) ? lane_length__ : 0) - 1;

            for (uint32_t i = starting_index; i < segment_length__; ++i, ++curr_offset, ++prev_offset) {
                if (curr_offset % lane_length__ == 1) {
                    prev_offset = curr_offset - 1;
                }

                uint64_t pseudo_rand = memory[prev_offset].v[0];
                uint64_t ref_lane = (pass == 0 && slice == 0) ? lane : (((pseudo_rand >> 32)) % lanes__);
                uint64_t ref_index = index_alpha__(pass, slice, i, (uint32_t)(pseudo_rand & 0xFFFFFFFF), ref_lane == lane);

                block* ref_block = memory + lane_length__ * ref_lane + ref_index;
                fill_block__(memory + prev_offset, ref_block, memory + curr_offset, pass != 0);
            }
        }

        void fill_segment_i__(block *memory, uint32_t pass, uint32_t lane, uint32_t slice, Argon2Type atp) const {
            block address_block, input_block, zero_block;
            init_block_value__(&zero_block, 0);
            init_block_value__(&input_block, 0);

            input_block.v[0] = pass;
            input_block.v[1] = lane;
            input_block.v[2] = slice;
            input_block.v[3] = memory_blocks__;
            input_block.v[4] = tcost__;
            input_block.v[5] = (uint64_t)atp;

            uint32_t starting_index = 0;

            if (pass == 0 && slice == 0) {
                starting_index = 2;
                next_addresses(&address_block, &input_block, &zero_block);
            }

            uint32_t curr_offset = lane * lane_length__ + slice * segment_length__ + starting_index;
            uint32_t prev_offset = curr_offset + ((curr_offset % lane_length__ == 0) ? lane_length__ : 0) - 1;

            for (uint32_t i = starting_index; i < segment_length__; ++i, ++curr_offset, ++prev_offset) {
                if (curr_offset % lane_length__ == 1) {
                    prev_offset = curr_offset - 1;
                }

                if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
                    next_addresses(&address_block, &input_block, &zero_block);
                }

                uint64_t pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
                uint64_t ref_lane = (pass == 0 && slice == 0)? lane : (((pseudo_rand >> 32)) % lanes__);
                uint64_t ref_index = index_alpha__(pass, slice, i, (uint32_t)(pseudo_rand & 0xFFFFFFFF), ref_lane == lane);

                block* ref_block = memory + lane_length__ * ref_lane + ref_index;
                fill_block__(memory + prev_offset, ref_block, memory + curr_offset, pass != 0);
            }
        }
    };
}
