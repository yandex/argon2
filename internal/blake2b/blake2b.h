#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include "argonishche.h"

#define BLAKE2_PACKED(x) x __attribute__((packed))

namespace argonishche {

    const uint32_t BLAKE2B_BLOCKBYTES = 128;
    const uint32_t BLAKE2B_OUTBYTES = 64;
    const uint32_t BLAKE2B_KEYBYTES = 64;
    const uint32_t BLAKE2B_SALTBYTES = 16;
    const uint32_t BLAKE2B_PERSONALBYTES = 16;

    template <InstructionSet instructionSet>
    class Blake2B final : public Blake2Base {
    public:
        virtual ~Blake2B<instructionSet>() {
            secure_zero_memory__((void*)&state__, sizeof(state__));
            secure_zero_memory__((void*)&param__, sizeof(param__));
        }

        InstructionSet GetInstructionSet() { return instructionSet; }

    protected:
        typedef struct blake2b_state__
        {
            uint64_t    h[8];
            uint64_t    t[2];
            uint64_t    f[2];
            uint8_t     buf[BLAKE2B_BLOCKBYTES];
            size_t      buflen;
            size_t      outlen;
            uint8_t     last_node;
        } blake2b_state;

        BLAKE2_PACKED(
                struct blake2b_param__
                {
                    uint8_t  digest_length; /* 1 */
                    uint8_t  key_length;    /* 2 */
                    uint8_t  fanout;        /* 3 */
                    uint8_t  depth;         /* 4 */
                    uint32_t leaf_length;   /* 8 */
                    uint32_t node_offset;   /* 12 */
                    uint32_t xof_length;    /* 16 */
                    uint8_t  node_depth;    /* 17 */
                    uint8_t  inner_length;  /* 18 */
                    uint8_t  reserved[14];  /* 32 */
                    uint8_t  salt[BLAKE2B_SALTBYTES]; /* 48 */
                    uint8_t  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
                }
        );
        typedef struct blake2b_param__ blake2b_param;

        blake2b_state state__;
        blake2b_param param__;

    protected:
        void compress__(const uint8_t block[BLAKE2B_BLOCKBYTES]);
        void initial_xor__(uint8_t* h, const uint8_t* p);

        static void secure_zero_memory__(void* src, size_t len) {
            static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
            memset_v(src, 0, len);
        }

        void init_param__()
        {
            const uint8_t *p = (const uint8_t*)(&param__);

            memset(&state__, 0, sizeof(state__));
            initial_xor__((uint8_t *)(state__.h), p);
            state__.outlen = param__.digest_length;
        }

        void increment_counter__(const uint64_t inc) {
            state__.t[0] += inc;
            state__.t[1] += (state__.t[0] < inc) ? 1 : 0;
        }

        bool is_last_block__() {
            return state__.f[0] != 0;
        }

        void set_last_node__() {
            state__.f[1] = (uint64_t)-1;
        }

        void set_last_block__() {
            if(state__.last_node)
                set_last_node__();

            state__.f[0] = (uint64_t)-1;
        }

    public:
        Blake2B(size_t outlen) {
            /*
             * Note that outlen check was moved to proxy class
             */

            param__.digest_length = (uint8_t)outlen;
            param__.key_length = 0;
            param__.fanout = 1;
            param__.depth = 1;
            param__.leaf_length = 0;
            param__.node_offset = 0;
            param__.xof_length = 0;
            param__.node_depth = 0;
            param__.inner_length = 0;

            memset(param__.reserved, 0, sizeof(param__.reserved));
            memset(param__.salt, 0, sizeof(param__.salt));
            memset(param__.personal, 0, sizeof(param__.personal));

            init_param__();
        }

        Blake2B(size_t outlen, const void *key, size_t keylen) {
            /**
             * Note that key and outlen checks were moved to proxy classes
             */
            param__.digest_length = (uint8_t)outlen;
            param__.key_length = (uint8_t)keylen;
            param__.fanout = 1;
            param__.depth = 1;

            param__.leaf_length = 0;
            param__.node_offset = 0;
            param__.xof_length = 0;
            param__.node_depth = 0;
            param__.inner_length = 0;

            memset(param__.reserved, 0, sizeof(param__.reserved));
            memset(param__.salt, 0, sizeof(param__.salt));
            memset(param__.personal, 0, sizeof( param__.personal));

            init_param__();
            uint8_t block[BLAKE2B_BLOCKBYTES] = {0};
            memcpy(block, key, keylen);
            Update(block, BLAKE2B_BLOCKBYTES);
            secure_zero_memory__(block, BLAKE2B_BLOCKBYTES);
        }

        void Update(uint32_t in) override {
            Update((const void*)&in, sizeof(in));
        }

        void Update(const void *pin, size_t inlen) override {
            const uint8_t* in = (uint8_t*)pin;
            if( inlen > 0 )
            {
                size_t left = state__.buflen;
                size_t fill = BLAKE2B_BLOCKBYTES - left;
                if( inlen > fill )
                {
                    state__.buflen = 0;
                    memcpy(state__.buf + left, in, fill); /* Fill buffer */
                    increment_counter__(BLAKE2B_BLOCKBYTES);
                    compress__(state__.buf); /* Compress */
                    in += fill;
                    inlen -= fill;
                    while(inlen > BLAKE2B_BLOCKBYTES) {
                        increment_counter__(BLAKE2B_BLOCKBYTES);
                        compress__(in);
                        in += BLAKE2B_BLOCKBYTES;
                        inlen -= BLAKE2B_BLOCKBYTES;
                    }
                }
                memcpy(state__.buf + state__.buflen, in, inlen);
                state__.buflen += inlen;
            }
        }

        void Final(void *out, size_t outlen) override {
            if(out == nullptr || outlen < state__.outlen)
                throw std::invalid_argument("out is null or outlen is too long") ;

            if(is_last_block__())
                throw std::logic_error("Final can't be called several times");

            increment_counter__(state__.buflen);
            set_last_block__();
            memset(state__.buf + state__.buflen, 0, BLAKE2B_BLOCKBYTES - state__.buflen);
            compress__(state__.buf);
            memcpy(out, (void*)&state__.h[0], outlen);
        }
    };
}
