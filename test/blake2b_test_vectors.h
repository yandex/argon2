#pragma once

#include <cstdint>
#include <iomanip>
#include "argonishche.h"
#include "internal/blake2b/blake2b.h"

namespace argonishche {
    /* Result of BLAKE2B-512("abc") */
    const uint8_t ResultABC[BLAKE2B_OUTBYTES] = {
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
        0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
        0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
        0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
        0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
        0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
        0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
    };

    /* Result of BLAKE2B-128("abc") */
    const uint8_t ResultABC128[16] = {
        0xcf, 0x4a, 0xb7, 0x91, 0xc6, 0x2b, 0x8d, 0x2b,
        0x21, 0x09, 0xc9, 0x02, 0x75, 0x28, 0x78, 0x16
    };

    /* Taken from RFC7693 for selftest */
    const size_t b2b_md_len[4] = { 20, 32, 48, 64 };
    const size_t b2b_in_len[6] = { 0, 3, 128, 129, 255, 1024 };
    const uint8_t blake2b_res[32] = {
            0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
            0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
            0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
            0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
    };

#define BLAKE2B_ABC_TEST(IS) class TestABC_Blake2B_##IS { \
    public: \
        static bool RunTest() { \
            uint8_t hash_val[BLAKE2B_OUTBYTES]; \
            Blake2B<InstructionSet::IS> hash(BLAKE2B_OUTBYTES); \
            hash.Update("abc", 3); \
            hash.Final(hash_val, sizeof(hash_val)); \
            return memcmp(hash_val, ResultABC, BLAKE2B_OUTBYTES) == 0; \
        } \
    };

#define BLAKE2B_ABC128_TEST(IS) class TestABC128_Blake2B_##IS { \
    public: \
        static bool RunTest() { \
            uint8_t hash_val[sizeof(ResultABC128)]; \
            Blake2B<InstructionSet::IS> hash(sizeof(ResultABC128)); \
            hash.Update("abc", 3); \
            hash.Final(hash_val, sizeof(hash_val)); \
            return memcmp(hash_val, ResultABC128, sizeof(ResultABC128)) == 0; \
        } \
    };

    /* Taken from RFC7693 for BLAKE2B selftest */
    static void selftest_seq(uint8_t *out, size_t len, uint32_t seed)
    {
        size_t i;
        uint32_t t, a , b;

        a = 0xDEAD4BAD * seed;              // prime
        b = 1;

        for (i = 0; i < len; ++i) {         // fill the buf
            t = a + b;
            a = b;
            b = t;
            out[i] = (uint8_t)((t >> 24) & 0xFF);
        }
    }

#define BLAKE2B_RFC7693_SELFTEST(IS) class TestRFC7693_Blake2B_##IS { \
    private: \
        static void KeyedHash(uint8_t* out, size_t outlen, uint8_t* key, size_t keylen, uint8_t* in, size_t inlen) { \
            Blake2B<InstructionSet::IS> hash(outlen, key, keylen); \
            hash.Update(in, inlen); \
            hash.Final(out, outlen); \
        } \
        static void Hash(uint8_t* out, size_t outlen, uint8_t* in, size_t inlen) { \
            Blake2B<InstructionSet::IS> hash(outlen); \
            hash.Update(in, inlen); \
            hash.Final(out, outlen); \
        } \
    public: \
        static bool RunTest() { \
            uint8_t in[1024], md[64], key[64]; \
            Blake2B<InstructionSet::IS> hash(32); \
            for (int i = 0; i < 4; ++i) { \
                size_t outlen = b2b_md_len[i]; \
                for (int j = 0; j < 6; j++) { \
                    size_t inlen = b2b_in_len[j]; \
                    selftest_seq(in, inlen, inlen); \
                    Hash(md, outlen, in, inlen); \
                    hash.Update(md, outlen); \
                    selftest_seq(key, outlen, outlen); \
                    KeyedHash(md, outlen, key, outlen, in, inlen); \
                    hash.Update(md, outlen); \
                } \
            } \
            hash.Final(md, 32); \
            return memcmp(md, blake2b_res, 32) == 0; \
        } \
    };

}
