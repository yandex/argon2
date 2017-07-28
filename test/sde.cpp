#include <argonishche.h>

#include <iostream>
#include <cstring>

namespace argonishche {
    const uint8_t GenKatPassword[32] = {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    };

    const uint8_t GenKatSalt[16] = {
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    };

    const uint8_t GenKatSecret[8] = {
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    };

    const uint8_t GenKatAAD[12] = {
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04,
    };


    static bool TestArgon2(Argon2Type atype) {
        const uint8_t TestResult[3][32] = {
            // Argon2d result
            {
                 0x7b, 0xa5, 0xa1, 0x7a, 0x72, 0xf7, 0xe5, 0x99,
                 0x77, 0xf7, 0xf2, 0x3d, 0x10, 0xe6, 0x21, 0x89,
                 0x8c, 0x63, 0xce, 0xbe, 0xed, 0xda, 0xbd, 0x15,
                 0xd8, 0xc6, 0x8f, 0x53, 0xea, 0xb2, 0x1a, 0x32
            },
            // Argon2i result
            {
                0x87, 0x4d, 0x23, 0xfb, 0x9f, 0x55, 0xe2, 0xff,
                0x66, 0xbc, 0x19, 0x03, 0x46, 0xe7, 0x01, 0x19,
                0x7c, 0x9f, 0x25, 0xd1, 0x1d, 0xa4, 0x5a, 0xad,
                0x0d, 0x5d, 0x24, 0x19, 0x8a, 0xac, 0xd2, 0xbb
            },
            // Argon2id result
            {
                0x99, 0xdf, 0xcf, 0xc2, 0x89, 0x76, 0x93, 0x9d,
                0xa2, 0x97, 0x09, 0x44, 0x34, 0xd8, 0x6f, 0xd0,
                0x0c, 0x94, 0x9a, 0x0f, 0x31, 0x8c, 0x22, 0xf0,
                0xcb, 0xb4, 0x69, 0xaa, 0xa8, 0x72, 0x18, 0xba
            }
        };

        Argon2Factory factory;
        InstructionSet maxInstructionSet = factory.GetInstructionSet();
        for (int i = (int)InstructionSet::REF; i <= (int)maxInstructionSet; ++i) {
            uint8_t result[32];
            auto argon2 = factory.Create(
                    (InstructionSet) i, atype,
                    1, 32, 1, GenKatSecret, sizeof(GenKatSecret));

            argon2->Hash(GenKatPassword, sizeof(GenKatPassword), GenKatSalt, sizeof(GenKatSalt),
                          result, sizeof(result), GenKatAAD, sizeof(GenKatAAD));

            if (memcmp(result, TestResult[(uint32_t)atype], sizeof(result)) != 0) {
                std::cout << Utils::Argon2TypeToString(atype) << " hash fail: "
                     << Utils::InstructionSetToString((InstructionSet)i) << std::endl;
                return false;
            }

            if (!argon2->Verify(GenKatPassword, sizeof(GenKatPassword),
                                 GenKatSalt, sizeof(GenKatSalt),
                                 TestResult[(uint32_t)atype], sizeof(TestResult[(uint32_t)atype]),
                                 GenKatAAD, sizeof(GenKatAAD))) {
                std::cout << Utils::Argon2TypeToString(atype) << " verify fail: "
                     << Utils::InstructionSetToString((InstructionSet)i) << std::endl;
                return false;
            }
        }

        return true;
    }

    static bool TestTwoPassArgon2(Argon2Type atype) {
        const uint8_t Result[3][32] = {
            {
                 0x59, 0xb0, 0x94, 0x62, 0xcf, 0xdc, 0xd2, 0xb4,
                 0x0a, 0xbd, 0x17, 0x81, 0x0a, 0x47, 0x4a, 0x8e,
                 0xc1, 0xab, 0xb7, 0xc1, 0x8d, 0x07, 0x53, 0x7c,
                 0xb9, 0x64, 0xa2, 0x59, 0x3f, 0xe9, 0xd9, 0xc5
            },
            {
                 0xc1, 0x0f, 0x00, 0x5e, 0xf8, 0x78, 0xc8, 0x07,
                 0x0e, 0x2c, 0xc5, 0x2f, 0x57, 0x75, 0x25, 0xc9,
                 0x71, 0xc7, 0x30, 0xeb, 0x00, 0x64, 0x4a, 0x4e,
                 0x26, 0xd0, 0x6e, 0xad, 0x75, 0x46, 0xe0, 0x44
            },
            {
                 0x6c, 0x00, 0xb7, 0xa9, 0x00, 0xe5, 0x00, 0x4c,
                 0x24, 0x46, 0x9e, 0xc1, 0xe7, 0xc0, 0x1a, 0x99,
                 0xb2, 0xb8, 0xf7, 0x73, 0x75, 0xd4, 0xec, 0xa7,
                 0xd8, 0x08, 0x42, 0x11, 0xd3, 0x23, 0x6b, 0x7a
            }
        };

        Argon2Factory factory;
        InstructionSet maxInstruction = factory.GetInstructionSet();
        for (uint32_t is = 0; is <= (uint32_t)maxInstruction; is++) {
            auto argon2 = factory.Create((InstructionSet)is, atype, 2, 32, 1, GenKatSecret, sizeof(GenKatSecret));
            uint8_t hashResult[32];
            argon2->Hash(GenKatPassword, sizeof(GenKatPassword), GenKatSalt, sizeof(GenKatSalt),
                         hashResult, sizeof(hashResult), GenKatAAD, sizeof(GenKatAAD));
            if (memcmp(Result[(uint32_t)atype], hashResult, sizeof(hashResult)) != 0) {
                std::cout << Utils::Argon2TypeToString(atype) << "(t=2) hash fail: "
                          << Utils::InstructionSetToString((InstructionSet)is) << std::endl;
                return false;
            }

            if (!argon2->Verify(GenKatPassword, sizeof(GenKatPassword), GenKatSalt, sizeof(GenKatSalt),
                               Result[(uint32_t)atype], sizeof(Result[(uint32_t)atype]), GenKatAAD, sizeof(GenKatAAD))) {
                std::cout << Utils::Argon2TypeToString(atype) << "(t=2) verify fail: "
                          << Utils::InstructionSetToString((InstructionSet)is) << std::endl;
                return false;
            }
        }
        return true;
    }

    static bool TestFourThreadsArgon2(Argon2Type atype) {
        uint8_t Result[3][32] = {
            {
                0x8f, 0xa2, 0x7c, 0xed, 0x28, 0x38, 0x79, 0x0f,
                0xba, 0x5c, 0x11, 0x85, 0x1c, 0xdf, 0x90, 0x88,
                0xb2, 0x18, 0x44, 0xd7, 0xf0, 0x4c, 0x97, 0xb2,
                0xca, 0xaf, 0xe4, 0xdc, 0x61, 0x4c, 0xae, 0xb2
            },
            {
                0x61, 0x1c, 0x99, 0x3c, 0xb0, 0xb7, 0x23, 0x16,
                0xbd, 0xa2, 0x6c, 0x4c, 0x2f, 0xe8, 0x2d, 0x39,
                0x9c, 0x8f, 0x1c, 0xfd, 0x45, 0xd9, 0x58, 0xa9,
                0xb4, 0x9c, 0x6c, 0x64, 0xaf, 0xf0, 0x79, 0x0b
            },
            {
                0x4f, 0x93, 0xb5, 0xad, 0x78, 0xa4, 0xa9, 0x49,
                0xfb, 0xe3, 0x55, 0x96, 0xd5, 0xa0, 0xc2, 0xab,
                0x6f, 0x52, 0x2d, 0x2d, 0x29, 0xbc, 0x98, 0x49,
                0xca, 0x92, 0xaa, 0xae, 0xba, 0x05, 0x29, 0xd8
            }
        };

        Argon2Factory factory;
        InstructionSet maxInstruction = factory.GetInstructionSet();
        for (uint32_t is = 0; is <= (uint32_t)maxInstruction; is++) {
            auto argon2 = factory.Create((InstructionSet)is, atype, 2, 64, 4, GenKatSecret, sizeof(GenKatSecret));
            uint8_t hashResult[32];
            argon2->Hash(GenKatPassword, sizeof(GenKatPassword), GenKatSalt, sizeof(GenKatSalt),
                         hashResult, sizeof(hashResult), GenKatAAD, sizeof(GenKatAAD));
            if (memcmp(hashResult, Result[(uint32_t)atype], sizeof(Result[(uint32_t)atype])) != 0) {
                std::cout << Utils::Argon2TypeToString(atype) << "(t=2,m=64,p=4) fail: "
                          << Utils::InstructionSetToString((InstructionSet)is) << std::endl;
                return false;
            }
        }
        return true;
    }

    static bool TestBlake2B() {
        const uint8_t Result[64] = {
                0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
                0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
                0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
                0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
                0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
                0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
                0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
                0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
        };
        const uint8_t data[] = {'a', 'b', 'c'};

        Blake2BFactory factory;
        InstructionSet maxInstructionSet = factory.GetInstructionSet();
        for(int i = (int)InstructionSet::REF; i <= (int)maxInstructionSet; ++i) {
            auto blake2b = factory.Create((InstructionSet)i, sizeof(Result));
            uint8_t hashResult[64] = {0};

            blake2b->Update(data, sizeof(data));
            blake2b->Final(hashResult, sizeof(hashResult));

            if(memcmp(hashResult, Result, sizeof(Result)) != 0) {
                std::cout << "Blake2B fail: " << Utils::InstructionSetToString((InstructionSet)i) << std::endl;
                return false;
            }
        }

        return true;
    }

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

    /* Taken from RFC7693 for selftest */
    const size_t b2b_md_len[4] = { 20, 32, 48, 64 };
    const size_t b2b_in_len[6] = { 0, 3, 128, 129, 255, 1024 };
    const uint8_t blake2b_res[32] = {
            0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
            0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
            0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
            0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
    };

    static void Hash(InstructionSet is, uint8_t* out, uint32_t outlen, const uint8_t* in, uint32_t inlen) {
        Blake2BFactory factory;
        auto blake2b = factory.Create(is, outlen);
        blake2b->Update(in, inlen);
        blake2b->Final(out, outlen);
    }

    static void KeyedHash(InstructionSet is, uint8_t* out, uint32_t outlen, const uint8_t* key, uint32_t keylen, const uint8_t* in, uint32_t inlen) {
        Blake2BFactory factory;
        auto blake2b = factory.Create(is, outlen, key, keylen);
        blake2b->Update(in, inlen);
        blake2b->Final(out, outlen);
    }

    static bool Blake2BSelfTest() {
        Blake2BFactory blake2BFactory;
        InstructionSet maxInstructionSet = blake2BFactory.GetInstructionSet();
        for (uint32_t is = 0; is <= (uint32_t)maxInstructionSet; is++) {
            auto blake2b = blake2BFactory.Create((InstructionSet)is, 32);
            uint8_t in[1024], md[64], key[64];

            for (int i = 0; i < 4; ++i) {
                size_t outlen = b2b_md_len[i];
                for (int j = 0; j < 6; j++) {
                    size_t inlen = b2b_in_len[j];
                    selftest_seq(in, inlen, (uint32_t)inlen);
                    Hash((InstructionSet)is, md, (uint32_t)outlen, in, (uint32_t)inlen);
                    blake2b->Update(md, outlen);
                    selftest_seq(key, outlen, (uint32_t)outlen);
                    KeyedHash((InstructionSet)is, md, (uint32_t)outlen, key, (uint32_t)outlen, in, (uint32_t)inlen);
                    blake2b->Update(md, outlen);
                }
            }
            blake2b->Final(md, 32);
            if (memcmp(md, blake2b_res, 32) != 0) {
                std::cout << "Blake2B selftest fail: "
                          << Utils::InstructionSetToString((InstructionSet)is)
                          << std::endl;
                return false;
            }
        }
        return true;
    }
}

using namespace argonishche;

int main(int argc, char** argv) {
    if (!TestArgon2(Argon2Type::Argon2_d))
        return EXIT_FAILURE;
    if (!TestArgon2(Argon2Type::Argon2_i))
        return EXIT_FAILURE;
    if (!TestArgon2(Argon2Type::Argon2_id))
        return EXIT_FAILURE;
    if (!TestBlake2B())
        return EXIT_FAILURE;
    if (!Blake2BSelfTest())
        return EXIT_FAILURE;
    if (!TestTwoPassArgon2(Argon2Type::Argon2_d))
        return EXIT_FAILURE;
    if (!TestTwoPassArgon2(Argon2Type::Argon2_i))
        return EXIT_FAILURE;
    if (!TestTwoPassArgon2(Argon2Type::Argon2_id))
        return EXIT_FAILURE;
    if (!TestFourThreadsArgon2(Argon2Type::Argon2_d))
        return EXIT_FAILURE;
    if (!TestFourThreadsArgon2(Argon2Type::Argon2_i))
        return EXIT_FAILURE;
    if (!TestFourThreadsArgon2(Argon2Type::Argon2_id))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
