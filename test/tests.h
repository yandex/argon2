#pragma once

#include "argon2_test_vectors.h"
#include "blake2b_test_vectors.h"

#define DECLARE_ARGON2_TESTS(IS) \
    ARGON2D_TEST(IS) \
    ARGON_TEST(IS, Argon2Type::Argon2_i, GenKatResult2i, 1, 32, 1) \
    ARGON_TEST(IS, Argon2Type::Argon2_id, GenKatResult2id, 1, 32, 1) \
    ARGON_TEST(IS, Argon2Type::Argon2_d, GenKatResult, 1, 32, 1) \
    ARGON_TEST(IS, Argon2Type::Argon2_d, GenKatResult2d2pass, 2, 32, 1) \
    ARGON_TEST(IS, Argon2Type::Argon2_i, GenKatResult2i2pass, 2, 32, 1) \
    ARGON_TEST(IS, Argon2Type::Argon2_id, GenKatResult2id2pass, 2, 32, 1) \
    ARGON_TEST(IS, Argon2Type::Argon2_d, GenKatResult2d2pass2threads32kb, 2, 32, 2) \
    ARGON_TEST(IS, Argon2Type::Argon2_d, GenKatResult2d2pass4threads64kb, 2, 64, 4) \
    ARGON_TEST(IS, Argon2Type::Argon2_i, GenKatResult2i2pass4threads64kb, 2, 64, 4) \
    ARGON_TEST(IS, Argon2Type::Argon2_id, GenKatResult2id2pass4threads64kb, 2, 64, 4)

#define RUN_ARGON2_TEST(IS, RES) \
    CHECK_RESULT(Test_Argon2_##IS##RES::RunTest());

#define RUN_ARGON2_TESTS(IS) \
    CHECK_RESULT(Test_Argon2d_1024_##IS::RunTest()); \
    RUN_ARGON2_TEST(IS, GenKatResult) \
    RUN_ARGON2_TEST(IS, GenKatResult2i) \
    RUN_ARGON2_TEST(IS, GenKatResult2id) \
    RUN_ARGON2_TEST(IS, GenKatResult2d2pass) \
    RUN_ARGON2_TEST(IS, GenKatResult2i2pass) \
    RUN_ARGON2_TEST(IS, GenKatResult2id2pass) \
    RUN_ARGON2_TEST(IS, GenKatResult2d2pass2threads32kb) \
    RUN_ARGON2_TEST(IS, GenKatResult2d2pass4threads64kb) \
    RUN_ARGON2_TEST(IS, GenKatResult2i2pass4threads64kb) \
    RUN_ARGON2_TEST(IS, GenKatResult2id2pass4threads64kb)

#define DECLARE_BLAKE2B_TESTS(IS) \
    BLAKE2B_ABC_TEST(IS) \
    BLAKE2B_ABC128_TEST(IS) \
    BLAKE2B_RFC7693_SELFTEST(IS)

#define RUN_BLAKE2B_TESTS(IS) \
    CHECK_RESULT(TestABC_Blake2B_##IS::RunTest()); \
    CHECK_RESULT(TestABC128_Blake2B_##IS::RunTest()); \
    CHECK_RESULT(TestRFC7693_Blake2B_##IS::RunTest());
