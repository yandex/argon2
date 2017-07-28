#include <cstring>

#include "argonishche.h"
#include "cpuid/cpuid.h"

#include "internal/proxies/ref/proxy_ref.h"
#include "internal/proxies/sse2/proxy_sse2.h"
#include "internal/proxies/ssse3/proxy_ssse3.h"
#include "internal/proxies/sse41/proxy_sse41.h"
#include "internal/proxies/avx2/proxy_avx2.h"

namespace argonishche {
    Argon2Factory::Argon2Factory(bool skipTest) {
        instructionSet__ = cpuid::CpuId::GetBestSet();
        if(!skipTest)
            quick_test__();
    }

    std::unique_ptr<Argon2Base> Argon2Factory::Create(InstructionSet instructionSet, Argon2Type atype, uint32_t tcost,
                                      uint32_t mcost, uint32_t threads, const uint8_t *key, uint32_t keylen) const {
        switch (instructionSet) {
            case InstructionSet::REF:
                return std::make_unique<Argon2ProxyREF>(atype, tcost, mcost, threads, key, keylen);
            case InstructionSet::SSE2:
                return std::make_unique<Argon2ProxySSE2>(atype, tcost, mcost, threads, key, keylen);
            case InstructionSet::SSSE3:
                return std::make_unique<Argon2ProxySSSE3>(atype, tcost, mcost, threads, key, keylen);
            case InstructionSet::SSE41:
                return std::make_unique<Argon2ProxySSSE3>(atype, tcost, mcost, threads, key, keylen);
            case InstructionSet::AVX2:
                return std::make_unique<Argon2ProxyAVX2>(atype, tcost, mcost, threads, key, keylen);
        }

        /* to avoid gcc warning  */
        throw std::runtime_error("Invalid instruction set value");
    }

    std::unique_ptr<Argon2Base> Argon2Factory::Create(Argon2Type atype, uint32_t tcost, uint32_t mcost, uint32_t threads,
                                      const uint8_t *key, uint32_t keylen) const {
        return Create(instructionSet__, atype, tcost, mcost, threads, key, keylen);
    }

    InstructionSet Argon2Factory::GetInstructionSet() const {
        return instructionSet__;
    }

    /* TODO: Argon2i and Argon2id test */
    void Argon2Factory::quick_test__() const {
        const uint8_t password[8] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        const uint8_t salt[8] = {'s', 'o', 'm', 'e', 's', 'a', 'l', 't'};
        const uint8_t test_result[][32] = {
                {
                        0x2e, 0x2e, 0x5e, 0x05, 0xfe, 0x57, 0xac, 0x2c,
                        0xf4, 0x72, 0xec, 0xd0, 0x45, 0xef, 0x68, 0x7e,
                        0x56, 0x2a, 0x98, 0x0f, 0xd5, 0x03, 0x39, 0xb3,
                        0x89, 0xc8, 0x70, 0xe1, 0x96, 0x2b, 0xbc, 0x45
                },
                {
                        0x95, 0x46, 0x6c, 0xc4, 0xf9, 0x2f, 0x87, 0x49,
                        0x54, 0x61, 0x7e, 0xec, 0x0a, 0xa1, 0x19, 0x5d,
                        0x22, 0x98, 0x0a, 0xbd, 0x62, 0x5e, 0x5c, 0xac,
                        0x44, 0x76, 0x3a, 0xe3, 0xa9, 0xcb, 0x6a, 0xb7
                },
                {
                        0xc8, 0xe9, 0xae, 0xdc, 0x95, 0x6f, 0x6a, 0x7d,
                        0xff, 0x0a, 0x4d, 0x42, 0x94, 0x0d, 0xf6, 0x28,
                        0x62, 0x3f, 0x32, 0x8e, 0xa1, 0x23, 0x50, 0x05,
                        0xab, 0xac, 0x93, 0x3c, 0x57, 0x09, 0x3e, 0x23
                }
        };

        uint8_t hash_result[32] = {0};
        for(uint32_t atype = (uint32_t)Argon2Type::Argon2_d; atype <= (uint32_t)Argon2Type::Argon2_id; ++atype) {
            auto argon2d = std::make_unique<Argon2ProxyREF>((Argon2Type)atype, 1, 1024, 1);
            argon2d->Hash(password, sizeof(password), salt, sizeof(salt), hash_result, sizeof(hash_result));
            if(memcmp(test_result[atype], hash_result, sizeof(hash_result)) != 0)
                throw std::runtime_error("Argon2 runtime test fail");
        }

        if(instructionSet__ >= InstructionSet::SSE2) {
            for (uint32_t atype = (uint32_t) Argon2Type::Argon2_d; atype <= (uint32_t) Argon2Type::Argon2_id; ++atype) {
                auto argon2d = std::make_unique<Argon2ProxySSE2>((Argon2Type)atype, 1, 1024, 1);
                argon2d->Hash(password, sizeof(password), salt, sizeof(salt), hash_result, sizeof(hash_result));
                if (memcmp(test_result[atype], hash_result, sizeof(hash_result)) != 0)
                    throw std::runtime_error("Argon2 runtime test fail");
            }
        }

        if(instructionSet__ >= InstructionSet::SSSE3){
            for (uint32_t atype = (uint32_t) Argon2Type::Argon2_d; atype <= (uint32_t) Argon2Type::Argon2_id; ++atype) {
                auto argon2d = std::make_unique<Argon2ProxySSSE3>((Argon2Type)atype, 1, 1024, 1);
                argon2d->Hash(password, sizeof(password), salt, sizeof(salt), hash_result, sizeof(hash_result));
                if (memcmp(test_result[atype], hash_result, sizeof(hash_result)) != 0)
                    throw std::runtime_error("Argon2 runtime test fail");
            }
        }

        if(instructionSet__ >= InstructionSet::SSE41){
            for (uint32_t atype = (uint32_t) Argon2Type::Argon2_d; atype <= (uint32_t) Argon2Type::Argon2_id; ++atype) {
                auto argon2d = std::make_unique<Argon2ProxySSE41>((Argon2Type)atype, 1, 1024, 1);
                argon2d->Hash(password, sizeof(password), salt, sizeof(salt), hash_result, sizeof(hash_result));
                if (memcmp(test_result[atype], hash_result, sizeof(hash_result)) != 0)
                    throw std::runtime_error("Argon2 runtime test fail");
            }
        }

        if(instructionSet__ >= InstructionSet::AVX2){
            for (uint32_t atype = (uint32_t) Argon2Type::Argon2_d; atype <= (uint32_t) Argon2Type::Argon2_id; ++atype) {
                auto argon2d = std::make_unique<Argon2ProxyAVX2>((Argon2Type)atype, 1, 1024, 1);
                argon2d->Hash(password, sizeof(password), salt, sizeof(salt), hash_result, sizeof(hash_result));
                if (memcmp(test_result[atype], hash_result, sizeof(hash_result)) != 0)
                    throw std::runtime_error("Argon2 runtime test fail");
            }
        }
    }

    Blake2BFactory::Blake2BFactory(bool skipTest) {
        instructionSet__ = cpuid::CpuId::GetBestSet();
        if(!skipTest)
            quick_test__();
    }

    std::unique_ptr<Blake2Base> Blake2BFactory::Create(InstructionSet instructionSet, size_t outlen, const uint8_t *key,
                                                       size_t keylen) const {
        switch(instructionSet) {
            case InstructionSet::REF:
                return std::make_unique<Blake2BProxyREF>(outlen, key, keylen);
            case InstructionSet::SSE2:
                return std::make_unique<Blake2BProxySSE2>(outlen, key, keylen);
            case InstructionSet::SSSE3:
                return std::make_unique<Blake2BProxySSSE3>(outlen, key, keylen);
            case InstructionSet::SSE41:
                return std::make_unique<Blake2BProxySSE41>(outlen, key, keylen);
            case InstructionSet::AVX2:
                return std::make_unique<Blake2BProxyAVX2>(outlen, key, keylen);
        }

        /* to supress gcc warning */
        throw std::runtime_error("Invalid instruction set");
    }

    std::unique_ptr<Blake2Base> Blake2BFactory::Create(size_t outlen, const uint8_t *key, size_t keylen) const {
        return Create(instructionSet__, outlen, key, keylen);
    }

    InstructionSet Blake2BFactory::GetInstructionSet() const {
        return instructionSet__;
    }

    void Blake2BFactory::quick_test__() const {
        const char* test_str = "abc";
        const uint8_t test_result[] = {
            0xcf, 0x4a, 0xb7, 0x91, 0xc6, 0x2b, 0x8d, 0x2b,
            0x21, 0x09, 0xc9, 0x02, 0x75, 0x28, 0x78, 0x16
        };

        uint8_t hash_val[16];
        if(instructionSet__ >= InstructionSet::REF) {
            auto blake2 = std::make_unique<Blake2BProxyREF>(16);
            blake2->Update(test_str, 3);
            blake2->Final(hash_val, 16);
            if(memcmp(test_result, hash_val, 16) != 0)
                throw std::runtime_error("Blake2B runtime test fail");
        }

        if(instructionSet__ >= InstructionSet::SSE2) {
            auto blake2 = std::make_unique<Blake2BProxySSE2>(16);
            blake2->Update(test_str, 3);
            blake2->Final(hash_val, 16);
            if(memcmp(test_result, hash_val, 16) != 0)
                throw std::runtime_error("Blake2B runtime test fail");
        }

        if(instructionSet__ >= InstructionSet::SSSE3) {
            auto blake2 = std::make_unique<Blake2BProxySSSE3>(16);
            blake2->Update(test_str, 3);
            blake2->Final(hash_val, 16);
            if(memcmp(test_result, hash_val, 16) != 0)
                throw std::runtime_error("Blake2B runtime test fail");
        }

        if(instructionSet__ >= InstructionSet::SSE41) {
            auto blake2 = std::make_unique<Blake2BProxySSE41>(16);
            blake2->Update(test_str, 3);
            blake2->Final(hash_val, 16);
            if(memcmp(test_result, hash_val, 16) != 0)
                throw std::runtime_error("Blake2B runtime test fail");
        }

        if(instructionSet__ >= InstructionSet::AVX2) {
            auto blake2 = std::make_unique<Blake2BProxyAVX2>(16);
            blake2->Update(test_str, 3);
            blake2->Final(hash_val, 16);
            if(memcmp(test_result, hash_val, 16) != 0)
                throw std::runtime_error("Blake2B runtime test fail");
        }
    }
}
