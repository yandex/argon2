#pragma once

#include <cstdint>
#include <string>

#include "argonishche.h"

namespace cpuid {
    class CpuId {
    public:
        explicit CpuId(unsigned int i);
        const uint32_t& EAX() const;
        const uint32_t& EBX() const;
        const uint32_t& ECX() const;
        const uint32_t& EDX() const;

        static constexpr uint32_t FlagAVX2BMI12 =  (1 << 5) | (1 << 3) | (1 << 8);
        static constexpr uint32_t FlagFMAMOVBEOSXSAVE = ((1 << 12) | (1 << 22) | (1 << 27));
        static constexpr uint32_t FlagSSE41 = 1 << 19;
        static constexpr uint32_t FlagSSE42 = 1 << 20;
        static constexpr uint32_t FlagSSSE3 = 1 << 9;
        static constexpr uint32_t FlagSSE2 = 1 << 26;

    public:
        static std::string GetVendor();
        static argonishche::InstructionSet GetBestSet();
        static bool HasAVX2BMI12();
        static bool HasSSE41();
        static bool HasSSE42();
        static bool HasSSSE3();
        static bool HasSSE2();

    protected:
        uint32_t regs[4];
    };
}
