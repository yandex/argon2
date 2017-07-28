#include "argonishche.h"

namespace argonishche {
    static const char* const InstructionSetStrings[5] = {
            "REF", "SSE2", "SSSE3", "SSE41", "AVX2"
    };

    static const char* const Argon2TypeStrings[3] = {
            "Argon2d", "Argon2i", "Argon2id"
    };

    std::string Utils::InstructionSetToString(InstructionSet is) {
        return InstructionSetStrings[(uint32_t)is];
    }

    std::string Utils::Argon2TypeToString(Argon2Type a) {
        return Argon2TypeStrings[(uint32_t)a];
    }
}
