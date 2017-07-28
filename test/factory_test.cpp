#include "argonishche.h"
#include <iostream>

int main(int argc, char** argv) {
    try {
        argonishche::Argon2Factory argon2Factory;
        /* Just to prevent compiler from optimizing out factory creation */
        std::cout << "Instruction set according to Argon2: "
                  << argonishche::Utils::InstructionSetToString(argon2Factory.GetInstructionSet())
                  << std::endl;

        argonishche::Blake2BFactory blake2BFactory;
        /* Just to prevent compiler from optimizing out factory creation */
        std::cout << "Instruction set according to Blake2B: "
                  << argonishche::Utils::InstructionSetToString(blake2BFactory.GetInstructionSet())
                  << std::endl;

        return 0;
    } catch (std::runtime_error& e) {
        return 1;
    }
}
