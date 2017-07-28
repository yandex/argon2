#pragma once

#include <cstdint>
#include <string>
#include <memory>

namespace argonishche {
    /**
     * Type of Argon2 algorithm
     */
    enum class Argon2Type : uint32_t {
        Argon2_d = 0,   /// Data dependent version of Argon2
        Argon2_i = 1,   /// Data independent version of Argon2
        Argon2_id = 2   /// Mixed version of Argon2
    };

    /**
     * Instruction sets for which Argon2 is optimized
     */
    enum class InstructionSet : uint32_t {
        REF = 0,        /// Reference implementation
        SSE2 = 1,       /// SSE2 optimized version
        SSSE3 = 2,      /// SSSE3 optimized version
        SSE41 = 3,      /// SSE4.1 optimized version
        AVX2 = 4        /// AVX2 optimized version
    };

    class Utils {
    public:
        /**
         * Converts InstructionSet to a string value
         * @param is InstructionSet
         * @return sting representation of the InstructionSet value
         */
        static std::string InstructionSetToString(InstructionSet is);

        /**
         * Converts Argon2Type to a string value
         * @param a Argon2Type
         * @return string representation of Argon2Type
         */
        static std::string Argon2TypeToString(Argon2Type a);
    };

    /**
     * Interface of all Argon2 instances
     */
    class Argon2Base {
    public:
        virtual ~Argon2Base() { }
        /**
         * Applies Argon2 algorithm
         * @param pwd password
         * @param pwdlen password length
         * @param salt salt
         * @param saltlen salt length
         * @param out output
         * @param outlen output length
         * @param aad additional authenticated data (optional)
         * @param aadlen additional authenticated data length (optional)
         */
        virtual void Hash(const uint8_t *pwd, uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                          uint8_t *out, uint32_t outlen, const uint8_t *aad = nullptr, uint32_t aadlen = 0) const = 0;

        /**
         * Applies Argon2 algorithm to a password and compares the result with the hash data
         * @param pwd password
         * @param pwdlen password length
         * @param salt salt
         * @param saltlen salt length
         * @param hash hash value to compare with the result
         * @param hashlen hash value length
         * @param aad additional authenticated data (optional)
         * @param adadlen additional authenticated data length (optional)
         * @return true if the Argon2 result equals to the value in hash
         */
        virtual bool Verify(const uint8_t *pwd, uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                            const uint8_t *hash, uint32_t hashlen, const uint8_t *aad = nullptr, uint32_t adadlen = 0) const = 0;

        /**
         * Applies Argon2 algorithms but allows to pass memory buffer for work.
         * This allows to use external memory allocator or reuse already allocated memory buffer.
         * @param memory memory buffer for Argon2 calculations
         * @param mlen memory buffer len (must be at least the value returned by the GetMemorySize method)
         * @param pwd password to hash
         * @param pwdlen password length
         * @param salt salt
         * @param saltlen salt length
         * @param out output buffer
         * @param outlen output length
         * @param aad additional authenticated data (optional)
         * @param aadlen additional authenticated data length (optional)
         * @throws std::runtime_error if the memory is not enough to carry out the algorithm
         */
        virtual void HashWithCustomMemory(uint8_t* memory, size_t mlen, const uint8_t *pwd, uint32_t pwdlen,
                                          const uint8_t* salt, uint32_t saltlen, uint8_t* out, uint32_t outlen,
                                          const uint8_t* aad = nullptr, uint32_t aadlen = 0) const = 0;
        /**
         * Applies Argon2 algorithm to a password and compares the result with the hash data.
         * This method allows to use a custom memory allocator or reuse already allocated memory buffer.
         * @param memory memory buffer for Argon2 calculations
         * @param mlen memory buffer length
         * @param pwd password to hash
         * @param pwdlen password length
         * @param salt salt
         * @param saltlen salt length
         * @param hash hash value to compare with the result
         * @param hashlen hash value length
         * @param aad additional authenticated data (optional)
         * @param aadlen additional authenticated data length (optional)
         * @throws std::runtime_error if the memory is not enough to carry out the algorithm
         * @return true if the Argon2 result equals to the value in hash
         */
        virtual bool VerifyWithCustomMemory(uint8_t* memory, size_t mlen, const uint8_t *pwd, uint32_t pwdlen,
                                            const uint8_t *salt, uint32_t saltlen, const uint8_t *hash, uint32_t hashlen,
                                            const uint8_t *aad = nullptr, uint32_t aadlen = 0) const = 0;

        /**
         * The function calculates the size of memory required by Argon2 algorithm
         * @return memory buffer size
         */
        virtual size_t GetMemorySize() const = 0;
    };

    /**
     * A factory to create Argon2 instances depending on instruction set, tcost, mcost, the number of threads etc.
     */
    class Argon2Factory {
    public:
        /**
         * Constructs a factory object
         * @param skipTest if true then a simple runtime test will be skipped in the constructor (optional)
         * @throws std::runtime_error if the test fails
         */
        Argon2Factory(bool skipTest = false);

        /**
         * Creates an instance of Argon2 algorithm.
         * The particular optimization is chosen automatically based on the cpuid instruction output.
         * @param atype the type of Argon2 algorithm
         * @param tcost the number of passes over memory block, must be at least 1
         * @param mcost the size in kilobytes of memory block used by Argon2
         * @param threads the number of threads for parallel version of Argon2 (must be 1,2 or 4)
         * @param key a secret key to use for password hashing (optional)
         * @param keylen the length of the key (optional)
         * @throws std::runtime_eerror in case of error
         * @return unique_ptr to Argon2 instance
         */
        std::unique_ptr<Argon2Base> Create(Argon2Type atype = Argon2Type::Argon2_d, uint32_t tcost = 1, uint32_t mcost = 1024,
                                           uint32_t threads = 1, const uint8_t* key = nullptr, uint32_t keylen = 0) const;

        /**
         * Creates an instance of Argon2 algorithm optimized for the provided instruction set
         * @param instructionSet instruction set
         * @param atype the type of Argon2 algorithm
         * @param tcost the number of passes over memory block, must be at least 1
         * @param mcost the size in kilobytes of memory block used by Argon2
         * @param threads the number of threads for parallel version of Argon2 (must be 1,2 or 4)
         * @param key a secret key to use for password hashing (optional)
         * @param keylen the length of the key (optional)
         * @throws std::runtime_error in case of errors
         * @return unique_ptr to Argon2 instance
         */
        std::unique_ptr<Argon2Base> Create(InstructionSet instructionSet, Argon2Type atype = Argon2Type::Argon2_d, uint32_t tcost = 1,
                                           uint32_t mcost = 1024, uint32_t threads = 1, const uint8_t* key = nullptr,
                                           uint32_t keylen = 0) const;

        /**
         * The function returns the best instruction set available on the current CPU
         * @return InstructionSet value
         */
        InstructionSet GetInstructionSet() const;

    protected:
        InstructionSet instructionSet__ = InstructionSet::REF;
        void quick_test__() const;
    };

    /**
     * Interface for all Blake2B instances
     */
    class Blake2Base {
    public:
        virtual ~Blake2Base() { }
        /**
         * Updates intermediate hash with an uint32_t value
         * @param in integer to hash
         */
        virtual void Update(uint32_t in) = 0;

        /**
         * Updates intermediate hash with an array of bytes
         * @param pin input
         * @param inlen input length
         */
        virtual void Update(const void *pin, size_t inlen) = 0;

        /**
         * Finalizes the hash calculation and returns the hash value
         * @param out output buffer
         * @param outlen output buffer length
         */
        virtual void Final(void *out, size_t outlen) = 0;
    };

    /**
     * A factory that creates Blake2B instances optimized for different instruction sets
     */
    class Blake2BFactory {
    public:
        /**
         * Constructs the factory object
         * @param skipTest if true then the constructor skips runtime Blake2B test
         * @throws std::runtime_error if the test fails
         */
        Blake2BFactory(bool skipTest = false);

        /**
         * Creates an instance of Blake2B hash algorithm.
         * The optimisation is selected automatically based on the cpuid instruction output.
         * @param outlen the output buffer length, this value takes part in hashing
         * @param key a secret key to make Blake2B work as a keyed hash function
         * @param keylen the secret key length
         * @throws std::runtime_error if parameters are wrong
         * @return returns an unique_ptr containing Blake2B instance
         */
        std::unique_ptr<Blake2Base> Create(size_t outlen = 32, const uint8_t* key = nullptr, size_t keylen = 0) const;

        /**
         * Creates an instance of Blake2B hash algorithm optimized for the particular instruction set
         * @param instructionSet instruction set
         * @param outlen the output buffer length, this value takes part in hashing
         * @param key a secret key to make Blake2B work as a keyed hash function
         * @param keylen the secret key length
         * @throws std::runtime_error if parameters are wrong
         * @return returns an unique_ptr containing Blake2B instance
         */
        std::unique_ptr<Blake2Base> Create(InstructionSet instructionSet, size_t outlen = 32,
                                           const uint8_t* key = nullptr, size_t keylen = 0) const;

        /**
         * The function returns the best instruction set available on the current CPU
         * @return InstructionSet value
         */
        InstructionSet GetInstructionSet() const;

    protected:
        InstructionSet instructionSet__ = InstructionSet::REF;
        void quick_test__() const;
    };
}

