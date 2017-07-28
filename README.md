Argonishche
===========

[![Build Status](https://travis-ci.org/yandex/argon2.svg?branch=master)](https://travis-ci.org/yandex/argon2)

# Overview

The library comprises an implementation of Argon2 (i, d, id) and Blake2B algorithms that features the following:
* C++14 interface
* constexpr and partial templates to get rid of useless branches
* SSE2, SSSE3, SSE4.1, AVX2 optimized implementations of Argon2 and Blake2B
* Runtime CPU dispatching (a partiular implementation is chosen runtime depending on SIMD extentions available in the CPU)
* OpenMP for multithreading in contrast to pthread in the [Argon2 reference implementation](github.com/P-H-C/phc-winner-argon2) 
* In contrast to the [Argon2 reference implementation](github.com/P-H-C/phc-winner-argon2) the library uses SIMD-optimized Blake2B

# How to use

```
#include <argonishche.h>

uint32_t tcost = 1;     /* one pass */
uint32_t mcost = 32;    /* in KB */
uint32_t threads = 1;   /* one thread version */
bool runTest = false; /* by default factory runs a quick runtime test; pass 'false' to disable it */

argonishche::Argon2Factory afactory(runTest);
std::unique_ptr<argonishche::Argon2Base> argon2 = afactory.Create(argonishche::Argon2Type::Argon2_d, tcost, mcost, threads, key, keylen);
argon2->Hash(input, insize, salt, saltsize, out, outlen);
bool result = argon2->Verify(pwd, pwdlen, salt, saltlen, hash, hashlen, aad, addlen);

argonishche::Blake2BFactory bfactory(runTest);
uint32_t outlen = 32;
std::unique_ptr<argonishche::Blake2Base> blake2b = bfactory.Create(outlen, key, keylen);
blake2b->Update(in, inlen);
blake2b->Final(out, outlen);
```

There are also `HashWithCustomMemory` and `VerifyWithCustomMemory` methods to which you can pass a memory area to use it for computations and to save a little on memory allocation. `GetMemorySize` method returns the size of memory area that required for a particular instance.

# Benchmark results

On my OS X 10.11, MacBook Pro (Early 2015, Core i5 2,7 GHz, 16 GB 1867 MHz DDR3) for `(Argon2_d, 1, 2048, 1)` it gives:

| Implementation               | Speed per one core (H/s) |
|------------------------------|--------------------------|
| REF (x64 w/o optimizations)  | 458.51                   |
| SSE2                         | 665.17                   |
| SSSE3                        | 743.86                   |
| SSE4.1                       | 723.41                   |
| AVX2                         | 1120.14                  |

On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz for `(Argon2_d, 1, 2048, 1)` it gives:

| Implementation               | Speed per one core (H/s) |
|------------------------------|--------------------------|
| REF (x64 w/o optimizations)  | 423.9                    |
| SSE2                         | 663.42                   |
| SSSE3                        | 715.33                   |
| SSE4.1                       | 720.12                   |
| AVX2                         | 1130.36                  |                    

# How to add your own Argon2 configuration

The library uses constexpr to calculate some values at compile time. mcost value is a template variable, so the library doesn't support arbitrary mcost values except for predefined ones (in practise you usually don't need it).

To add a new mcost value just modify the file `internal/proxy/proxy_macros.h` and add appropriate `ARGON2_INSTANCE_DECL` declaration.

# cmake options

You can use the following cmake options:

| Option              |Default value | Description                                  |
|---------------------|--------------|----------------------------------------------|
| BUILD_WITH_OPENMP   | ON           | Use OpenMP if it's available                 |
| BUILD_TESTS         | ON           | Build library tests                          |
| BUILD_BENCHMARK     | ON           | Build openssl speed like benchmarking tool   |

# Testing with Intel SDE

One of the tests is intended to run under Intel SDE emulator. Make sure you have SDE in your PATH  and run `test_sde.sh <build_folder>/test/test_sde`.

# Other documentation

`argonishche.h` contains some Doxygen comments so Doxygen can be used to generate documentation.

# About the name

Just "Argon" and Russian suffix "-ищ" (-ishch). In Russian suffix "-ищ" (-ishch) means something that is bigger than ordinary and that scares small children. In this case - something that is bigger than Argon :)

# Acknowledgements

This project uses some ideas and pieces of code from the following projects licensed under CC0:
* https://github.com/P-H-C/phc-winner-argon2
* https://github.com/BLAKE2/BLAKE2

And it wouldn't be possible to make the library without work of the following people:
* Alex Biryukov, Daniel Dinu, Dmitry Khovratovich who designed Argon2 algorithm
* Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, Christian Winnerlein who designed Blake2 algorithm

I'm also thankful to Igor Klevanets for his fruitful feedback and code reviews.

