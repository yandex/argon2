#include "cpuid.h"

#if defined(_MSC_VER)
#include <immintrin.h>
#include <intrin.h>
#endif  // defined(_MSC_VER)

namespace cpuid {

    /*
     * Taken from
     * https://software.intel.com/sites/default/files/article/405250/how-to-detect-new-instruction-support-in-the-4th-generation-intel-core-processor-family.pdf
     */
    static void run_cpuid(int eax, int ecx, int* abcd)
    {
#if defined(_MSC_VER)
        __cpuidex(abcd, eax, ecx);
#else
        int ebx = 0, edx = 0;
# if defined( __i386__ ) && defined ( __PIC__ )
        /* in case of PIC under 32-bit EBX cannot be clobbered */
         __asm__ ( "movl %%ebx, %%edi \n\t cpuid \n\t xchgl %%ebx, %%edi" : "=D" (ebx),
# else
        __asm__ ( "cpuid" : "+b" (ebx),
# endif
        "+a" (eax), "+c" (ecx), "=d" (edx) );
        abcd[0] = eax; abcd[1] = ebx; abcd[2] = ecx; abcd[3] = edx;
#endif
    }

    static int check_xcr0_ymm()
    {
        int xcr0;
#if defined(_MSC_VER)
        xcr0 = (int)_xgetbv(0); /* min VS2010 SP1 compiler is required */
#else
        __asm__ ("xgetbv" : "=a" (xcr0) : "c" (0) : "%edx" );
#endif
        return ((xcr0 & 6) == 6); /* checking if xmm and ymm state are enabled in XCR0 */
    }

    CpuId::CpuId(int eax) {
        run_cpuid(eax, 0, regs);
    }

    const int& CpuId::EAX() const {
        return regs[0];
    }

    const int& CpuId::EBX() const {
        return regs[1];
    }

    const int& CpuId::ECX() const {
        return regs[2];
    }

    const int& CpuId::EDX() const {
        return regs[3];
    }

    std::string CpuId::GetVendor() {
        CpuId cpuid(0);
        std::string vendor;
        vendor += std::string((const char*)&cpuid.EBX(), 4);
        vendor += std::string((const char*)&cpuid.EDX(), 4);
        vendor += std::string((const char*)&cpuid.ECX(), 4);

        return vendor;
    }

    bool CpuId::HasAVX2BMI12() {
        CpuId cpuidfma(1);
        if ((cpuidfma.ECX() & FlagFMAMOVBEOSXSAVE) != FlagFMAMOVBEOSXSAVE) {
            return false;
        }

        if (!check_xcr0_ymm())
            return false;

        CpuId cpuidavx2(7); /* Extended Features */
        if ((cpuidavx2.EBX() & CpuId::FlagAVX2BMI12) != CpuId::FlagAVX2BMI12) {
            return false;
        }

        CpuId cpuidLzcnt(0x80000001);
        return (cpuidLzcnt.ECX() & (1 << 5)) != 0;
    }

    bool CpuId::HasSSE41() {
        CpuId cpuid1(1); /* Feature bits */
        return ((cpuid1.ECX() & CpuId::FlagSSE41) == CpuId::FlagSSE41);
    }

    bool CpuId::HasSSE42() {
        CpuId cpuid1(1); /* Feature bits */
        return ((cpuid1.ECX() & CpuId::FlagSSE42) == CpuId::FlagSSE42);
    }

    bool CpuId::HasSSSE3() {
        CpuId cpuid1(1); /* Feature bits */
        return ((cpuid1.ECX() & CpuId::FlagSSSE3) == CpuId::FlagSSSE3);
    }

    bool CpuId::HasSSE2() {
        CpuId cpuid1(1); /* Feature bits */
        return ((cpuid1.EDX() & CpuId::FlagSSE2) == CpuId::FlagSSE2);
    }

    argonishche::InstructionSet CpuId::GetBestSet() {
        /* On Intel CPUs AVX2 comes with BMI2 */
        if(HasAVX2BMI12())
            return argonishche::InstructionSet::AVX2;

        if(HasSSE41() && HasSSE42())
            return argonishche::InstructionSet::SSE41;

        if (HasSSSE3())
            return argonishche::InstructionSet::SSSE3;

        if (HasSSE2())
            return argonishche::InstructionSet::SSE2;

        return argonishche::InstructionSet::REF;
    }
}
