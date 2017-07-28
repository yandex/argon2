#include <iostream>
#include "cpuid/cpuid.h"

using namespace std;

static void cout_tabbed(const string& key, const string& val) {
    cout << "\t" << "\"" << key << "\": " << "\"" << val << "\"," << endl;
}

int main(int argc, char** argv) {
    cout << "{" << endl;
    cout_tabbed("Vendor", cpuid::CpuId::GetVendor());

    cout_tabbed("AVX2BMI12", cpuid::CpuId::HasAVX2BMI12() ? "True" : "False");
    cout_tabbed("SSE4.1", cpuid::CpuId::HasSSE41() ? "True" : "False");
    cout_tabbed("SSE4.2", cpuid::CpuId::HasSSE42() ? "True" : "False");
    cout_tabbed("SSSE3", cpuid::CpuId::HasSSSE3() ? "True" : "False");
    cout_tabbed("SSE2", cpuid::CpuId::HasSSE2() ? "True" : "False");
    cout_tabbed("BestInstructionSet", argonishche::Utils::InstructionSetToString(cpuid::CpuId::GetBestSet()));
    cout << "}" << endl;

    return 0;
}
