#include "cpuid/cpuid.h"

#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <chrono>

#include "argonishche.h"

using namespace argonishche;

volatile bool run = true;

static void AlarmHandler(int i)
{
    (void)i;    /* To remove warning about unused parameter */
    run = false;
}

struct BenchmarkResult {
    uint64_t count;
    double time;
};

struct Config {
    uint32_t tcost;
    uint32_t mcost;
    uint32_t threads;
    uint32_t fork;
    bool help;
    char* json_filename;
    Argon2Type type;
};

class ArgumentsParser {
public:
    static void PrintHelp(char* appname) {
        std::cout << appname << " - is a simple 'openssl speed' like benchmark" << std::endl;
        std::cout << "Usage: " << std::endl;
        std::cout << "\t--tcost" << "\t\t" << "tcost value indicates number of passes over memory" << std::endl;
        std::cout << "\t--mcost" << "\t\t" << "mcost in Kb indicates how much memory Argon2 will use" << std::endl;
        std::cout << "\t--threads" << "\t\t" << "threags parameter sets the number of threads in Argon2. You need OpenMP or the processing will be carried out sequentially." << std::endl;
        std::cout << "\t--fork" << "\t\t" << "how many processes will be used for benchmark" << std::endl;
        std::cout << "\t--json" << "\t\t" << "filename to write results in json format" << std::endl;
        std::cout << "\t--type" << "\t\t" << "Argon2 type can be i, d or id" << std::endl;
    }

    static Config Parse(int argc, char** argv) {
        Config def;
        /* default values */
        def.tcost = 1;
        def.mcost = 2048;
        def.threads = 1;
        def.fork = 2;
        def.json_filename = nullptr;
        def.help = false;
        def.type = Argon2Type::Argon2_d;

        int i = 1;
        while(i < argc) {
            std::string arg = argv[i];
            if((arg == "--tcost" || arg == "-t") && (i + 1 < argc)) {
                int value = std::atoi(argv[i + 1]);
                if (value <= 0) {
                    std::cout << "[E] tcost must be a positive integer!" << std::endl;
                    i += 2;
                    continue;
                }
                def.tcost = (uint32_t)value;
                i += 2;
                continue;
            } else if((arg == "--mcost" || arg == "-m") && (i + 1 < argc)) {
                int value = std::atoi(argv[i + 1]);
                if (value <= 0) {
                    std::cout << "[E] mcost must be a positive integer!" << std::endl;
                    i += 2;
                    continue;
                }
                def.mcost = (uint32_t)value;
                i += 2;
                continue;
            } else if((arg == "--threads" || arg == "-th") && (i + 1 < argc)) {
                int value = std::atoi(argv[i + 1]);
                if(value <= 0) {
                    std::cout << "[E] threads must be a positive integer!" << std::endl;
                    i += 2;
                    continue;
                }
                def.threads = (uint32_t)value;
                i += 2;
            } else if((arg == "--fork" || arg == "-f") && (i + 1 < argc)) {
                int value = std::atoi(argv[i + 1]);
                if(value <= 0) {
                    std::cout << "[E] fork must be a positive integer!" << std::endl;
                    i += 2;
                    continue;
                }
                def.fork = (uint32_t)value;
                i += 2;
                continue;
            } else if((arg == "--json" || arg == "-j") && (i + 1 < argc)) {
                def.json_filename = argv[i + 1];
                i += 2;
                continue;
            } else if((arg == "--help")) {
                def.help = true;
                i += 1;
                continue;
            } else if((arg == "--type") && (i + 1 < argc)) {
                std::string type = argv[i + 1];
                if (type == "d")
                    def.type = Argon2Type::Argon2_d;
                else if(type == "i")
                    def.type = Argon2Type::Argon2_i;
                else if (type == "id") {
                    def.type = Argon2Type::Argon2_id;
                } else {
                    std::cout << "[E] Unrecognized Argon2 type " << type << std::endl;
                    std::cout << "[E] " << Utils::Argon2TypeToString(def.type) << " will be used instead" << std::endl;
                }
                i += 2;
                continue;
            } else {
                std::cout << "[E] Unrecognized command line argument " << argv[i] << std::endl;
                std::cout.flush();
                ++i;
            }
        }

        return def;
    }
};

class Argon2Benchmark {
public:
    Argon2Benchmark(InstructionSet instructionSet, Argon2Type argon2Type, uint32_t tcost,
                    uint32_t mcost, uint32_t threads, uint32_t forksnum)
            : forksnum__(forksnum), tcost__(tcost), mcost__(mcost), threads__(threads), instructionSet__(instructionSet) {
        if(forksnum__ == 0)
            forksnum__ = 1;
        Argon2Factory factory;
        uint8_t key[32];
        memset(key, 0xaa, 32);
        memset(pwd__, 0xbb, sizeof(pwd__));
        memset(salt__, 0xcc, sizeof(salt__));
        argon2__ = factory.Create(instructionSet, argon2Type, tcost, mcost, threads, key, sizeof(key));
        results__.reset(new BenchmarkResult[forksnum__]);
        fds__.reset(new int[forksnum__]);
    }

    /* Returns true if we're parent */
    bool Run() {
	    if(forksnum__ > 1) {
            int pid;
            int fd[2] = {0, 0};
            for(uint32_t i = 0; i < forksnum__; ++i) {
                if(pipe(fd) == -1) {
                    throw std::runtime_error("Can't open pipe");
                }

                fflush(stderr);
                fflush(stdout);

                pid = fork();
                if(pid == -1) {
                    throw std::runtime_error("Can't fork process");
                }

                if(pid) { /* parent */
                    close(fd[1]);
                    fds__[i] = fd[0];
                } else { /* child */
                    close(fd[0]);
                    BenchmarkResult result = RunTest__();
                    bool sres = SendData__(result, fd[1]);
                    close(fd[1]);
                    if(!sres)
                        throw std::runtime_error("Can't send the data");

                    exit(0);
                }
            }

            CollectResults__();
            return true;
        } else {
            BenchmarkResult result = RunTest__();
            memcpy(&results__.get()[0], &result, sizeof(result));
            return true;
        }

        return false;
    }

    void PrintResults() {
        std::cout << "Num\t| Count\t| Time\t " << std::endl;
        for(uint32_t i = 0; i < forksnum__; ++i) {
            std::cout << i << "\t| " << results__[i].count << "\t| " << results__[i].time << "\t" << std::endl;
        }
    }

    void AddJson(std::stringstream& str) {
        str << "\t\"" << Utils::InstructionSetToString(instructionSet__) << "\": {" << std::endl;
        str << "\t\t" << "\"params\": {" << std::endl;
        str << "\t\t\t" << "\"tcost\": " << tcost__ << ", " << std::endl;
        str << "\t\t\t" << "\"mcost\": " << mcost__ << ", " << std::endl;
        str << "\t\t\t" << "\"threads\": " << tcost__ << ", " << std::endl;
        str << "\t\t\t" << "\"fork\": " << forksnum__  << std::endl;
        str << "\t\t" << "}," << std::endl;

        str << "\t\t" << "\"results\": [" << std::endl;

        for(uint32_t i = 0; i < forksnum__; i++) {
            str << "\t\t\t" << "{" << std::endl;
            str << "\t\t\t\t" << "\"num\": " << i << "," << std::endl;
            str << "\t\t\t\t" << "\"count\": " << results__[i].count << "," << std::endl;
            str << "\t\t\t\t" << "\"time\" : \"" << results__[i].time << "\", " << std::endl;
            str << "\t\t\t" << "}" << ((i == forksnum__ - 1) ? " " : ",") << std::endl;
        }

        str << "\t\t" << "]" << std::endl;
        str << "\t}";
    }

protected:
    BenchmarkResult RunTest__() {
        BenchmarkResult result = {0, 0};
        run = true;

        auto start_time = std::chrono::system_clock::now();
        signal(SIGALRM, AlarmHandler);
        alarm(RunningTime);

        while(run) {
            Iteration__();
            result.count++;
        }

        auto stop_time = std::chrono::system_clock::now();
        result.time = std::chrono::duration<double, std::milli>(stop_time - start_time).count() / 1000.0;

        return result;
    }

    void CollectResults__() {
        for(uint32_t i = 0; i < forksnum__; ++i) {
            ReadData__(&(results__[i]), fds__[i]);
            close(fds__[i]);
        }
    }

    void Iteration__() {
        argon2__->Hash(pwd__, sizeof(pwd__), salt__, sizeof(salt__), out__, sizeof(out__));
    }

    static bool SendData__(const BenchmarkResult& data, int fd) {
        bool result = false;
        FILE* f = fdopen(fd, "wb");

        if (f != nullptr) {
            if (1 == fwrite((void *) &data, sizeof(BenchmarkResult), 1, f)) {
                result = true;
                fflush(f);
            }
            fclose(f);
        }

        return result;
    }

    static void ReadData__(BenchmarkResult* br, int fd) {
        FILE* f = fdopen(fd, "rb");
        if (f != nullptr) {
            size_t read_result = fread((void*)br, sizeof(BenchmarkResult), 1, f);
            fclose(f);

            if(read_result == 1)
                return;
            else
                throw std::runtime_error("Can't read pipe"); /* XXX */
        }

        throw std::runtime_error("Can't open pipe for reading"); /* XXX */
    }

protected:
    uint8_t pwd__[32];
    uint8_t salt__[32];
    uint8_t out__[32];
    std::unique_ptr<Argon2Base> argon2__;
    uint32_t forksnum__;
    uint32_t tcost__;
    uint32_t mcost__;
    uint32_t threads__;
    InstructionSet instructionSet__;

    std::unique_ptr<BenchmarkResult[]> results__;
    std::unique_ptr<int[]> fds__;

    static const int RunningTime = 10;
};

int main(int argc, char** argv)
{
    Config cnf = ArgumentsParser::Parse(argc, argv);
    if (cnf.help) {
        ArgumentsParser::PrintHelp(argv[0]);
        return EXIT_SUCCESS;
    }

    std::cout << "[~] Argorithm: " << Utils::Argon2TypeToString(cnf.type) << std::endl;
    std::cout << "[~] Tcost: " << cnf.tcost << std::endl;
    std::cout << "[~] Mcost: " << cnf.mcost << std::endl;
    std::cout << "[~] Threads: " << cnf.threads << std::endl;
#ifdef _OPENMP
    std::cout << "[~] OpenMP is enabled so the fork parameter will be ignored" << std::endl;
    cnf.fork = 1;
#endif
    std::cout << "[~] Fork: " << cnf.fork << std::endl;

    Argon2Benchmark benchmarkRef(InstructionSet::REF, cnf.type,
                                 cnf.tcost, cnf.mcost, cnf.threads, cnf.fork);
    Argon2Benchmark benchmarkSse2(InstructionSet::SSE2, cnf.type,
                                  cnf.tcost, cnf.mcost, cnf.threads, cnf.fork);
    Argon2Benchmark benchmarkSsse3(InstructionSet::SSSE3, cnf.type,
                                   cnf.tcost, cnf.mcost, cnf.threads, cnf.fork);
    Argon2Benchmark benchmarkSse41(InstructionSet::SSE41, cnf.type,
                                   cnf.tcost, cnf.mcost, cnf.threads, cnf.fork);
    Argon2Benchmark benchmarkAvx2(InstructionSet::AVX2, cnf.type,
                                  cnf.tcost, cnf.mcost, cnf.threads, cnf.fork);

    InstructionSet best = cpuid::CpuId::GetBestSet();

    /* Warmup */
    std::cout << "[~] Warmup..." << std::endl;
    for(int i = 0; i < 3; ++i) {
        Argon2Benchmark warmup(InstructionSet::REF, Argon2Type::Argon2_d, 1, 1024, 1, cnf.fork);
        if(!warmup.Run())   /* Shutdown the child process */
            return 0;
    }

    std::cout << "[~] Running REF..." << std::endl;
    benchmarkRef.Run();

    if(best >= InstructionSet::SSE2) {
        std::cout << "[~] Running SSE2..." << std::endl;
        benchmarkSse2.Run();
    }

    if(best >= InstructionSet::SSSE3) {
        std::cout << "[~] Running SSSE3..." << std::endl;
        benchmarkSsse3.Run();
    }

    if(best >= InstructionSet::SSE41) {
        std::cout << "[~] Running SSE41..." << std::endl;
        benchmarkSse41.Run();
    }

    if(best >= InstructionSet::AVX2) {
        std::cout << "[~] Running AVX2..." << std::endl;
        benchmarkAvx2.Run();
    }

    std::stringstream json;
    json << "{" << std::endl;

    std::cout << "---- REF ----" << std::endl;
    benchmarkRef.PrintResults();
    benchmarkRef.AddJson(json);

    if(best >= InstructionSet::SSE2) {
        std::cout << "---- SSE2 ---" << std::endl;
        benchmarkSse2.PrintResults();
        json << "," << std::endl;
        benchmarkSse2.AddJson(json);
    }

    if(best >= InstructionSet::SSSE3) {
        std::cout << "--- SSSE3 ---" << std::endl;
        benchmarkSsse3.PrintResults();
        json << "," << std::endl;
        benchmarkSsse3.AddJson(json);
    }

    if (best >= InstructionSet::SSE41) {
        std::cout << "--- SSE41 ---" << std::endl;
        benchmarkSse41.PrintResults();
        json << "," << std::endl;
        benchmarkSse41.AddJson(json);
    }

    if(best >= InstructionSet::AVX2) {
        std::cout << "-----AVX2----" << std::endl;
        benchmarkAvx2.PrintResults();
        json << "," << std::endl;
        benchmarkAvx2.AddJson(json);
    }
    json << std::endl << "}" << std::endl;

    if (cnf.json_filename != nullptr) {
        std::ofstream fl;
        fl.open(cnf.json_filename);
        if(fl.is_open()) {
            fl << json.str();
            fl.close();
            std::cout << "[~] The results have been written to " << cnf.json_filename << std::endl;
        } else {
            std::cout << "[E] Can't write to file " << cnf.json_filename << std::endl;
        }
    }

    return 0;
}
