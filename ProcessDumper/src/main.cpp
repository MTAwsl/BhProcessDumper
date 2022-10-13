#include <argparse/argparse.hpp>
#include <iostream>
#include <windows.h>
#include "ProcessClass.h"
#include "MemoryClass.h"
#include "bhException.h"

int main(int argc, char** argv) {
    argparse::ArgumentParser program("BhProcessDumper");

    program.add_argument("-n", "--name")
        .help("Name of the target process.");

    program.add_argument("-p", "--pid")
        .help("PID of the target process.")
        .scan<'u', DWORD>();

    program.add_argument("-o", "--output")
        .help("Output file name.");

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    try {
        const char* processname = nullptr;
        DWORD pid = 0;
        const char* outputDir = nullptr;
        if (program.is_used("-p")) {
            pid = program.get<DWORD>("-p");
        }
        else if (program.is_used("-n")) {
            processname = program.get<const char*>("-n");
        }
        else {
            std::cerr << "No Process specified. Using -p for PID or -n for Process Name." << std::endl;
            std::cerr << program;
            std::exit(1);
        }
#pragma warning (push)
#pragma warning (disable: 6387)
        std::shared_ptr<Process> proc = nullptr;
        if (pid) proc = std::make_shared<Process>(pid);
        else proc = std::make_shared<Process>(processname);
        MemMap mmap(proc);
        mmap.Refresh();
#pragma warning (pop)
        for (auto& pair : mmap.GetMap()) {
            const MemoryPage& page = pair.second;
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << page.GetBaseAddr() << " "
                << std::setw(7) << std::setfill(' ') << MemRegionTypeStringify[page.GetType()] << " "
                << std::setw(5) << std::setfill(' ') << MemProtectionToString(page.GetProtection()) << " "
                << page.GetInfo()
                << std::endl;
        }
        
        if (program.is_used("-o")) {
            mmap.DumpToFile(program.get<std::string>("-o"));
        }
        else {
            mmap.DumpToFile(std::string() + proc->GetProcName() + "_dump.dmp");
        }
    }
    catch (bhException& err) {
        err.Alert();
        std::exit(1);
    }

	return 0;
}