#include <argparse/argparse.hpp>
#include <iostream>
#include <windows.h>
#include <string>
#include <filesystem>
#include <vector>
#include <fstream>
#include "filestruct.h"

const char* MemRegionTypeStringify[] = {
   "Private", "Mapped", "Image", "Others", "Invalid"
};

std::string MemProtectionToString(DWORD Protect) {
    std::string result;
    if (!Protect)        //reserved pages don't have a protection (https://goo.gl/Izkk0c)
    {
        return "";
    }
    switch (Protect & 0xFF)
    {
    case PAGE_NOACCESS:
        result = "----";
        break;
    case PAGE_READONLY:
        result = "-R--";
        break;
    case PAGE_READWRITE:
        result = "-RW-";
        break;
    case PAGE_WRITECOPY:
        result = "-RWC";
        break;
    case PAGE_EXECUTE:
        result = "E---";
        break;
    case PAGE_EXECUTE_READ:
        result = "ER--";
        break;
    case PAGE_EXECUTE_READWRITE:
        result = "ERW-";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        result = "ERWC";
        break;
    default:
        break;
    }

    result.push_back(((Protect & PAGE_GUARD) == PAGE_GUARD) ? 'G' : '-');
    //  Rights[5] = ((Protect & PAGE_NOCACHE) == PAGE_NOCACHE) ? '' : '-';
    //  Rights[6] = ((Protect & PAGE_WRITECOMBINE) == PAGE_GUARD) ? '' : '-';

    return result;
}

int main(int argc, char** argv) {
    argparse::ArgumentParser program("BhProcessDumper");

    program.add_argument("file").required();

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    std::filesystem::path path = program.get<std::string>("file");
    if (!std::filesystem::exists(path)) {
        std::cerr << "File not found!" << std::endl;
        return 1;
    }
    std::ifstream file(path, std::ios::in | std::ios::binary);
    dumpfile_header head;
    
    std::vector<std::string> stringTable= {};
    file.read(reinterpret_cast<char*>(&head), sizeof(dumpfile_header) - 1);
    for (size_t i = 0; i < head.strCount; i++) {
        std::string str;
        std::getline(file, str, '\0');
        stringTable.push_back(str);
    }
    std::cout << "Process " << stringTable[0] << std::endl;
    for (size_t i = 0; i < head.pageCount; i++) {
        page_data pg;
        file.read(reinterpret_cast<char*>(&pg), sizeof(page_data) - 1);
        // No need to read data, you can read data using file.read
        // In this example, we just skip those bytes.
        file.ignore(pg.size);
        std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << pg.addr << " "
            << std::setw(7) << std::setfill(' ') << MemRegionTypeStringify[pg.type] << " "
            << std::setw(5) << std::setfill(' ') << MemProtectionToString(pg.Protection) << " "
            << (pg.infoStrIndex ? stringTable[pg.infoStrIndex] : "")
            << std::endl;
    }

	return 0;
}