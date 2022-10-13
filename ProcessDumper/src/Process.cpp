#include "ProcessClass.h"
#include "filestruct.h"
#include <psapi.h>
#include <TlHelp32.h>
#include <fstream>

HANDLE Process::GetHandle() const noexcept
{
	return this->hProc;
}

DWORD Process::GetPID() const noexcept
{
	return this->pid;
}

const char* Process::GetProcName() const noexcept
{
	return this->ProcessName.c_str();
}

bool Process::GetThrow() const noexcept
{
	return this->_throw;
}

void Process::SetThrow(bool _throw) noexcept
{
	this->_throw = _throw;
}

const std::unordered_map<uintptr_t, std::string>& Process::GetModNameMap() const noexcept
{
	return this->modNameMap;
}

Process::Process(std::string name) : ProcessName(name) {
	std::string errMsg;
	char tempName[max(MAX_PATH, MAX_MODULE_NAME32 + 1)];
	this->pid = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		throw BHWINEXCEPTION("CreateToolhelp32Snapshot returned a invalid handle.");
	}

	PROCESSENTRY32 procEntry;
	ZeroMemory(&procEntry, sizeof(PROCESSENTRY32));
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	// Inherit over processes
	if (!Process32First(hSnap, &procEntry)) throw BHWINEXCEPTION("Process32First returned false.");
	do {
		sprintf_s(tempName, "%ws", procEntry.szExeFile);
		if (!strcmp(tempName, name.c_str())) {
			this->pid = procEntry.th32ProcessID; // Process found
			break;
		}
	} while (Process32Next(hSnap, &procEntry));
	
	// Process not found
	if (this->pid == 0) {
		errMsg = "Process ";
		errMsg += name;
		errMsg += " not found.";
		throw BHNORMEXCEPTION(errMsg.c_str());
	}
	CloseHandle(hSnap);

	HANDLE Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (Handle)
	{
		char Buffer[MAX_PATH];
		if (GetModuleFileNameExA(Handle, 0, Buffer, MAX_PATH))
		{
			this->ProcessName = Buffer;
			this->hProc = Handle;
		}
		else
		{
			CloseHandle(Handle);
			throw BHWINEXCEPTION("Cannot retrieve the target process name.");
		}

	}
	else throw BHWINEXCEPTION("OpenProcess returned 0.");

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->pid);
	if (hSnap == INVALID_HANDLE_VALUE) {
		throw BHWINEXCEPTION("CreateToolhelp32Snapshot returned a invalid handle.");
	}
	MODULEENTRY32 modEntry;
	ZeroMemory(&modEntry, sizeof(MODULEENTRY32));
	modEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hSnap, &modEntry)) throw BHWINEXCEPTION("Module32First returned false.");
	do {
		sprintf_s(tempName, "%ws", modEntry.szModule);
		this->modNameMap.insert({ reinterpret_cast<uintptr_t>(modEntry.modBaseAddr), tempName });
	} while (Module32Next(hSnap, &modEntry));

}

Process::Process(DWORD pid) {
	if (pid == 0) throw BHNORMEXCEPTION("Target process pid is 0, or you are trying to open the current Process.");
	this->pid = pid;
	HANDLE Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (Handle)
	{
		char Buffer[MAX_PATH];
		if (GetModuleFileNameExA(Handle, 0, Buffer, MAX_PATH))
		{
			this->ProcessName = strrchr(Buffer, '\\')+1;
			this->hProc = Handle;
		}
		else
		{
			CloseHandle(Handle);
			throw BHWINEXCEPTION("Cannot retrieve the target process name.");
		}
		
	}
	else throw BHWINEXCEPTION("OpenProcess returned 0.");

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->pid);
	char tempName[max(MAX_PATH, MAX_MODULE_NAME32 + 1)];
	if (hSnap == INVALID_HANDLE_VALUE) {
		throw BHWINEXCEPTION("CreateToolhelp32Snapshot returned a invalid handle.");
	}
	MODULEENTRY32 modEntry;
	ZeroMemory(&modEntry, sizeof(MODULEENTRY32));
	modEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hSnap, &modEntry)) throw BHWINEXCEPTION("Module32First returned false.");
	do {
		sprintf_s(tempName, "%ws", modEntry.szModule);
		this->modNameMap.insert({ reinterpret_cast<uintptr_t>(modEntry.modBaseAddr), tempName });
	} while (Module32Next(hSnap, &modEntry));
}

const Process& Process::operator=(const Process& src) {
	return src;
}

bool Process::ReadProcessMemory(uintptr_t addr, size_t size, OUT byte* out) const
{
	if (!::ReadProcessMemory(this->GetHandle(), reinterpret_cast<LPVOID>(addr), out, size, nullptr)) {
		if (this->_throw) throw BHWINEXCEPTION((std::stringstream() << ("Memory address 0x") << std::hex << addr << " is inaccessiable.").str().c_str());
		return false;
	}
	return true;
}

bool Process::WriteProcessMemory(uintptr_t addr, size_t size, IN byte* out) const
{
	if (!::WriteProcessMemory(this->GetHandle(), reinterpret_cast<LPVOID>(addr), out, size, nullptr)) {
		if (this->_throw) throw BHWINEXCEPTION((std::stringstream() << ("Could not write to memory address 0x") << std::hex << addr).str().c_str());
		return false;
	}
	return true;
}

uintptr_t Process::VirtualAlloc(uintptr_t addr, size_t size, DWORD flAllocationType, DWORD flProtect) const
{
	uintptr_t result = reinterpret_cast<uintptr_t>(::VirtualAllocEx(this->GetHandle(), reinterpret_cast<LPVOID>(addr), size, flAllocationType, flProtect));
	if (!result) throw BHWINEXCEPTION("VirtualAlloc Failed.");
	return result;
}

bool Process::VirtualFree(uintptr_t addr, size_t size, DWORD dwFreeType, bool override) const
{
#pragma warning( push )
#pragma warning( disable : 28160)
	if (!override) {
		if (!dwFreeType) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream() <<"VirtualFree on memory address 0x" << std::hex << addr << " Failed. Because dwFreeType is 0.").str().c_str());
			return false;
		}
		if ((dwFreeType & MEM_RELEASE) == 0) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream() <<"VirtualFree on memory address 0x" << std::hex << addr << " Failed. Because passing without MEM_RELEASE could result in memory leak.").str().c_str());
			return false;
		}
		if (size != 0) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream() << "VirtualFree on memory address 0x" << std::hex << addr << " Failed. Because dwSize cannot be non-zero when MEM_RELEASE is passed.").str().c_str());
			return false;
		}
		if (dwFreeType & MEM_DECOMMIT) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream() << "VirtualFree on memory address 0x" << std::hex << addr << " Failed. Because passing both MEM_RELEASE and MEM_DECOMMIT is not allowed.").str().c_str());
			return false;
		}
	}
	if (!::VirtualFreeEx(this->GetHandle(), reinterpret_cast<LPVOID>(addr), size, dwFreeType)) {
		if (this->_throw) throw BHWINEXCEPTION((std::stringstream() << "VirtualFree on memory address 0x" << std::hex << addr << " Failed.").str().c_str());
		return false;
	}
	return true;
#pragma warning( pop )
}

DWORD Process::VirtualProtect(uintptr_t addr, size_t size, DWORD flNewProtect) const
{
	DWORD oldProtect;
	if (!::VirtualProtectEx(this->GetHandle(), reinterpret_cast<LPVOID>(addr), size, flNewProtect, &oldProtect))
		throw BHWINEXCEPTION((std::stringstream() << "VirtualProtect on memory address 0x" << std::hex << addr << " Failed.").str());
	return oldProtect;
}

MEMORY_BASIC_INFORMATION& Process::VirtualQuery(uintptr_t addr) const
{
	ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (!::VirtualQueryEx(this->hProc, reinterpret_cast<LPVOID>(addr), &this->mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		throw BHWINEXCEPTION((std::stringstream() << "VirtualQuery Failed at address 0x" << std::hex << addr).str());
	}
	return this->mbi;
}

Process::~Process()
{
	CloseHandle(hProc);
}

MemMap::MemMap(std::shared_ptr<Process> ptr): proc(ptr) {}

MemoryPage& MemMap::Load(uintptr_t addr)
{
	MemoryPage page = MemoryPage(this->proc, addr);
	if (page.GetBaseAddr() != addr) throw BHNORMEXCEPTION((std::stringstream() << ("The address 0x") << std::hex << addr << " is not equal to the Page Base 0x" << std::hex << page.GetBaseAddr()).str());
	if (page.GetState() & MEM_COMMIT) {
		if (this->mem_consumption + page.GetSize() > this->max_mem_usage) this->SwapPages(page.GetSize());
		page.Dump();
	}
	this->mmap.insert({ addr, std::move(page) });
	return this->mmap[addr];
}

void MemMap::Refresh()
{
	uintptr_t pageStart = 0;
	this->mmap.clear();
	this->mem_consumption = 0;
	do {
		try {
			MemoryPage& page = this->Load(pageStart);
			uintptr_t nextPageStart = pageStart + page.GetSize();

			// Exclude Free
			if (page.GetState() == MEM_FREE) {
				this->mmap.erase(pageStart);
				if (nextPageStart <= pageStart) break;
				pageStart = nextPageStart;
				continue;
			}

			// Continue the loop
			if (nextPageStart <= pageStart) break;
			pageStart = nextPageStart;
		}
		catch (bhWinException& err) {
			if (err.GetCode() != ERROR_INVALID_PARAMETER || err.GetMsg().find("VirtualQuery") == std::string::npos)
				throw err;
			break;
		}
	} while (true);
}

void MemMap::DumpToFile(fs::path path) const
{
	fs::path extension = path.extension();
	path.replace_extension("tmp");
	std::ofstream file(path, std::ios::out | std::ios::trunc | std::ios::binary);
	std::unordered_map<std::string, uint16_t> stringTable = { {this->proc->GetProcName(), 0}};
	uint16_t strIndexEnd = 1;
	std::cout << "Building file dump..." << std::endl;
	for (auto& pair : this->mmap) {
		const MemoryPage& pg = pair.second;
		std::string info = pg.GetInfo();
		uint16_t strIndex = 0;
		if (!info.empty()) {
			if (stringTable.contains(info)) {
				strIndex = stringTable.at(info);
			}
			else {
				strIndex = strIndexEnd++;
				stringTable.insert({ info, strIndex });
			}
		}
		page_data pgdata = {
			pg.GetType(), pg.GetBaseAddr(), pg.GetAllocBase(),
			pg.GetState(), pg.GetProtection(), strIndex, static_cast<uint32_t>(pg.GetSize())
		};
		if (pg.GetState() & MEM_COMMIT) {
			file.write(reinterpret_cast<const char*>(&pgdata), sizeof(pgdata) - 1);
			byte* buf = new byte[pg.GetSize()];
			pg.Pull(buf, pg.GetSize());
			file.write(reinterpret_cast<const char*>(buf), pg.GetSize());
			delete[] buf;
		}
	}
	file.close();
	std::cout << "Writing string table..." << std::endl;
	std::ifstream tmpFile(path, std::ios::in | std::ios::binary);
	path.replace_extension(extension);
	std::ofstream dmpFile(path, std::ios::out | std::ios::trunc | std::ios::binary);
	dumpfile_header head;
	std::unordered_map<uint16_t, const std::string&> strTableOrdered = {};
	for (auto& pair : stringTable) {
		strTableOrdered.insert({ pair.second, pair.first });
	}
	head.time = std::time(nullptr);
#ifdef _WIN64
	head.arch = 0x8664;
#else
	head.arch = 0x1386;
#endif
	head.strCount = strIndexEnd;
	head.pageCount = static_cast<uint32_t>(this->mmap.size());
	dmpFile.write(reinterpret_cast<const char*>(&head), sizeof(dumpfile_header) - 1);
	for (uint16_t i = 0; i < strIndexEnd; i++)
		dmpFile.write(strTableOrdered.at(i).c_str(), strTableOrdered.at(i).size() + 1);
	std::cout << "Copying dump file..." << std::endl;
	
	const unsigned int length = 8192;
	char buffer[length];

	tmpFile.read(buffer, length);
	while (!tmpFile.eof()) {
		dmpFile.write(buffer, length);
		tmpFile.read(buffer, length);
	}

	dmpFile.write(buffer, tmpFile.gcount());

	tmpFile.close();
	dmpFile.close();
	path.replace_extension("tmp");
	std::cout << "Removing temp file" << std::endl;
	fs::remove(path);
	std::cout << "Done!" << std::endl;
}

const std::unordered_map<uintptr_t, MemoryPage>& MemMap::GetMap() const noexcept
{
	return this->mmap;
}

void MemMap::SwapPages(size_t size)
{
	using enum MemoryPage::DumpStorageMode;
	this->mem_consumption += size;
	
	// Too lazy to implement an efficient algorithm for this.
	for (auto& pair : this->mmap) {
		MemoryPage& page = pair.second;
		if (page.GetDumpMode() == Memory) {
			page.Swap();
			this->mem_consumption -= page.GetSize();
		}
	}
}
