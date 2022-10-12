#include "ProcessClass.h"
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

Process::Process(std::string name) : ProcessName(name) {
	std::string errMsg;
	char tempName[MAX_PATH];
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
			pid = procEntry.th32ProcessID; // Process found
			break;
		}
	} while (!Process32Next(hSnap, &procEntry));
	
	// Process not found
	if (pid == 0) {
		errMsg = "Process ";
		errMsg += name;
		errMsg += " not found.";
		throw BHNORMEXCEPTION(errMsg.c_str());
	}
	CloseHandle(hSnap);

	if (pid == 0) throw BHNORMEXCEPTION("Target process pid is 0, or you are trying to open the current Process.");
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
}

Process::Process(DWORD pid) {
	if (pid == 0) throw BHNORMEXCEPTION("Target process pid is 0, or you are trying to open the current Process.");
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
}

const Process& Process::operator=(const Process& src) {
	return src;
}

bool Process::ReadProcessMemory(uintptr_t addr, size_t size, OUT byte* out) const
{
	if (!::ReadProcessMemory(this->GetHandle(), reinterpret_cast<LPVOID>(addr), out, size, nullptr)) {
		if (this->_throw) throw BHWINEXCEPTION((std::stringstream("Memory address 0x") << std::hex << addr << " is inaccessiable.").str().c_str());
		return false;
	}
	return true;
}

bool Process::WriteProcessMemory(uintptr_t addr, size_t size, IN byte* out) const
{
	if (!::WriteProcessMemory(this->GetHandle(), reinterpret_cast<LPVOID>(addr), out, size, nullptr)) {
		if (this->_throw) throw BHWINEXCEPTION((std::stringstream("Could not write to memory address 0x") << std::hex << addr).str().c_str());
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
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream("VirtualFree on memory address 0x") << std::hex << addr << " Failed. Because dwFreeType is 0.").str().c_str());
			return false;
		}
		if ((dwFreeType & MEM_RELEASE) == 0) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream("VirtualFree on memory address 0x") << std::hex << addr << " Failed. Because passing without MEM_RELEASE could result in memory leak.").str().c_str());
			return false;
		}
		if (size != 0) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream("VirtualFree on memory address 0x") << std::hex << addr << " Failed. Because dwSize cannot be non-zero when MEM_RELEASE is passed.").str().c_str());
			return false;
		}
		if (dwFreeType & MEM_DECOMMIT) {
			if (this->_throw) throw BHWINEXCEPTION((std::stringstream("VirtualFree on memory address 0x") << std::hex << addr << " Failed. Because passing both MEM_RELEASE and MEM_DECOMMIT is not allowed.").str().c_str());
			return false;
		}
	}
	if (!::VirtualFreeEx(this->GetHandle(), reinterpret_cast<LPVOID>(addr), size, dwFreeType)) {
		if (this->_throw) throw BHWINEXCEPTION((std::stringstream("VirtualFree on memory address 0x") << std::hex << addr << " Failed.").str().c_str());
		return false;
	}
	return true;
#pragma warning( pop )
}

MEMORY_BASIC_INFORMATION& Process::VirtualQuery(uintptr_t addr) const
{
	ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (!::VirtualQueryEx(this->hProc, reinterpret_cast<LPVOID>(addr), &this->mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		throw BHWINEXCEPTION((std::stringstream("VirtualQuery Failed at address 0x") << std::hex << addr).str());
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
	if (page.GetBaseAddr() != addr) throw BHNORMEXCEPTION((std::stringstream("The address 0x") << std::hex << addr << " is not equal to the Page Base 0x" << std::hex << page.GetBaseAddr()).str());
	if (this->mem_consumption + page.GetSize() > this->max_mem_usage) this->SwapPages(page.GetSize());
	this->mmap.insert({ addr, std::move(page) });
	return this->mmap[addr];
}

void MemMap::Refresh()
{
	uintptr_t pageStart = 0;
	MemoryPage* lastPage = nullptr;
	do {
		MemoryPage& page = this->Load(pageStart);
		uintptr_t nextPageStart = pageStart + page.GetSize();

		// Exclude Free
		if (page.GetState() == MEM_FREE) {
			this->UnLoad(pageStart);
			if (nextPageStart <= pageStart) break;
			pageStart = nextPageStart;
		}

		// Update LastPage
		lastPage = &page;

		// Continue the loop
		if (nextPageStart <= pageStart) break;
		pageStart = nextPageStart;
	} while (true);
}

void MemMap::UnLoad(uintptr_t addr)
{
	this->mem_consumption -= this->mmap[addr].GetSize();
	this->PreLoad();
	this->mmap.erase(addr);
}

void MemMap::SwapPages(size_t size)
{
	MemoryPage* page = nullptr;
	do {
		page = &this->mmap[this->unswapped_addr_bound];
		page->Swap();
		this->unswapped_addr_bound = page->GetBaseAddr() + page->GetSize();
	} while(this->mem_consumption + size - page->GetSize() < this->max_mem_usage);
}

void MemMap::PreLoad()
{
	auto it = this->mmap.find(this->unswapped_addr_bound);
	if (it == this->mmap.begin()) return;
	while (this->mem_consumption + (--it)->second.GetSize() < this->max_mem_usage)
		it->second.UnSwap();
}
