#pragma once
#include "stdafx.h"
#include "MemoryClass.h"

class MemoryPage;
class Process;

class MemMap {
public:
	MemMap(std::shared_ptr<Process> ptr);
	MemoryPage& Load(uintptr_t addr);
	void Refresh();
	void UnLoad(uintptr_t addr);
private:
	void SwapPages(size_t size);
	void PreLoad();
private:
	size_t mem_consumption = 0;
	const size_t max_mem_usage = 20 << 20; // 20 MegaBytes
	std::shared_ptr<Process> proc;
	uintptr_t unswapped_addr_bound = 0;
	std::unordered_map<uintptr_t, MemoryPage> mmap = {};
};

class Process {
public:
	HANDLE GetHandle() const noexcept;
	DWORD GetPID() const noexcept;
	const char* GetProcName() const noexcept;
	bool GetThrow() const noexcept;
	void SetThrow(bool) noexcept;
public:
	Process(std::string name);
	Process(DWORD pid);
	const Process& operator=(const Process& src);
	bool ReadProcessMemory(uintptr_t addr, size_t size, OUT byte* out) const;
	bool WriteProcessMemory(uintptr_t addr, size_t size, IN byte* out) const;
	uintptr_t VirtualAlloc(uintptr_t addr, size_t size, DWORD flAllocationType, DWORD flProtect) const;
	bool VirtualFree(uintptr_t addr, size_t size, DWORD dwFreeType, bool override = false) const;
	MEMORY_BASIC_INFORMATION& VirtualQuery(uintptr_t addr) const;
	~Process();
public:
private:
	HANDLE hProc;
	DWORD pid;
	std::string ProcessName;
	bool _throw = true;
protected:
	mutable MEMORY_BASIC_INFORMATION mbi;
};

