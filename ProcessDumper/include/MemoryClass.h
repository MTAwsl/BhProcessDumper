#pragma once
#include "stdafx.h"
#include "ProcessClass.h"

namespace fs = std::filesystem;

class Process;

enum MemRegionType { Private=0, Mapped, Image, Others, Invalid };
extern const char* MemRegionTypeStringify[];

std::string MemProtectionToString(DWORD);

class MemoryPage {
public:
	enum DumpStorageMode { Memory, Disk, Initial, None };

	class DumpException : public bhException {
	public:
		enum Type {NonCommit, AlreadySwapped, NotSwapped, NotDumped, InvalidMode, Unexpected};
		Type err;
		DumpException(Type type, const char* file, unsigned int line, uintptr_t msg);
	};
public:
	MemRegionType GetType() const noexcept;
	DWORD GetProtection() const noexcept;
	std::shared_ptr<Process> GetProcess() const noexcept;
	uintptr_t GetBaseAddr() const noexcept;
	uintptr_t GetAllocBase() const noexcept;
	size_t GetSize() const noexcept;
	DumpStorageMode GetDumpMode() const noexcept;
	DWORD GetState() const noexcept;
	std::string GetInfo() const noexcept;
	std::string GetProcName() const noexcept;
	template <typename T> const T& operator[](unsigned int) const;

	void Swap() const;
	void UnSwap() const;
	void Dump() const;
	void Pull(OUT byte* out, IN size_t size) const;
	MemoryPage(std::shared_ptr<Process> proc, uintptr_t address);
	MemoryPage(const MemoryPage& src);
	MemoryPage() noexcept;
	~MemoryPage();
private:
	MemRegionType type;
	std::shared_ptr<Process> proc;
	DWORD state;
	DWORD perm;
	uintptr_t addr;
	uintptr_t allocBaseAddr;
	size_t size;
	std::string info;
	std::string procName;
protected:
	mutable DumpStorageMode mode;
	mutable fs::path dumppath;
	mutable std::unique_ptr<byte[]> buffer;
	mutable std::fstream dumpfile;
};

