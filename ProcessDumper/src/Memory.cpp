#include "MemoryClass.h"

MemoryPage::MemRegionType MemoryPage::GetType() const noexcept
{
	return this->type;
}

DWORD MemoryPage::GetProtection() const noexcept
{
	return this->perm;
}

std::shared_ptr<Process> MemoryPage::GetProcess() const noexcept
{
    return this->proc;
}

uintptr_t MemoryPage::GetBaseAddr() const noexcept
{
	return this->addr;
}

uintptr_t MemoryPage::GetAllocBase() const noexcept
{
	return this->allocBaseAddr;
}

size_t MemoryPage::GetSize() const noexcept
{
	return this->size;
}

MemoryPage::DumpStorageMode MemoryPage::GetDumpMode() const noexcept
{
    return this->mode;
}

DWORD MemoryPage::GetState() const noexcept
{
    return this->state;
}

std::string MemoryPage::GetInfo() const noexcept
{
	return this->info;
}

std::string MemoryPage::GetProcName() const noexcept
{
    return this->procName;
}

template<typename T>
inline const T& MemoryPage::operator[](unsigned int index) const
{
    if (!this->state & MEM_COMMIT) throw BHNORMEXCEPTION((std::stringstream("Tried to Read address ") << std::hex << "0x" << this->addr+index << " which is not commited.").str().c_str());
    if (index >= size / sizeof(T)) throw BHNORMEXCEPTION("Index out of bound.");
    if (this->mode == Disk) this->UnSwap();
    return ((const T*)(buffer.get()))[index];
}

void MemoryPage::Swap() const
{
    using enum MemoryPage::DumpException::Type;

    switch (this->mode) {
    case None:
        throw DumpException(NonCommit, __FILE__, __LINE__, this->addr);
        return;
    case Disk:
        throw DumpException(AlreadySwapped, __FILE__, __LINE__, this->addr);
        return;
    case Memory:
        break;
    default:
        throw DumpException(InvalidMode, __FILE__, __LINE__, this->mode);
        return;
    }

    try {
        char fileName[MAX_PATH];
        fs::path path = std::filesystem::temp_directory_path();
        if (sprintf_s(fileName, "%s_0x%p_%x.dump", this->procName.c_str(), reinterpret_cast<LPVOID>(this->addr), rand()) == -1) throw BHNORMEXCEPTION("Dump Path initalization failed.");
        path.append(fileName);

        this->dumppath = path;
        this->dumpfile.open(this->dumppath, std::ios::out | std::ios::binary | std::ios::trunc);
        this->dumpfile.write(reinterpret_cast<const char*>(this->buffer.get()), this->size);
        this->dumpfile.close();

        // Change mode and free memory after dump.
        this->mode = Disk;
        if (!this->buffer) throw BHNORMEXCEPTION("Memory corruption.");
        this->buffer.release();
        this->buffer = nullptr;
    }
    catch (fs::filesystem_error& e) {
        SetLastError(e.code().value());
        throw BHWINEXCEPTION("Failed to get temp path.");
    }
    catch (std::ios::failure& e) {
        SetLastError(e.code().value());
        throw BHWINEXCEPTION((std::string("Failed to dump memory to file at ") + this->dumppath.string()).c_str());
    }
}

void MemoryPage::UnSwap() const
{
    using enum MemoryPage::DumpException::Type;

    switch (this->mode) {
    case None:
        throw DumpException(NonCommit, __FILE__, __LINE__, this->addr);
        return;
    case Disk:
        break;
    case Memory:
        throw DumpException(NotSwapped, __FILE__, __LINE__, this->addr);
        return;
    case Initial:
        throw DumpException(NotDumped, __FILE__, __LINE__, this->addr);
    default:
        throw DumpException(InvalidMode, __FILE__, __LINE__, this->mode);
        return;
    }

    try {
        if (this->buffer) throw BHNORMEXCEPTION("Potential Memory leak detected.");
        this->buffer = std::make_unique<byte[]>(this->size);
        if (!this->buffer) throw BHNORMEXCEPTION("Not enough RAM.");
        dumpfile.open(this->dumppath, std::ios::in | std::ios::binary);
        dumpfile.read(reinterpret_cast<char*>(this->buffer.get()), this->size);
        dumpfile.close();
        fs::remove(this->dumppath);
    }
    catch (std::ios::failure& e) {
        SetLastError(e.code().value());
        throw BHWINEXCEPTION((std::string("Failed to dump memory to file at ") + this->dumppath.string()).c_str());
    }
    catch (fs::filesystem_error& e) {
        SetLastError(e.code().value());
        throw BHWINEXCEPTION((std::string("Failed to delete dump file ") + this->dumppath.string()).c_str());
    }

}

void MemoryPage::Dump() const
{
    using enum MemoryPage::DumpException::Type;
    if (this->mode == None) throw DumpException(NonCommit, __FILE__, __LINE__, this->addr);
    if (this->mode != Initial) throw DumpException(Unexpected, __FILE__, __LINE__, reinterpret_cast<uintptr_t>((std::stringstream("Tried to dump the address 0x") << std::hex << this->addr << " twice.").str().c_str()));
    this->buffer = std::make_unique<byte[]>(this->size);
    if (!this->buffer) throw BHNORMEXCEPTION("Not enough RAM.");
    this->mode = Memory;
    if (!this->proc) throw BHNORMEXCEPTION("Process in this memory page is invalid.");
    this->proc->ReadProcessMemory(this->addr, this->size, this->buffer.get());
}

void MemoryPage::Pull(OUT byte* out, IN size_t size) const
{
    using enum MemoryPage::DumpException::Type;

    if (size < this->size) throw BHNORMEXCEPTION("The buffer to receive page data is too small.");

    switch (this->mode) {
    case None:
        throw DumpException(NonCommit, __FILE__, __LINE__, this->addr);
        return;
    case Initial:
        this->Dump();
        break;
    case Disk:
        this->UnSwap();
        // DO NOT ADD BREAK AT THIS LINE.
        // LET IT OVERFLOW.
    case Memory:
        memcpy_s(out, size, reinterpret_cast<const void* const>(this->addr), this->size);
        break;
    default:
        throw DumpException(InvalidMode, __FILE__, __LINE__, this->mode);
        return;
    }
    
}

MemoryPage::MemoryPage(std::shared_ptr<Process> proc, uintptr_t address) : proc(proc)
{
    using enum MemRegionType;

    MEMORY_BASIC_INFORMATION mbi = proc->VirtualQuery(address);
    this->procName = proc->GetProcName();
	this->addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
	this->allocBaseAddr = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
	this->size = mbi.RegionSize;
    this->state = mbi.State;
    this->mode = None;
    this->dumpfile.exceptions(std::ios::eofbit | std::ios::failbit);

    switch (mbi.Type)
    {
    case MEM_IMAGE:
        this->type = Image;
        break;
    case MEM_MAPPED:
        this->type = Mapped;
        break;
    case MEM_PRIVATE:
        this->type = Private;
        break;
    default:
        this->type = Others;
        break;
    }
    this->perm = mbi.Protect;
    
    this->buffer = nullptr;
    if (this->state & MEM_COMMIT) {
        this->mode = Initial;
    }
}

MemoryPage::MemoryPage(const MemoryPage& src) : proc(src.GetProcess())
{
    char fileName[MAX_PATH];
    fs::path tempPath = std::filesystem::temp_directory_path();

    this->type = src.GetType();
    this->addr = src.GetBaseAddr();
    this->allocBaseAddr = src.GetAllocBase();
    this->perm = src.GetProtection();
    this->info = src.GetInfo();
    this->procName = src.GetProcName();
    this->size = src.GetSize();
    this->state = src.GetState();
    this->buffer = nullptr;
    switch (src.GetDumpMode()) {
    case Memory:
        this->buffer = std::make_unique<byte[]>(this->size);
        if (!this->buffer) throw BHNORMEXCEPTION("Not enough RAM.");
        src.Pull(this->buffer.get(), this->size);
        this->mode = Memory;
        break;
    case Disk:
        if (sprintf_s(fileName, "%s_0x%p_%x.dump", this->procName.c_str(), reinterpret_cast<LPVOID>(this->addr), rand()) == -1) throw BHNORMEXCEPTION("Dump Path initalization failed.");
        tempPath.append(fileName);
        this->dumppath = tempPath;
        fs::copy_file(src.dumppath, tempPath);
        this->mode = Disk;
        break;
    case Initial:
    case None:
        this->mode = src.GetDumpMode();
        break;
    }
}

MemoryPage::MemoryPage() noexcept
{
    this->type = Invalid;
    this->proc = nullptr;
    state = 0;
    perm = 0;
    addr = 0;
    allocBaseAddr = 0;
    size = 0;
    info = "THIS INFORMATION SHOULD NOT BE DISPLAYED.";
    procName = "INVALID PROCESS.";
    mode = None;
    dumppath = "/dev/null";
    buffer = nullptr;
}



MemoryPage::~MemoryPage()
{
    try {
        switch (this->mode) {
        case Disk:
            fs::remove(this->dumppath);
            break;
        case Memory:
            this->buffer.reset();
            this->buffer = nullptr;
            break;
        default:
            break;
        }
    }
    catch (fs::filesystem_error& e) {
        SetLastError(e.code().value());
        BHWINEXCEPTION((std::string("Failed to delete dump file ") + this->dumppath.string()).c_str()).Alert(); // Alert to delete the dump file manually.
    }
}

MemoryPage::DumpException::DumpException(Type type, const char* file, unsigned int line, uintptr_t msg) : bhException(file, line, reinterpret_cast<const char*>(msg))
{
    this->err = type;
    switch (type) {
    case NonCommit:
        this->SetMsg(((std::stringstream)"Trying to dump non-commit memory 0x" << std::hex << msg).str());
        break;
    case AlreadySwapped:
        this->SetMsg(((std::stringstream)"The memory region 0x" << std::hex << msg << "has already been swapped into disk.").str());
        break;
    case NotSwapped:
        this->SetMsg(((std::stringstream)"The memory region 0x" << std::hex << msg << "has not swapped into disk.").str());
        break;
    case NotDumped:
        this->SetMsg(((std::stringstream)"The memory region 0x" << std::hex << msg << "has not been dumped.").str());
        break;
    case InvalidMode:
        this->SetMsg(((std::stringstream)"The dump mode " << msg << " is invalid.").str());
        break;
    case Unexpected:
    default:
        break;
    }
}
