#include "bhexception.h"

bhException::bhException(const char* file, unsigned int line, std::string msg) noexcept
{
    this->file = file;
    this->line = line;
    this->msg = msg;
}

std::string bhException::GetFile() const noexcept { return this->file; }
unsigned int bhException::GetLine() const noexcept { return this->line; }
std::string bhException::GetMsg() const noexcept { return this->msg; }

void bhException::SetMsg(std::string msg) noexcept
{
	this->msg = msg;
}

const char* bhException::what() const noexcept
{
    if (whatMsg.empty()) {
        std::stringstream ostr;
        ostr << "[File] " << this->file << std::endl 
            << "[Line] " << this->line << std::endl 
            << "[Description] " << this->msg << std::endl;
        whatMsg = ostr.str();
    }
    return whatMsg.c_str();
}

void bhException::Alert() const noexcept
{
    MessageBoxA(NULL, this->what(), "Error", MB_OK | MB_ICONERROR);
}

bhWinException::bhWinException(const char* file, unsigned int line, std::string msg) noexcept : bhException(file, line, msg)
{
    errorCode = GetLastError();
	char* pMsgBuf = nullptr;
	// windows will allocate memory for err string and make our pointer point to it
	const DWORD nMsgLen = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, this->errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPSTR>(&pMsgBuf), 0, nullptr
	);
	// 0 string length returned indicates a failure
	if (nMsgLen == 0)
	{
		winErrMsg = "Windows cannot identifie the error code.";
	}
	else {
		// copy error string from windows-allocated buffer to std::string
		winErrMsg = pMsgBuf;
		// free windows buffer
		LocalFree(pMsgBuf);
	}
}

const char* bhWinException::what() const noexcept
{
	if (whatMsg.empty()) {
		std::stringstream ostr;
		ostr << "[File] " << this->GetFile() << std::endl
			<< "[Line] " << this->GetLine() << std::endl
			<< "[Description] " << this->GetMsg() << std::endl
			<< "[Error Code]" << this->errorCode << std::endl
			<< "[Windows Error Description]" << std::endl
			<< this->winErrMsg << std::endl;
		whatMsg = ostr.str();
	}
	return whatMsg.c_str();
}
