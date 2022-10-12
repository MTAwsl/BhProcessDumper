#pragma once
#include <string>
#include <exception>
#include <sstream>
#include <windows.h>
#define BHNORMEXCEPTION(msg) bhException(__FILE__, __LINE__, msg)
#define BHWINEXCEPTION(msg) bhWinException(__FILE__, __LINE__, msg)

class bhException : public std::exception {
public:
	bhException(const char* file, unsigned int line, std::string msg) noexcept;
	std::string GetFile() const noexcept;
	unsigned int GetLine() const noexcept;
	std::string GetMsg() const noexcept;
	void SetMsg(std::string msg) noexcept;
	virtual const char* what() const noexcept override;
	virtual void Alert() const noexcept;
private:
	std::string file;
	unsigned int line;
	std::string msg;
protected:
	mutable std::string whatMsg;
};

class bhWinException : public bhException {
public:
	bhWinException(const char* file, unsigned int line, std::string msg) noexcept;
	virtual const char* what() const noexcept override;
private:
	DWORD errorCode;
	std::string winErrMsg;
};