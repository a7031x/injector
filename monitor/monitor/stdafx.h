// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <filesystem>
#include "hookapi.hpp"
#include <Shlwapi.h>
#include <ShlObj.h>
#include <sstream>
#include <fstream>
#include <string>
#include <set>
#include <mutex>
#include "utils.hpp"
#include "mono.h"
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

static std::wofstream& ofs() {
	static std::wofstream _ofs(L"od.txt");
	return _ofs;
}

static std::mutex& mtx() {
	static std::mutex _mtx;
	return _mtx;
}

using namespace std;
#include <NTSecAPI.h>
#define DR_DO_NOT_DEFINE_byte
// TODO: reference additional headers your program requires here
template<typename head_t, typename... args_t>
inline std::wstring format(const head_t& head, const args_t&... args) {
	return format(head) + L" " + format(args...);
}

template<typename head_t>
inline std::wstring format(const head_t& head) {
	std::wstringstream ss;
	std::wstring text;
	ss << std::hex << head;
	ss >> text;
	return text;
}

template<>
inline std::wstring format<std::string>(const std::string& head) {
	return std::wstring(head.begin(), head.end());
}

template<>
inline std::wstring format<std::wstring>(const std::wstring& head) {
	return head;
}

template<typename... args_t>
inline void od(const args_t&... args) {
	std::wstring text = format(args...);
	text += L"\r\n";
	std::unique_lock lock(mtx());
	ofs() << text << std::flush;
	OutputDebugStringW((TEXT("FATE:") + text).c_str());
}

inline void replace_inline(std::string& str,
	const std::string& oldStr,
	const std::string& newStr)
{
	std::string::size_type pos = 0u;
	while ((pos = str.find(oldStr, pos)) != std::string::npos) {
		str.replace(pos, oldStr.length(), newStr);
		pos += newStr.length();
	}
}
