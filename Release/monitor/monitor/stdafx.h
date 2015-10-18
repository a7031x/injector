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
#include <custom/hookapi.hpp>
#include <Shlwapi.h>
#include <ShlObj.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
using namespace std;
using namespace std::tr2::sys;
#include <boost/algorithm/string.hpp>
#include <NTSecAPI.h>
#include <custom/debugutility.hpp>

// TODO: reference additional headers your program requires here
