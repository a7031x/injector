// monitor.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
void __stdcall MySleep(DWORD ms)
{
	MessageBoxA(nullptr, "sleep", "sleep", MB_OK);
}

void beginPatch(const std::filesystem::path& folder, char* base)
{
	hookapi::hook(Sleep, MySleep);
}