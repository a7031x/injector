// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"


void beginPatch(const path& folder, char* base);

typedef struct _OBJECT_ATTRIBUTES {
   ULONG           Length;
   HANDLE          RootDirectory;
   PUNICODE_STRING ObjectName;
   ULONG           Attributes;
   PVOID           SecurityDescriptor;
   PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

LONG WINAPI MyCreateFile(
	PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PVOID IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	wchar_t p[MAX_PATH];
	wcscpy_s(p, ObjectAttributes->ObjectName->Buffer);
	PathRemoveExtensionW(p);
	PathAddExtensionW(p, L".org");
	wcscat_s(p, PathFindExtensionW(ObjectAttributes->ObjectName->Buffer));
	UNICODE_STRING oldString = *ObjectAttributes->ObjectName;
	if(exists(path(p + 4)))
	{
		ObjectAttributes->ObjectName->Buffer = p;
		ObjectAttributes->ObjectName->Length += 8;
		ObjectAttributes->ObjectName->MaximumLength += 8;
	}
	od(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, ObjectAttributes->ObjectName->MaximumLength);
	auto result = hookapi::call_origin_by_hook(MyCreateFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
		ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	*ObjectAttributes->ObjectName = oldString;
	od(result);
	return result;
}

void bypassSelfVerification()
{
	auto api3 = GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateFile");
	hookapi::hook_unsafe(api3, MyCreateFile);
}


HRESULT WINAPI MyGetFolderPathA(__reserved HWND hwnd, __in int csidl, __in_opt HANDLE hToken, __in DWORD dwFlags, __out_ecount(MAX_PATH) LPSTR pszPath)
{
	GetModuleFileNameA(nullptr, pszPath, MAX_PATH);
	PathRemoveFileSpecA(pszPath);
	return 0;
}

HRESULT WINAPI MyGetFolderPathW(__reserved HWND hwnd, __in int csidl, __in_opt HANDLE hToken, __in DWORD dwFlags, __out_ecount(MAX_PATH) LPWSTR pszPath)
{
	GetModuleFileNameW(nullptr, pszPath, MAX_PATH);
	PathRemoveFileSpecW(pszPath);
	return 0;
}

BOOL WINAPI MyGetSpecialFolderPathA(__reserved HWND hwnd, __out_ecount(MAX_PATH) LPSTR pszPath, __in int csidl, __in BOOL fCreate)
{
	GetModuleFileNameA(nullptr, pszPath, MAX_PATH);
	PathRemoveFileSpecA(pszPath);
	return TRUE;
}

BOOL WINAPI MyGetSpecialFolderPathW(__reserved HWND hwnd, __out_ecount(MAX_PATH) LPWSTR pszPath, __in int csidl, __in BOOL fCreate)
{
	GetModuleFileNameW(nullptr, pszPath, MAX_PATH);
	PathRemoveFileSpecW(pszPath);
	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		bypassSelfVerification();
		{
			wchar_t path[MAX_PATH];
			GetModuleFileNameW(nullptr, path, _countof(path));
			PathRemoveFileSpecW(path);
			auto base = reinterpret_cast<char*>(GetModuleHandleW(nullptr));
			auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
			auto ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
			hookapi::hook(SHGetFolderPathA, MyGetFolderPathA);
			hookapi::hook(SHGetFolderPathW, MyGetFolderPathW);
			hookapi::hook(SHGetSpecialFolderPathA, MyGetSpecialFolderPathA);
			hookapi::hook(SHGetSpecialFolderPathW, MyGetSpecialFolderPathW);
			DWORD oldProtection;
			VirtualProtect(base + ntHeader->OptionalHeader.BaseOfCode,
				ntHeader->OptionalHeader.SizeOfImage - ntHeader->OptionalHeader.BaseOfCode, PAGE_EXECUTE_READWRITE, &oldProtection);
			beginPatch(path, base);
		//	VirtualProtect(base + ntHeader->OptionalHeader.BaseOfCode,
		//		ntHeader->OptionalHeader.SizeOfImage - ntHeader->OptionalHeader.BaseOfCode, oldProtection, &oldProtection);
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

