/*
	Author: HouSD
	Date: 2013/02/27

	This is x86 32 and 64 bits Windows NT architectures operation system inline hook library.
	The library is THREAD SAFE and REENTERABLE.
	CAUTION: Not all APIs with jump or call instructions as its first few instructions is supported. Fortunately, all windows APIs were designed to support inline hook.
	The following SDKs are required before using this library:
		1 boost
		2 dynamoRIO

	Take the following steps to set up the required SDK.
		1 Copy the source code folder of boost to the project's default search paths. It's recommended to copy the boost directory to $(VCInstallPath)\include.
		2 Do it the same way to the dynamoRIO SDK.
		3 Run the console, set the current path to boost, then compile the boost library through "bjam --toolset=msvc-10.0 address-model=32 --build-type=complete".
		  The msvc-10.0 should be set consistent with the VC version. For example, replace it with msvc-9.0 if the current VC version is 2008.
		4 Copy the librarys from boost/stage/lib to the VC/lib folder.
		5 Do the same thing as step 3, 4 with the address-model set to 64. In step 4, copy the boost/stage/lib to VC/lib/amd64.
		6 Copy the drdecode.lib from DynamoRIO/lib32/release and DynamoRIO/lib64/release to VC/lib and VC/lib/amd64 relatively.

	Ensure the the size of function (including the following gap) you are going to hook is more than 5 bytes in Win32 or 14 bytes in x64. Since all windows APIs
	are aligned to 32 bytes so it will be no problem to hook them. If the api is from third party, it should be taken into consideration.

	The following example illustrates how to hook an arbitrary function.

	#include "hookapi.hpp"
	#include <windows.h>

	HINSTANCE MyLoadLibrary(LPCTSTR path)
	{
		//The first brackets embrace the whose origin function to be called.
		//The second brackets embrace the parameters.
		//The return type of call_origin is consistent with what of the origin function.
		return hookapi::call_origin(LoadLibrary)(path);

		//Also, you can call hookapi::call_origin_by_hook(MyLoadLibrary)(path) if the origin api is not easy to get.
		//But if you've known the origin api, calling the call_origin gains better performance.
	}

	void main()
	{
		//The first function is to be hooked.
		//The second function is the hijacked function.
		hookapi::hook(LoadLibrary, MyLoadLibrary);
	}

	Do not need to call hookapi::unhook(LoadLibrary) manually, the unhook procedure will be done when the progress is exiting. Of cause, you can unhook anywhere.
	If the target api has not been hooked, nothing will happen.
*/
#pragma once

#include <map>
#include <math.h>
#include <string>
#include <tuple>
#include <memory>
#include <Windows.h>
//#ifdef _DEBUG
//#pragma comment(linker, "/nodefaultlib:libcmt.lib")
//#endif // !DEBUG
#pragma comment(lib, "dynamorio.lib")
#define	WINDOWS
#ifdef _WIN64
#define	X86_64
#define	MIN_HOOK_SIZE	8
#else
#define	X86_32
#define	MIN_HOOK_SIZE	5
#endif // _WIN64

#include "DynamoRIO/include/dr_api.h"

namespace hookapi
{
	class hookutility
	{
	public:
		hookutility(PVOID api, PVOID detour)
		{
			initialize(api, detour);
		}
		~hookutility()
		{
			release();
		}
		PVOID get_origin()
		{
			return m_origin;
		}
		PVOID get_detour() { return m_detour; }
	private:
		void initialize(PVOID api, PVOID detour)
		{
			size_t hook_size = MIN_HOOK_SIZE;

			m_api = reinterpret_cast<byte*>(api);
			m_detour = reinterpret_cast<byte*>(detour);

			auto offset = int64_t(m_detour[56]) - int64_t(m_api);
			if (INT32_MIN > offset || INT32_MAX < offset) hook_size = 14;

			m_saved_size = 0;
			while (hook_size > m_saved_size) m_saved_size += decode_sizeof(nullptr, &m_api[m_saved_size], nullptr _IF_X64(nullptr));

			//	m_origin = (byte*)VirtualAlloc(nullptr, MIN_HOOK_SIZE + 8, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			DWORD old_protect;
			VirtualProtect(m_origin, sizeof(m_origin), PAGE_EXECUTE_READWRITE, &old_protect);

			if (0xEB == m_api[0])	//the first instruction of the origin api is jmp short [byte], it takes two bytes.
			{
				make_jump(m_origin, m_api + 2 + m_api[1], &m_origin[8]);					//the origin simply jump to where the origin api would jump to.
			}
			else if (0xE9 == m_api[0])	//long jump
			{
				make_jump(m_origin, m_api + 5 + *reinterpret_cast<uint32_t*>(m_api + 1), &m_origin[48]);
			}
#ifdef _WIN64
			else if (0x48 == m_api[0] && 0x25FF == *reinterpret_cast<WORD*>(&m_api[1]))
			{
				auto jump_to = *reinterpret_cast<size_t*>(m_api + 7 + *reinterpret_cast<uint32_t*>(&m_api[3]));
				make_jump(m_origin, reinterpret_cast<PVOID>(jump_to), &m_origin[8]);
			}
#endif // _WIN64
			else
			{
				memcpy(m_origin, m_api, m_saved_size);										//origin->Execute the first several instructions of the origin api
				make_jump(&m_origin[m_saved_size], &m_api[m_saved_size], &m_origin[48]);	//then jump to the following instruction of the origin api
			}

			VirtualProtect(m_api, m_saved_size, PAGE_EXECUTE_READWRITE, &old_protect);
			make_jump(m_api, m_detour, &m_origin[56]);						//the patched api instructions will jump to the detour api.
			VirtualProtect(m_api, m_saved_size, old_protect, &old_protect);
		}
		void make_jump(PVOID from, PVOID to, PVOID x64_address_holder)
		{
			auto pb_from = reinterpret_cast<unsigned char*>(from);
			auto pb_to = reinterpret_cast<unsigned char*>(to);
#ifndef _WIN64
			pb_from[0] = 0xE9;
			*reinterpret_cast<DWORD*>(&pb_from[1]) = pb_to - pb_from - MIN_HOOK_SIZE;
#else
			int64_t offset = (int64_t)(reinterpret_cast<unsigned char*>(x64_address_holder) - pb_from - 6);
			if (INT32_MIN <= offset && INT32_MAX >= offset)
			{
				*reinterpret_cast<WORD*>(pb_from) = 0x25FF;
				*reinterpret_cast<ULONG32*>(&pb_from[2]) = (ULONG32)offset;
				*reinterpret_cast<ULONG64*>(x64_address_holder) = ULONG64(to);
			}
			else
			{
				*reinterpret_cast<WORD*>(pb_from) = 0x25FF;
				*reinterpret_cast<ULONG32*>(&pb_from[2]) = 0;
				*reinterpret_cast<ULONG64*>(&pb_from[6]) = ULONG64(to);
			}
#endif // _WIN64
		}
		void release()
		{
			DWORD old_protect;
			VirtualProtect(m_api, m_saved_size, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(m_api, m_origin, m_saved_size);
			VirtualProtect(m_api, m_saved_size, old_protect, &old_protect);
			//	VirtualFree(m_origin, MIN_HOOK_SIZE + 8, MEM_FREE);
		}
	private:
		byte* m_api;
		byte* m_detour;
		byte m_origin[64];
		size_t m_saved_size;
	};

	typedef std::map<PVOID, std::shared_ptr<hookutility>> HookMap;
	inline HookMap* hookmap()
	{
		//For performance reason, use p_context to cache to environment value.
	//	static context_imply* p_context = nullptr;
	//	if(nullptr != p_context) return *p_context;
		static HookMap* p_hookmap = nullptr;

		if (nullptr != p_hookmap) return p_hookmap;
		//Define the environment value to hold the address of the context in text form, since the environment value can only be text.
		wchar_t env[64];
		std::wstring key = L"46EBBDC3-EEDC-42D4-BA1D-D454DFCE8E42:";	//The context guid, in order to distinguish with other keys.
		key += std::to_wstring(GetCurrentProcessId());
		if (GetEnvironmentVariableW(key.c_str(), env, _countof(env)))
		{
			//If SetEnvironmentVariable has been called, this branch must be achieved.
			//Then decode the context from env string.
			p_hookmap = (HookMap*)_wtoi64(env);
			return p_hookmap;
		}

		//Define the local static context to hold the process context, which is immediately registered to the environment value.
		//static context_imply s_context;
		static HookMap instance;
		p_hookmap = &instance;
		_i64tow_s((size_t)p_hookmap, env, _countof(env), 10);
		SetEnvironmentVariableW(key.c_str(), env);
		return p_hookmap;
	}
	//#define	hookapi_guid	L"A6A0B36E-FC50-4FF2-8AC9-4538F0AC7C9C"
	//#define	hookmap	runtime_context::process::create_or_get_ptr<HookMap>(hookapi_guid)
	template<typename F>
	inline void hook(F api, F shell)//eg. hook(Sleep, MySleep);
	{
		//	ProcessCriticalSection(hookapi_guid);
		(*hookmap())[api] = std::make_shared<hookutility>(api, shell);
	}
	template<typename TShell>
	inline void hook_unsafe(PVOID api, TShell shell)
	{
		hook(api, *(void**)&shell);
	}
	inline void unhook(PVOID api)//eg. unhook(sleep);
	{
		//	ProcessCriticalSection(hookapi_guid);
		hookmap()->erase(api);
	}
	template<typename F>
	inline F call_origin(F api)//eg. call_origin(Sleep)(1000);
	{
		//	ProcessCriticalSection(hookapi_guid);
		auto hook = (*hookmap())[api];
		if (nullptr == hook) return api;
		else return (F)hook->get_origin();
	}
	template<typename F>
	inline F call_origin_by_hook(F shell)
	{
		//	ProcessCriticalSection(hookapi_guid);
		for (auto k = hookmap()->begin(); hookmap()->end() != k; ++k)
		{
			if (k->second->get_detour() == *(PVOID*)&shell) {
				auto api = k->second->get_origin();
				return *reinterpret_cast<F*>(&api);
			}
		}
		return shell;
	}
	inline bool is_hooked(void* api)
	{
		//	ProcessCriticalSection(hookapi_guid);
		return hookmap()->find(api) != hookmap()->end();
	}
	//#undef	hookmap
}