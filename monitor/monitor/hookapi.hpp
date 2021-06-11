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
#define	MIN_HOOK_SIZE	14
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
			m_api = reinterpret_cast<byte*>(api);
			m_detour = reinterpret_cast<byte*>(detour);
			m_saved_size = 0;
			while (MIN_HOOK_SIZE > m_saved_size) m_saved_size += decode_sizeof(nullptr, &m_api[m_saved_size], nullptr _IF_X64(nullptr));

			//	m_origin = (byte*)VirtualAlloc(nullptr, MIN_HOOK_SIZE + 8, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			DWORD old_protect;
			VirtualProtect(m_origin, sizeof(m_origin), PAGE_EXECUTE_READWRITE, &old_protect);

			transfer_code(m_api, m_origin, m_saved_size);
			//memcpy(m_origin, m_api, m_saved_size);										//origin->Execute the first several instructions of the origin api
			//fix_relative(m_api, m_origin, m_saved_size);
			//make_jump(&m_origin[m_saved_size], &m_api[m_saved_size], m_address_holder0);	//then jump to the following instruction of the origin api
			std::copy(m_api, m_api + m_saved_size, m_saved);								//saving bytes for recovery.
			VirtualProtect(m_api, m_saved_size, PAGE_EXECUTE_READWRITE, &old_protect);
			make_smart_jump(m_api, m_detour);														//the patched api instructions will jump to the detour api.
			VirtualProtect(m_api, m_saved_size, old_protect, &old_protect);
		}
		void make_smart_jump(byte* source, byte* target) {
			size_t function_size = compute_function_size_with_padding(source, MIN_HOOK_SIZE);
			if (MIN_HOOK_SIZE <= function_size)
				make_jump(source, target);
			else {
				if (function_size < 2) throw std::exception("function size is too small to hook.");
				auto gap = seek_for_padding_code(source - 128 + 2, MIN_HOOK_SIZE, 255);
				if (nullptr == gap) throw std::exception("cannot find code gap nearby.");
				patch_bytes(source, (byte)0xEB, byte(gap - source - 2));
				make_jump(gap, target);
			}
		}
		template<typename T, typename Head, typename... Tails>
		size_t patch_bytes(T address, Head head, Tails... tails) {
			*reinterpret_cast<Head*>(address) = head;
			return sizeof(Head) + patch_bytes((size_t)address + sizeof(Head), tails...);
		}
		template<typename T> size_t patch_bytes(T address) { return 0; }

		template<typename T, typename Head, typename... Tails>
		bool match_bytes(T address, Head head, Tails... tails) {
			if (*reinterpret_cast<Head*>(address) != head) return false;
			else return match_bytes((size_t)address + sizeof(Head), tails...);
		}
		template<typename T> bool match_bytes(T address) { return true; }
		size_t compute_function_size(byte* address, size_t max_size = INT_MAX) {
			size_t size = 0;
			while (size < max_size) {
				auto instruction_size = decode_sizeof(nullptr, &address[size], nullptr _IF_X64(nullptr));
				if (0xCC == address[size] && 1 == instruction_size) break;
				size += instruction_size;
			}
			return size;
		}
		size_t compute_function_size_with_padding(byte* address, size_t max_size = INT_MAX) {
			size_t size = compute_function_size(address, max_size);
			if (size < max_size) {
				while (address[size] == 0xCC && size < max_size) ++size;
			}
			return size;
		}
		byte* seek_for_padding_code(byte* address, size_t gap_size, int max_offset=INT_MAX) {
			for (byte* current = address; current < address + max_offset;) {
				auto function_size = compute_function_size(current);
				current += function_size;
				auto next_address = std::find_if(current, current + gap_size, [](byte x)->bool {return x != 0xCC; });
				if (current + gap_size == next_address) return current;
				else current = next_address;
			}
			return nullptr;
		}
		void transfer_code(byte* api, byte* origin, size_t size) {
			size_t origin_offset = 0;
			for (size_t api_offset = 0; api_offset < size;) {
				auto instruction_size = decode_sizeof(nullptr, &api[api_offset], nullptr _IF_X64(nullptr));
				auto origin_size = fix_relative_instruction(&api[api_offset], &origin[origin_offset], instruction_size);
				api_offset += instruction_size;
				origin_offset += origin_size;
			}
			make_jump(&origin[origin_offset], &api[size]);
		}
		size_t fix_relative_instruction(byte* source, byte* target, size_t instruction_size) {
			if (match_bytes(source, (byte)0xEB))	//the first instruction of the origin api is jmp short [byte], it takes two bytes.
			{
				return make_jump(target, source + 2 + source[1]);					//the origin simply jump to where the origin api would jump to.
			}
			else if (match_bytes(source, (byte)0xE9))	//long jump
			{
				return make_jump(target, source + 5 + *reinterpret_cast<uint32_t*>(source + 1));
			}
#ifdef _WIN64
			else if (match_bytes(source, (byte)0x48, (uint16_t)0x25FF))
			{
				auto refer_to = (uint64_t)source + 7 + *reinterpret_cast<uint32_t*>(&source[3]);
				auto jump_to = *reinterpret_cast<uint64_t*>(refer_to);
				return make_jump(target, reinterpret_cast<PVOID>(jump_to));
			}
			else if (match_bytes(source, (byte)0x48, (uint16_t)0x058B))
			{
				auto refer_to = (uint64_t)source + 7 + *reinterpret_cast<uint32_t*>(&source[3]);
				return patch_bytes(target, (byte)0x48, (byte)0xA1, (uint64_t)refer_to);
			}
#endif // _WIN64
			else {
				std::copy(source, source + instruction_size, target);
				return instruction_size;
			}
		}

		size_t make_jump(PVOID from, PVOID to)
		{
			auto pb_from = reinterpret_cast<unsigned char*>(from);
			auto pb_to = reinterpret_cast<unsigned char*>(to);
#ifndef _WIN64
			return patch_bytes(from, (byte)0xE9, (uint32_t)to - (uint32_t)from - 5);
#else
			return patch_bytes(from, (uint16_t)0x25FF, (uint32_t)0, (uint64_t)to);
#endif // _WIN64
		}
		void release()
		{
			DWORD old_protect;
			VirtualProtect(m_api, m_saved_size, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(m_api, m_saved, m_saved_size);
			VirtualProtect(m_api, m_saved_size, old_protect, &old_protect);
			//	VirtualFree(m_origin, MIN_HOOK_SIZE + 8, MEM_FREE);
		}
	private:
		byte* m_api;
		byte* m_detour;
		byte m_origin[128];
		byte m_saved[64];
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