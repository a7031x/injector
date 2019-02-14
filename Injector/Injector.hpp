#pragma once
#include <Windows.h>
#include "fileutils.hpp"
#include <filesystem>
#include <ImageHlp.h>
#pragma comment(lib,"Imagehlp.lib")
using namespace std::filesystem;

inline bool ansiequal(const char* p1, const char* p2)
{
	while(*p1 || *p2)
	{
		if(*p1 != *p2) return false;
		++p1;
		++p2;
	}
	return true;
}

class Injector
{
private:
	struct Extention
	{
		uint32_t	OEP;
		uint32_t	extentionBase;
		uint32_t	extentionSize;
		uint32_t	imageExtentionBase;
		uint32_t	virtualExtentionSize;
		int32_t		sectionVirtualOffset;
		std::vector<std::pair<uint32_t, uint32_t>> recovery;
	};
public:
	static bool inject(const path& p, const std::string& monitorName)
	{
		auto file = fileutils::readfile(p);
		if(0x400 > file.size()) return false;
		auto base = file.data();
		auto ext = extendCodeSection(base);
		file.resize(file.size() + ext.extentionSize);
		base = file.data();
		writeShell(base, ext, monitorName);
		DWORD headerSum, checkSum;
		CheckSumMappedFile(file.data(), file.size(), &headerSum, &checkSum);
		auto nt = ntHeader(base);
		nt->OptionalHeader.CheckSum = headerSum;
		auto orgPath = p;
		orgPath.replace_extension(".org" + orgPath.extension().string());
		copy_file(p, orgPath, copy_options::overwrite_existing);
		fileutils::writefile(p.string(), file);
		return true;
	}
private:
	static IMAGE_NT_HEADERS* ntHeader(char* base)
	{
		auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		return reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
	}
	static IMAGE_SECTION_HEADER* lastSection(char* base)
	{
		auto nt = ntHeader(base);
		auto sectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt + 1);
		auto it = std::max_element(sectionHeader, &sectionHeader[nt->FileHeader.NumberOfSections],
			[](const IMAGE_SECTION_HEADER& h1, const IMAGE_SECTION_HEADER& h2)
			{
				return h1.PointerToRawData < h2.PointerToRawData;
			});
		return it;
	}
	static IMAGE_DATA_DIRECTORY* sectionDirectory(char* base, IMAGE_SECTION_HEADER* section)
	{
		auto nt = ntHeader(base);
		for(int k = 0; k < 16; ++k)
		{
			if(nt->OptionalHeader.DataDirectory[k].VirtualAddress == section->VirtualAddress)
				return &nt->OptionalHeader.DataDirectory[k];
		}
		return nullptr;
	}
	static IMAGE_SECTION_HEADER* findSection(char* base, uint32_t virtualAddress)
	{
		auto nt = ntHeader(base);
		auto sectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt + 1);
		auto it = std::find_if(sectionHeader, &sectionHeader[nt->FileHeader.NumberOfSections],
			[virtualAddress](const IMAGE_SECTION_HEADER& section)
			{
				return virtualAddress >= section.VirtualAddress
					&& virtualAddress < section.VirtualAddress + section.SizeOfRawData;
			});
		return it;
	}
	static Extention extendCodeSection(char* base)
	{
		auto section = lastSection(base);
		uint32_t virtualExtention = 0x1000;
		uint32_t extentSize = max(0, virtualExtention + section->Misc.VirtualSize - section->SizeOfRawData);
		auto nt = ntHeader(base);
		Extention ext;
		ext.OEP = nt->OptionalHeader.AddressOfEntryPoint;
		ext.extentionSize = extentSize;
		ext.virtualExtentionSize = virtualExtention;
		ext.imageExtentionBase = nt->OptionalHeader.ImageBase + nt->OptionalHeader.SizeOfImage;
		ext.extentionBase = section->PointerToRawData + section->Misc.VirtualSize;
	//	ext.sectionVirtualOffset = max(int32_t(section->SizeOfRawData - section->Misc.VirtualSize), 0);
		ext.sectionVirtualOffset = section->Misc.VirtualSize + section->VirtualAddress;
		auto pushRecovery = [base, &ext](const void* address)
		{
			auto offset = uint32_t(reinterpret_cast<const char*>(address) - base);
			ext.recovery.push_back(std::pair<uint32_t, uint32_t>(offset, *reinterpret_cast<const uint32_t*>(address)));
		};
		auto directory = sectionDirectory(base, section);
		if(nullptr != directory)
		{
			pushRecovery(&directory->Size);
			directory->Size += ext.virtualExtentionSize;
		}
		pushRecovery(&nt->OptionalHeader.AddressOfEntryPoint);
		pushRecovery(&section->SizeOfRawData);
		pushRecovery(&section->Misc.VirtualSize);
		pushRecovery(&nt->OptionalHeader.SizeOfImage);
		pushRecovery(&section->Characteristics);
		section->SizeOfRawData += ext.extentionSize;
		section->Misc.VirtualSize += ext.virtualExtentionSize;
		nt->OptionalHeader.SizeOfImage += ext.virtualExtentionSize;
		section->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
		return ext;
	}
	static uint32_t idataItem(char* base, const char* name)
	{
		auto nt = ntHeader(base);
		auto iat = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto section = findSection(base, iat->VirtualAddress);
	//	auto rdata = sectionDirectory(base, section);	//iat is part of rdata
		auto virtualToRawOffset = int(section->PointerToRawData - section->VirtualAddress);
		auto offset = iat->VirtualAddress + virtualToRawOffset;
		auto importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(&base[offset]);
		while(importDescriptor->TimeDateStamp || importDescriptor->FirstThunk || importDescriptor->Name || importDescriptor->OriginalFirstThunk || importDescriptor->ForwarderChain)
		{
			auto api_offset = importDescriptor->FirstThunk;
			offset = (importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : api_offset) + virtualToRawOffset;
			auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(&base[offset]);
			const size_t HIGHEST_MARK = size_t(1) << (sizeof(size_t) * 8 - 1);
			while(0 != thunk->u1.AddressOfData)
			{
				if(0 == (thunk->u1.AddressOfData & HIGHEST_MARK))
				{
					auto api = reinterpret_cast<char*>(&base[thunk->u1.ForwarderString + virtualToRawOffset]) + sizeof(WORD);
					if(ansiequal(api, name))
						return api_offset + nt->OptionalHeader.ImageBase;
				}
				++thunk;
				api_offset += sizeof(size_t);
			}

			++importDescriptor;
		}
		return 0;
	}
	static void x64prefix(char*& shellBase)
	{
		x64code(shellBase, 0x48);
	}
	static void x64csprefix(char*& shellBase)
	{
		x64code(shellBase, 0x2E);
	}
	class stack_frame_t {
		char*& _shell;
	public:
		stack_frame_t(char*& shell) : _shell(shell) {
			x64code(_shell, { 0x48, 0x83, 0xEC, 0x78 });
		}
		~stack_frame_t() {
			x64code(_shell, { 0x48, 0x83, 0xC4, 0x78 });
		}
	};
	static void x64code(char*& shellBase, unsigned char code)
	{
#ifdef _WIN64
		*reinterpret_cast<unsigned char*>(shellBase++) = code;
#endif // _WIN64
	}
	static void x64code(char*& shellBase, const std::vector<unsigned char>& data) {
		for (unsigned char byte : data)
			x64code(shellBase, byte);
	}
	static void writeShell(char* base, const Extention& ext, const std::string& monitorName)
	{
		auto nt = ntHeader(base);
		auto shellBase = base + ext.extentionBase;
		auto procAddr = move(functionAddress());
		auto procAddress = shellBase;
		memcpy(procAddress, procAddr.data(), procAddr.size());
		shellBase += procAddr.size();

		char* kernel32String = nullptr;
		auto getModuleHandle = idataItem(base, "GetModuleHandleA");
		if(0 == getModuleHandle)
		{
			getModuleHandle = idataItem(base, "GetModuleHandleW");
			kernel32String = writeString(shellBase, L"kernel32.dll");
		}
		else
			kernel32String = writeString(shellBase, "kernel32.dll");
		auto loadLibraryString = writeString(shellBase, "LoadLibraryA");

		char* monitorString = nullptr;
		auto loadLibrary = idataItem(base, "LoadLibraryA");
		if(0 == loadLibrary && 0 == getModuleHandle)
		{
			loadLibrary = idataItem(base, "LoadLibraryW");
			monitorString = writeString(shellBase, std::wstring(monitorName.begin(), monitorName.end()));
		}
		else
			monitorString = writeString(shellBase, monitorName);

		auto virtualProtectString = writeString(shellBase, "VirtualProtect");
		auto imageOffset = ext.sectionVirtualOffset + nt->OptionalHeader.ImageBase - size_t(base) - ext.extentionBase;

		auto makePush = [&shellBase](size_t address)
		{
			x64prefix(shellBase);
			*shellBase++ = 0xBB;
			*reinterpret_cast<size_t*>(shellBase) = address;
			shellBase += sizeof(size_t);
			*shellBase++ = 0x53;

		};
		auto makePushRelative = [&shellBase](uint32_t address)
		{
			x64prefix(shellBase);
			*reinterpret_cast<uint16_t*>(shellBase) = 0x9F8D;
			*reinterpret_cast<uint32_t*>(shellBase + 2) = address;
			shellBase += 6;
			*shellBase++ = 0x53;
		};
		auto makeCall = [&shellBase](uint32_t address)
		{
			x64csprefix(shellBase);
			*reinterpret_cast<uint16_t*>(shellBase) = 0x15FF;
			shellBase += 2;
			*reinterpret_cast<uint32_t*>(shellBase) = address;
			shellBase += 4;
		};
		auto makeCallRelative = [&shellBase](uint32_t address)
		{
			stack_frame_t x(shellBase);
			x64prefix(shellBase);
			*reinterpret_cast<uint16_t*>(shellBase) = 0x9F8D;
			*reinterpret_cast<uint32_t*>(shellBase + 2) = address;
			shellBase += 6;
			x64csprefix(shellBase);
			*reinterpret_cast<uint16_t*>(shellBase) = 0x13FF;
			shellBase += 2;
		};
		auto makeCallDirect = [&shellBase](size_t from, size_t address)
		{
			stack_frame_t x(shellBase);
			*reinterpret_cast<unsigned char*>(shellBase++) = 0xE8;
#ifdef _WIN64
			from += 4;
#endif // _WIN64

			*reinterpret_cast<uint32_t*>(shellBase) = address - from - 5;
			shellBase += 4;
		};
		auto makeCallEax = [&shellBase]()
		{
			stack_frame_t x(shellBase);
			*reinterpret_cast<uint16_t*>(shellBase) = 0xD0FF;
			shellBase += 2;
		};
		auto makeMoveDwordEax = [&shellBase](uint32_t address)
		{
			*reinterpret_cast<unsigned char*>(shellBase++) = 0xA3;
			*reinterpret_cast<uint32_t*>(shellBase) = address;
			shellBase += 4;
		};
		auto makeMoveDwordEaxRelative = [&shellBase](uint32_t address)
		{
			*reinterpret_cast<uint16_t*>(shellBase) = 0x8789;
			*reinterpret_cast<uint32_t*>(shellBase + 2) = address;
			shellBase += 6;
		};
		auto makeOffset = [&shellBase,imageOffset]
		{
			*reinterpret_cast<unsigned char*>(shellBase++) = 0xE8;	//call $next
			*reinterpret_cast<uint32_t*>(shellBase) = 0;
			shellBase += 4;
			*reinterpret_cast<unsigned char*>(shellBase++) = 0x5F;	//pop edi/rdi
			x64prefix(shellBase);
			*reinterpret_cast<uint16_t*>(shellBase) = 0xEF81;
#ifdef _WIN64
			*reinterpret_cast<uint32_t*>(shellBase + 2) = (size_t)shellBase + imageOffset - 2;
#else
			*reinterpret_cast<uint32_t*>(shellBase + 2) = (size_t)shellBase + imageOffset - 1;
#endif
			shellBase += 6;
		};
		nt->OptionalHeader.AddressOfEntryPoint = (uint32_t)shellBase + imageOffset - nt->OptionalHeader.ImageBase;
		makeOffset();
		if(0 != getModuleHandle)
		{
			makePushRelative((size_t)kernel32String + imageOffset);
			x64code(shellBase, 0x59);//pop rcx
			makeCallRelative((size_t)getModuleHandle);
			makePushRelative((size_t)virtualProtectString + imageOffset);
			*shellBase++ = 0x50;	//push eax=GetModuleHandleA
			makePushRelative((size_t)loadLibraryString + imageOffset);
			*shellBase++ = 0x50;	//push eax
			x64code(shellBase, 0x59);//pop rcx
			x64code(shellBase, 0x5A);//pop rdx
			makeCallDirect((size_t)shellBase + imageOffset, (size_t)procAddress + imageOffset);
			makePushRelative((size_t)monitorString + imageOffset);
			x64code(shellBase, 0x59);//pop rcx
			makeCallEax();//LoadLibraryA("monitor.dll")
		}
		else if(0 != loadLibrary)
		{
			makePushRelative((size_t)monitorString + imageOffset);
			x64code(shellBase, 0x59);//pop rcx
			makeCallRelative((size_t)loadLibrary);
		}
		else
		{
			puts("No useful api.");
			getchar();
			ExitProcess(0);
		}
		x64code(shellBase, 0x59);//pop rcx
		x64code(shellBase, 0x5A);//pop rdx
		makeCallDirect((size_t)shellBase + imageOffset, (size_t)procAddress + imageOffset);
		//makePush((uint32_t)oldProtect + imageOffset);
		*shellBase++ = 0x53;
		x64prefix(shellBase);
		unsigned char espToEsp[] = {0x89, 0x24, 0x24};
		memcpy(shellBase, espToEsp, sizeof(espToEsp));
		shellBase += sizeof(espToEsp);
		makePush(PAGE_READWRITE);
		makePush(nt->OptionalHeader.SizeOfHeaders);
		makePushRelative(nt->OptionalHeader.ImageBase);
		x64code(shellBase, 0x59);//pop rcx
		x64code(shellBase, 0x5A);//pop rdx
		x64code(shellBase, { 0x41, 0x58 }); //pop r8
		x64code(shellBase, { 0x41, 0x59 }); //pop r9
		makeCallEax();
		for(auto& rec : ext.recovery)
		{
			*reinterpret_cast<unsigned char*>(shellBase++) = 0xB8;	//mov ecx, dddd
			*reinterpret_cast<uint32_t*>(shellBase) = rec.second;
			shellBase += 4;
			makeMoveDwordEaxRelative(rec.first + nt->OptionalHeader.ImageBase);
		}
		makePush(ext.OEP + nt->OptionalHeader.ImageBase);
		*reinterpret_cast<unsigned char*>(shellBase++) = 0xC3;	//retn
	}
	static char* writeString(char*& shellBase, const std::string& text)
	{
		memcpy(shellBase, text.data(), text.size() + 1);
		auto base = shellBase;
		shellBase += text.size() + 1;
		return base;
	}
	static char* writeString(char*& shellBase, const std::wstring& text)
	{
		memcpy(shellBase, text.data(), (text.size() + 1) * sizeof(wchar_t));
		auto base = shellBase;
		shellBase += (text.size() + 1) * sizeof(wchar_t);
		return base;
	}
	__declspec(dllexport) static void* function_address(HINSTANCE dll, const char* name)
	{
		IMAGE_DOS_HEADER*			dos_header;
		IMAGE_NT_HEADERS*			nt_header;
		IMAGE_SECTION_HEADER*		section_header;
		IMAGE_EXPORT_DIRECTORY*		exports;
		IMAGE_DATA_DIRECTORY*		directory;
		DWORD*						name_ref;
		WORD*						ordinal;
		long						k;
		BYTE*						base;

		base = const_cast<LPBYTE>(reinterpret_cast<const BYTE*>(dll));
		dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
		section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_header + 1);

		directory = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (0 == directory->Size) return nullptr;

		exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + directory->VirtualAddress);
		if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
			return nullptr;

		name_ref = reinterpret_cast<DWORD*>(&base[exports->AddressOfNames]);
		ordinal = reinterpret_cast<WORD*>(&base[exports->AddressOfNameOrdinals]);
		for (k = 0; k < (long)exports->NumberOfNames; ++k, ++name_ref, ++ordinal)
		{
			auto s0 = reinterpret_cast<const char*>(&base[*name_ref]);
			auto s1 = name;
			while (*s0 && *s1 && *s0 == *s1) {
				++s0;
				++s1;
			}
			if(*s0 == 0 && *s1 == 0)
				return base + *reinterpret_cast<DWORD*>(&base[exports->AddressOfFunctions + *ordinal * 4]);
		}
		return nullptr;
	}
	static std::vector<char> functionAddress()
	{
#ifdef _WIN64
		unsigned char shellCode[] = {
			0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89,
			0x7c, 0x24, 0x20, 0x48, 0x63, 0x41, 0x3c, 0x48, 0x8b, 0xea, 0x48, 0x8b, 0xd9, 0x83, 0xbc, 0x08, 0x8c,
			0x00, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x7c, 0x00, 0x00, 0x00, 0x8b, 0xbc, 0x08, 0x88, 0x00, 0x00, 0x00,
			0x48, 0x03, 0xf9, 0x8b, 0x77, 0x18, 0x85, 0xf6, 0x74, 0x6b, 0x83, 0x7f, 0x14, 0x00, 0x74, 0x65, 0x44,
			0x8b, 0x57, 0x20, 0x45, 0x33, 0xc9, 0x44, 0x8b, 0x5f, 0x24, 0x4c, 0x03, 0xd1, 0x4c, 0x03, 0xd9, 0x85,
			0xf6, 0x7e, 0x50, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8b, 0x02, 0x48, 0x8b, 0xcd,
			0x48, 0x03, 0xc3, 0x0f, 0xb6, 0x10, 0x84, 0xd2, 0x74, 0x23, 0x44, 0x0f, 0xb6, 0x01, 0x45, 0x84, 0xc0,
			0x74, 0x15, 0x41, 0x3a, 0xd0, 0x75, 0x10, 0x0f, 0xb6, 0x50, 0x01, 0x48, 0xff, 0xc0, 0x48, 0xff, 0xc1,
			0x84, 0xd2, 0x75, 0xe4, 0xeb, 0x05, 0x80, 0x38, 0x00, 0x75, 0x05, 0x80, 0x39, 0x00, 0x74, 0x27, 0x41,
			0xff, 0xc1, 0x49, 0x83, 0xc2, 0x04, 0x49, 0x83, 0xc3, 0x02, 0x44, 0x3b, 0xce, 0x7c, 0xb8, 0x33, 0xc0,
			0x48, 0x8b, 0x5c, 0x24, 0x08, 0x48, 0x8b, 0x6c, 0x24, 0x10, 0x48, 0x8b, 0x74, 0x24, 0x18, 0x48, 0x8b,
			0x7c, 0x24, 0x20, 0xc3, 0x41, 0x0f, 0xb7, 0x0b, 0x8b, 0x47, 0x1c, 0x8d, 0x0c, 0x88, 0x8b, 0x04, 0x19,
			0x48, 0x03, 0xc3, 0xeb, 0xd9, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			0xcc, 0xcc, 0xcc, 0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48, 0x8b, 0x49, 0x18, 0x48,
			0x85, 0xc9, 0x74, 0x3f, 0x48, 0x8b, 0x53, 0x28, 0x48, 0x2b, 0xd1, 0x48, 0x83, 0xe2, 0xf8, 0x48, 0x81,
			0xfa, 0x00, 0x10, 0x00, 0x00, 0x72, 0x18, 0x4c, 0x8b, 0x41, 0xf8, 0x48, 0x83, 0xc2, 0x27, 0x49, 0x2b,
			0xc8, 0x48, 0x8d, 0x41, 0xf8, 0x48, 0x83, 0xf8, 0x1f, 0x77, 0x1c, 0x49, 0x8b, 0xc8, 0xe8, 0x2d, 0xb1,
			0x00, 0x00, 0x33, 0xc0, 0x48, 0x89, 0x43, 0x18, 0x48, 0x89, 0x43, 0x20, 0x48, 0x89, 0x43, 0x28, 0x48,
			0x83, 0xc4, 0x20, 0x5b, 0xc3 
		};
#else
		unsigned char shellCode[] = {
				0x55, 0x8b, 0xec, 0x83, 0xec, 0x08, 0x53, 0x8b, 0x5d, 0x08, 0x8b, 0x43, 0x3c, 0x83, 0x7c, 0x18,
				0x7c, 0x00, 0x75, 0x09, 0x33, 0xc0, 0x5b, 0x8b, 0xe5, 0x5d, 0xc2, 0x08, 0x00, 0x8b, 0x44, 0x18,
				0x78, 0x03, 0xc3, 0x89, 0x45, 0xf8, 0x8b, 0x48, 0x18, 0x89, 0x4d, 0xfc, 0x85, 0xc9, 0x74, 0xe4,
				0x83, 0x78, 0x14, 0x00, 0x74, 0xde, 0x56, 0x8b, 0x70, 0x20, 0x8b, 0x40, 0x24, 0x57, 0x03, 0xc3,
				0x03, 0xf3, 0x33, 0xff, 0x89, 0x45, 0x08, 0x85, 0xc9, 0x7e, 0x2b, 0x8b, 0x55, 0x0c, 0x8b, 0x0e,
				0x2b, 0xca, 0x8b, 0xc2, 0x8d, 0x14, 0x19, 0x8a, 0x0c, 0x02, 0x84, 0xc9, 0x75, 0x04, 0x38, 0x08,
				0x74, 0x1f, 0x3a, 0x08, 0x75, 0x03, 0x40, 0xeb, 0xee, 0x83, 0x45, 0x08, 0x02, 0x47, 0x83, 0xc6,
				0x04, 0x3b, 0x7d, 0xfc, 0x7c, 0xd5, 0x5f, 0x5e, 0x33, 0xc0, 0x5b, 0x8b, 0xe5, 0x5d, 0xc2, 0x08,
				0x00, 0x8b, 0x45, 0x08, 0x5f, 0x0f, 0xb7, 0x08, 0x8b, 0x45, 0xf8, 0x5e, 0x8b, 0x40, 0x1c, 0x8d,
				0x04, 0x88, 0x8b, 0x04, 0x18, 0x03, 0xc3, 0x5b, 0x8b, 0xe5, 0x5d, 0xc2, 0x08, 0x00
			};
#endif
		return std::vector<char>(shellCode, &shellCode[sizeof(shellCode)]);
	}
};