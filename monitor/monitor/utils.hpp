#pragma once
#include "DynamoRIO/include/dr_api.h"

template<typename T>
inline void patch_bytes(T address, const std::vector<unsigned char>& bytes) {
	auto base = reinterpret_cast<unsigned char*>(address);
	std::copy(bytes.begin(), bytes.end(), base);
}

template<typename T>
inline void patch_nops(T address, size_t nops) {
	std::vector<unsigned char> bytes(nops, 0x90);
	patch_bytes(address, bytes);
}

inline size_t detect_boundary_size(size_t address, size_t size) {
	size_t offset = 0;
	auto base = (unsigned char*)address;
	while (true) {
		offset += decode_sizeof(nullptr, &base[offset], nullptr _IF_X64(nullptr));
		if (offset >= size)
			return offset;
	}
}

template<typename type_t>
inline size_t make_instruction(size_t address, unsigned char opcode, type_t immediate) {
	auto boundary_size = detect_boundary_size(address, 1 + sizeof(type_t));
	for (size_t k = 1 + sizeof(type_t); k < boundary_size; ++k)
		reinterpret_cast<unsigned char*>(address)[k] = 0x90;
	*reinterpret_cast<unsigned char*>(address++) = opcode;
	*reinterpret_cast<type_t*>(address) = immediate;
	address += sizeof(type_t);
	return address;
}

template<typename type_t>
inline size_t make_general_jump(size_t address, unsigned char opcode, type_t target) {
	return make_instruction<type_t>(address, opcode, (type_t)(target - address - sizeof(type_t) - 1));
}

template<typename type_t>
inline size_t make_call(size_t address, type_t target)
{
	return make_general_jump<long>(address, 0xE8, (size_t)target);
}

template<typename type_t>
inline size_t make_jump(size_t address, type_t target) {
	return make_general_jump<long>(address, 0xE9, (size_t)target);
}

template<typename type_t>
inline size_t make_short_jump(size_t address, type_t target) {
	return make_instruction<short>(address, 0xEB, (size_t)target);
}
