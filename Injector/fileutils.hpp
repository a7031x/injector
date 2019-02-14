#pragma once
#include <vector>
#include <filesystem>
#include <fstream>

namespace fileutils {
	std::vector<char> readfile(const std::filesystem::path& path) {
		std::ifstream input(path, std::ios::binary);
		std::vector<char> bytes(std::istreambuf_iterator<char>(input), {});
		input.close();
		return bytes;
	}

	void writefile(const std::filesystem::path& path, const std::vector<char>& bytes) {
		std::ofstream output(path, std::fstream::trunc | std::fstream::binary);
		output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
		output.close();
	}
}
