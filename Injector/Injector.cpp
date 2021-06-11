// Injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include "Injector.hpp"
#include <vector>
#include <string>
#include <Shlwapi.h>
#include <filesystem>
#pragma comment(lib, "shlwapi.lib")
using namespace std;

void copy_folder(const std::filesystem::path& source, const std::filesystem::path& target)
{
	std::filesystem::create_directories(target);
	for(std::filesystem::recursive_directory_iterator itr(source); decltype(itr)() != itr; ++itr)
	{
		std::filesystem::path p = target / std::filesystem::path(itr->path().string().substr(source.string().length() + 1));
		if(false == is_directory(itr->path()))
			copy_file(itr->path(), p, std::filesystem::copy_options::overwrite_existing);
		else
			std::filesystem::create_directories(p);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	string filepath;
	getline(cin, filepath);
	filepath.erase(std::remove(filepath.begin(), filepath.end(), '\"'), filepath.end());
	Injector::inject(filepath, "monitor.dll");
	auto targetfolder = std::filesystem::path(filepath).parent_path();
	std::filesystem::copy_file("dynamorio.dll", targetfolder / "dynamorio.dll");
	//wchar_t monitorFolder[MAX_PATH];
	//GetModuleFileNameW(nullptr, monitorFolder, _countof(monitorFolder));
	//PathRemoveFileSpecW(monitorFolder);
	//PathCombineW(monitorFolder, monitorFolder, L"monitor");
	//copy_folder(monitorFolder, std::filesystem::path(filepath).parent_path() / std::filesystem::path("monitor"));
	return 0;
}
